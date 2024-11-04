/*
Copyright (c) 2017, Plume Design Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
   1. Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
   3. Neither the name of the Plume Design Inc. nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL Plume Design Inc. BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/**
 * DFS STA iftype workaround
 *
 * The driver, when operating as an extender may
 * experience a radar event while it's root AP may
 * not.
 *
 * In such a case the driver will perform a forced
 * CSA without taking care of the STA iftype.
 *
 * Supposedly there's a reverse-CSA supported by
 * the driver, but that is vendor specific and
 * can't be relied on.
 *
 * To prevent the STA link landing on a part
 * overlapping old channel (eg. 44/160 -> 36/80)
 * due to DFS random runaway channel this module
 * will attempt to break the STA link upon radar
 * to either force a proper reassociation (using
 * proper channel) or going through Opensync's
 * fallback parent logic (typically 10s after STA
 * link loss that involved DFS).
 *
 * Without this workaround the STA link may end up
 * in a semi-broken state where it is able to
 * continue with tx/rx as long as the rate control
 * uses 80MHz modulatiom, and so does the AP. Once
 * that stops holding true, the link degrades and
 * disconnects sometime later.
 *
 * This assumes there is, and won't be, dfs-driven
 * static puncturing that Wi-Fi 7 (11be)
 * allows, because if there is, then puncturing
 * would be able to maintain the primary channel
 * and therefore continue operation without
 * issues.
 */

struct osw_plat_bcm_dfs_sta_war
{
    struct osw_state_observer obs;
    struct osw_conf_mutator mut;
    ds_tree_t vifs;
};

struct osw_plat_bcm_dfs_sta_war_vif
{
    ds_tree_node_t node;
    struct osw_plat_bcm_dfs_sta_war *m;
    char *vif_name;
    bool connected;
    bool mutated;
    struct osw_channel channel;
    struct osw_channel channel_prev;
    struct osw_timer backoff;
    struct osw_timer channel_prev_expiry;
};

#define OSW_PLAT_BCM_DFS_STA_WAR_BACKOFF_SEC 20
#define OSW_PLAT_BCM_DFS_STA_WAR_CHANNEL_SEC 3

#define LOG_PREFIX_DFS_STA_WAR(vif, fmt, ...) LOG_PREFIX("dfs_sta_war: %s: " fmt, (vif)->vif_name, ##__VA_ARGS__)

static void osw_plat_bcm_dfs_sta_war_vif_gc(struct osw_plat_bcm_dfs_sta_war_vif *vif)
{
    if (vif == NULL) return;
    if (vif->connected) return;
    if (osw_timer_is_armed(&vif->backoff)) return;

    LOGI(LOG_PREFIX_DFS_STA_WAR(vif, "dropping"));
    osw_timer_disarm(&vif->channel_prev_expiry);
    ds_tree_remove(&vif->m->vifs, vif);
    FREE(vif->vif_name);
    FREE(vif);
}

static void osw_plat_bcm_dfs_sta_war_vif_backoff_cb(struct osw_timer *t)
{
    struct osw_plat_bcm_dfs_sta_war_vif *vif = container_of(t, typeof(*vif), backoff);
    LOGI(LOG_PREFIX_DFS_STA_WAR(vif, "stopping forced disconnect"));
    if (vif->mutated == false)
    {
        LOGN(LOG_PREFIX_DFS_STA_WAR(vif, "never mutated.. confsync was blocked?"));
    }
    vif->mutated = false;
    osw_plat_bcm_dfs_sta_war_vif_gc(vif);
}

static void osw_plat_bcm_dfs_sta_war_vif_channel_cb(struct osw_timer *t)
{
    struct osw_plat_bcm_dfs_sta_war_vif *vif = container_of(t, typeof(*vif), channel_prev_expiry);
    LOGI(LOG_PREFIX_DFS_STA_WAR(
            vif,
            "prev channel " OSW_CHANNEL_FMT " forgotten",
            OSW_CHANNEL_ARG(&vif->channel_prev)));
    MEMZERO(vif->channel_prev);
    osw_plat_bcm_dfs_sta_war_vif_gc(vif);
}

static struct osw_plat_bcm_dfs_sta_war_vif *osw_plat_bcm_dfs_sta_war_vif_alloc(
        struct osw_plat_bcm_dfs_sta_war *m,
        const char *vif_name)
{
    struct osw_plat_bcm_dfs_sta_war_vif *vif = CALLOC(1, sizeof(*vif));
    osw_timer_init(&vif->backoff, osw_plat_bcm_dfs_sta_war_vif_backoff_cb);
    osw_timer_init(&vif->channel_prev_expiry, osw_plat_bcm_dfs_sta_war_vif_channel_cb);
    vif->vif_name = STRDUP(vif_name);
    vif->m = m;
    ds_tree_insert(&m->vifs, vif, vif->vif_name);
    LOGI(LOG_PREFIX_DFS_STA_WAR(vif, "allocated"));
    return vif;
}

static struct osw_plat_bcm_dfs_sta_war_vif *osw_plat_bcm_dfs_sta_war_vif_get(
        struct osw_plat_bcm_dfs_sta_war *m,
        const char *vif_name)
{
    return ds_tree_find(&m->vifs, vif_name) ?: osw_plat_bcm_dfs_sta_war_vif_alloc(m, vif_name);
}

static void osw_plat_bcm_dfs_sta_war_vif_start(struct osw_plat_bcm_dfs_sta_war_vif *vif, const char *reason)
{
    if (osw_timer_is_armed(&vif->backoff)) return;
    const uint64_t at = osw_time_mono_clk() + OSW_TIME_SEC(OSW_PLAT_BCM_DFS_STA_WAR_BACKOFF_SEC);

    LOGI(LOG_PREFIX_DFS_STA_WAR(vif, "starting forced disconnect because: %s", reason));
    osw_timer_arm_at_nsec(&vif->backoff, at);
    osw_conf_invalidate(&vif->m->mut);
}

static void osw_plat_bcm_dfs_sta_war_mutate_cb(struct osw_conf_mutator *mut, struct ds_tree *phy_tree)
{
    struct osw_plat_bcm_dfs_sta_war *m = container_of(mut, typeof(*m), mut);
    struct osw_conf_phy *phy;
    ds_tree_foreach (phy_tree, phy)
    {
        struct osw_conf_vif *vif;
        ds_tree_foreach (&phy->vif_tree, vif)
        {
            struct osw_plat_bcm_dfs_sta_war_vif *v = ds_tree_find(&m->vifs, vif->vif_name);
            if (v != NULL && osw_timer_is_armed(&v->backoff))
            {
                vif->enabled = false;
                if (v->mutated == false)
                {
                    LOGI(LOG_PREFIX_DFS_STA_WAR(v, "mutated at least once"));
                    v->mutated = true;
                }
            }
        }
    }
}

static void osw_plat_bcm_dfs_sta_war_vif_radar_detected_cb(
        struct osw_state_observer *self,
        const struct osw_state_vif_info *info,
        const struct osw_channel *channel)
{
    if (info->drv_state->vif_type != OSW_VIF_STA) return;
    const char *vif_name = info->vif_name;
    struct osw_plat_bcm_dfs_sta_war *m = container_of(self, typeof(*m), obs);
    struct osw_plat_bcm_dfs_sta_war_vif *vif = osw_plat_bcm_dfs_sta_war_vif_get(m, vif_name);
    LOGI(LOG_PREFIX_DFS_STA_WAR(vif, "radar while %sconnected", vif->connected ? "" : "dis"));
    if (vif->connected == false) return;
    const struct osw_channel_state *cs = info->phy->drv_state->channel_states;
    const size_t n_cs = info->phy->drv_state->n_channel_states;
    /* This may seem overly aggressive and one
     * might think checking NOL is sufficient.
     * However if we know we were connected and
     * suddenly one of the segments is no longer
     * cac-completed (nor non-dfs), then we're
     * operating at an incorrect channel. This is
     * defensive against driver mis-reporting DFS
     * states.
     */
    if (WARN_ON(osw_channel_is_none(&vif->channel))) return;
    const char *reason = strfmta(
            "%s%s%s",
            osw_cs_chan_intersects_state(cs, n_cs, &vif->channel, OSW_CHANNEL_DFS_CAC_POSSIBLE) ? "cac-possible " : "",
            osw_cs_chan_intersects_state(cs, n_cs, &vif->channel, OSW_CHANNEL_DFS_CAC_IN_PROGRESS) ? "cac-in-progress "
                                                                                                   : "",
            osw_cs_chan_intersects_state(cs, n_cs, &vif->channel, OSW_CHANNEL_DFS_NOL) ? "nol " : "");
    if (strlen(reason) == 0)
    {
        /* In case the channel managed to flip
         * _before_ radar event is reported make
         * sure to check if the last/prev channel
         * (which ages out) wasn't offending. If
         * there was a true re-assoc then it
         * will've cleared the channel_prev.
         */
        LOGI(LOG_PREFIX_DFS_STA_WAR(
                vif,
                "current channel " OSW_CHANNEL_FMT " is fine",
                OSW_CHANNEL_ARG(&vif->channel)));
        if (osw_channel_is_none(&vif->channel_prev)) return;
        reason =
                strfmta("%s%s%s",
                        osw_cs_chan_intersects_state(cs, n_cs, &vif->channel_prev, OSW_CHANNEL_DFS_CAC_POSSIBLE)
                                ? "cac-possible "
                                : "",
                        osw_cs_chan_intersects_state(cs, n_cs, &vif->channel_prev, OSW_CHANNEL_DFS_CAC_IN_PROGRESS)
                                ? "cac-in-progress "
                                : "",
                        osw_cs_chan_intersects_state(cs, n_cs, &vif->channel_prev, OSW_CHANNEL_DFS_NOL) ? "nol " : "");
        if (strlen(reason) == 0)
        {
            LOGI(LOG_PREFIX_DFS_STA_WAR(
                    vif,
                    "prev channel " OSW_CHANNEL_FMT " is fine too",
                    OSW_CHANNEL_ARG(&vif->channel)));
            return;
        }
    }

    osw_plat_bcm_dfs_sta_war_vif_start(vif, reason);
}

static void osw_plat_bcm_dfs_sta_war_sta_connected_cb(
        struct osw_state_observer *self,
        const struct osw_state_sta_info *info)
{
    if (info->vif->drv_state->vif_type != OSW_VIF_STA) return;
    const char *vif_name = info->vif->vif_name;
    struct osw_plat_bcm_dfs_sta_war *m = container_of(self, typeof(*m), obs);
    struct osw_plat_bcm_dfs_sta_war_vif *vif = osw_plat_bcm_dfs_sta_war_vif_get(m, vif_name);
    vif->connected = info->drv_state->connected;
    vif->channel = info->vif->drv_state->u.sta.link.channel;
    LOGI(LOG_PREFIX_DFS_STA_WAR(vif, "connected on " OSW_CHANNEL_FMT, OSW_CHANNEL_ARG(&vif->channel)));
    MEMZERO(vif->channel_prev);
    osw_plat_bcm_dfs_sta_war_vif_gc(vif);
}

static void osw_plat_bcm_dfs_sta_war_sta_disconnected_cb(
        struct osw_state_observer *self,
        const struct osw_state_sta_info *info)
{
    if (info->vif->drv_state->vif_type != OSW_VIF_STA) return;
    const char *vif_name = info->vif->vif_name;
    struct osw_plat_bcm_dfs_sta_war *m = container_of(self, typeof(*m), obs);
    struct osw_plat_bcm_dfs_sta_war_vif *vif = osw_plat_bcm_dfs_sta_war_vif_get(m, vif_name);
    LOGI(LOG_PREFIX_DFS_STA_WAR(vif, "disconnected from " OSW_CHANNEL_FMT, OSW_CHANNEL_ARG(&vif->channel)));
    vif->connected = info->drv_state->connected;
    MEMZERO(vif->channel);
    MEMZERO(vif->channel_prev);
    osw_plat_bcm_dfs_sta_war_vif_gc(vif);
}

static void osw_plat_bcm_dfs_sta_war_vif_changed_cb(
        struct osw_state_observer *self,
        const struct osw_state_vif_info *info)
{
    if (info->drv_state->vif_type != OSW_VIF_STA) return;
    const char *vif_name = info->vif_name;
    struct osw_plat_bcm_dfs_sta_war *m = container_of(self, typeof(*m), obs);
    struct osw_plat_bcm_dfs_sta_war_vif *vif = osw_plat_bcm_dfs_sta_war_vif_get(m, vif_name);
    const struct osw_channel *c = &info->drv_state->u.sta.link.channel;
    if (vif == NULL) return;
    if (vif->connected == false) return;
    if (osw_channel_is_equal(c, &vif->channel) == false)
    {
        LOGI(LOG_PREFIX_DFS_STA_WAR(
                vif,
                "switched from " OSW_CHANNEL_FMT " to " OSW_CHANNEL_FMT,
                OSW_CHANNEL_ARG(&vif->channel),
                OSW_CHANNEL_ARG(c)));
        vif->channel_prev = vif->channel;
        vif->channel = *c;
        const uint64_t at = osw_time_mono_clk() + OSW_TIME_SEC(OSW_PLAT_BCM_DFS_STA_WAR_CHANNEL_SEC);
        osw_timer_arm_at_nsec(&vif->channel_prev_expiry, at);
    }
    osw_plat_bcm_dfs_sta_war_vif_gc(vif);
}

static void osw_plat_bcm_dfs_sta_war_init(struct osw_plat_bcm_dfs_sta_war *m)
{
    ds_tree_init(&m->vifs, ds_str_cmp, struct osw_plat_bcm_dfs_sta_war_vif, node);
    m->obs.vif_changed_fn = osw_plat_bcm_dfs_sta_war_vif_changed_cb;
    m->obs.vif_radar_detected_fn = osw_plat_bcm_dfs_sta_war_vif_radar_detected_cb;
    m->obs.sta_connected_fn = osw_plat_bcm_dfs_sta_war_sta_connected_cb;
    m->obs.sta_disconnected_fn = osw_plat_bcm_dfs_sta_war_sta_disconnected_cb;
    m->mut.mutate_fn = osw_plat_bcm_dfs_sta_war_mutate_cb;
    m->mut.name = __FILE__;
}

static void osw_plat_bcm_dfs_sta_war_attach(struct osw_plat_bcm_dfs_sta_war *m)
{
    OSW_MODULE_LOAD(osw_conf);
    OSW_MODULE_LOAD(osw_state);

    osw_conf_register_mutator(&m->mut);
    osw_state_register_observer(&m->obs);
}

static struct osw_plat_bcm_dfs_sta_war *osw_plat_bcm_dfs_sta_war_new(void)
{
    struct osw_plat_bcm_dfs_sta_war *m = CALLOC(1, sizeof(*m));
    osw_plat_bcm_dfs_sta_war_init(m);
    osw_plat_bcm_dfs_sta_war_attach(m);
    return m;
}
