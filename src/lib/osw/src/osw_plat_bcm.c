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

/* libc */
#include <string.h>
#include <limits.h>
#include <netinet/in.h>
//#include <net/if.h>
//#include <linux/if_arp.h> /* ARPHRD_IEEE80211 */
#include <glob.h>
#include <inttypes.h>
#include <libgen.h>
#include <errno.h>
#include <linux/if_packet.h>

/* 3rd party */
#include <ev.h>
#include <netlink/msg.h>
#include <netlink/genl/genl.h>
#include <linux/nl80211.h>

/* opensync */
#include <ds_tree.h>
#include <memutil.h>
#include <util.h>
#include <const.h>
#include <os_nif.h>
#include <log.h>
#include <rq.h>
#include <nl.h>
#include <nl_conn.h>
#include <nl_80211.h>
#include <nl_cmd_task.h>

/* osw */
#include <osw_drv.h>
#include <osw_state.h>
#include <osw_module.h>
#include <osw_drv_nl80211.h>
#include <osw_hostap.h>
#include <osw_drv_common.h>
#include <osw_timer.h>
#include <osw_conf.h>
#include <osw_util.h>
#include <osw_ut.h>

/* bcmwl */
#include <bcmwl.h>
#include <bcmwl_sta.h>
#include <bcmwl_cim.h>
#include <bcmwl_ioctl.h>
#include <bcmwl_event.h>

#define LOG_PREFIX(fmt, ...) \
    "osw: plat: bcm: " fmt, \
    ##__VA_ARGS__

#define LOG_PREFIX_PHY(phy_name, fmt, ...) \
    LOG_PREFIX("%s: " fmt, \
    phy_name, \
    ##__VA_ARGS__)

#define LOG_PREFIX_VIF(phy_name, vif_name, fmt, ...) \
    LOG_PREFIX_PHY(phy_name, "%s: " fmt, \
    vif_name, \
    ##__VA_ARGS__)

#define LOG_PREFIX_STA(phy_name, vif_name, sta_addr, fmt, ...) \
    LOG_PREFIX_VIF(phy_name, vif_name, OSW_HWADDR_FMT": " fmt, \
    OSW_HWADDR_ARG(sta_addr), \
    ##__VA_ARGS__)

#define OSW_PLAT_BCM_CHSPEC_CENTER(cs) (CHSPEC_CHANNEL(cs) >> WL_CHANSPEC_CHAN_SHIFT)
#define OSW_PLAT_BCM_CHSPEC_BW(cs) (CHSPEC_BW(cs) >> WL_CHANSPEC_BW_SHIFT)
#define OSW_PLAT_BCM_CHSPEC_FIRST(cs) (OSW_PLAT_BCM_CHSPEC_CENTER(cs) - (1 << (OSW_PLAT_BCM_CHSPEC_BW(cs) - 1)) + 2)
#define OSW_PLAT_BCM_CHSPEC_LAST(cs) (OSW_PLAT_BCM_CHSPEC_CENTER(cs) + (1 << (OSW_PLAT_BCM_CHSPEC_BW(cs) - 1)) - 2)

/* Does not support 80+80 by design. */
#define OSW_PLAT_BCM_CHSPEC_FOREACH_SBC(c, cs) \
        for (c = OSW_PLAT_BCM_CHSPEC_FIRST(cs); \
             c > 0 && c <= OSW_PLAT_BCM_CHSPEC_LAST(cs); \
             c += 4)

struct osw_plat_bcm {
    struct osw_state_observer state_obs;
    struct osw_drv_nl80211_ops *nl_ops;
    struct osw_drv_nl80211_hook *nl_hook;
    struct osw_hostap *hostap;
    struct osw_hostap_hook *hostap_hook;
    struct osw_drv *drv_nl80211;
    struct nl_conn *nl_conn;
    struct nl_conn_subscription *nl_conn_sub;
    struct nl_80211_sub *nl_sub;
    struct ev_loop *loop;
    ev_io event_io;
    ev_io nl_io;
};

struct osw_plat_bcm_phy {
    struct osw_plat_bcm *m;
    const struct nl_80211_phy *info;
    unsigned int stats_mask_pending;
    bool scan_failed;
};

struct osw_plat_bcm_vif {
    struct osw_plat_bcm *m;
    const struct nl_80211_vif *info;
    unsigned int stats_mask_pending;
};

struct osw_plat_bcm_sta {
    struct osw_plat_bcm *m;
    const struct nl_80211_sta *info;
};

typedef void
osw_plat_bcm_phy_each_fn_t(struct osw_plat_bcm *m,
                           struct osw_plat_bcm_phy *phy,
                           void *priv);

typedef void
osw_plat_bcm_vif_each_fn_t(struct osw_plat_bcm *m,
                           struct osw_plat_bcm_vif *vif,
                           void *priv);

typedef void
osw_plat_bcm_sta_each_fn_t(struct osw_plat_bcm_vif *vif,
                           struct osw_plat_bcm_sta *sta,
                           void *priv);

struct osw_plat_bcm_phy_each_arg {
    struct osw_plat_bcm *m;
    osw_plat_bcm_phy_each_fn_t *fn;
    void *priv;
};

struct osw_plat_bcm_vif_each_arg {
    struct osw_plat_bcm *m;
    osw_plat_bcm_vif_each_fn_t *fn;
    void *priv;
};

struct osw_plat_bcm_sta_each_arg {
    struct osw_plat_bcm_vif *vif;
    osw_plat_bcm_sta_each_fn_t *fn;
    void *priv;
};

static bool
osw_plat_bcm_is_enabled(void)
{
    if (getenv("OSW_PLAT_BCM_DISABLED")) return false;
    return true;
}

static bool
osw_plat_bcm_is_disabled(void)
{
    return osw_plat_bcm_is_enabled() == false;
}

static enum osw_band
osw_plat_bcm_cs_into_band(const int cs)
{
    switch (CHSPEC_BAND(cs)) {
        case WL_CHANSPEC_BAND_2G:
            return OSW_BAND_2GHZ;
        case WL_CHANSPEC_BAND_5G:
            return OSW_BAND_5GHZ;
#ifdef WL_CHANSPEC_BAND_6G
        case WL_CHANSPEC_BAND_6G:
            return OSW_BAND_6GHZ;
#endif
    }
    return OSW_BAND_UNDEFINED;
}

static int
osw_plat_bcm_map_from_osw_ap(const struct osw_multi_ap *multi_ap)
{
    const int bit_fh = 1 << 0; /* 1 */
    const int bit_bh = 1 << 1; /* 2 */
    return (multi_ap->fronthaul_bss ? bit_fh : 0x0)
         | (multi_ap->backhaul_bss ? bit_bh : 0x0);
}

static void
osw_plat_bcm_map_to_osw_ap(const int val,
                           struct osw_multi_ap *multi_ap)
{
    const int bit_fh = 1 << 0; /* 1 */
    const int bit_bh = 1 << 1; /* 2 */
    multi_ap->fronthaul_bss = !!(val & bit_fh);
    multi_ap->backhaul_bss = !!(val & bit_bh);
}

static int
osw_plat_bcm_map_from_osw_sta(const bool multi_ap)
{
    const int bit_bh = 1 << 2; /* 4 */
    return (multi_ap ? bit_bh : 0x0);
}

static bool
osw_plat_bcm_map_to_osw_sta(const int val)
{
    const int bit_bh = 1 << 2; /* 4 */
    return (val & bit_bh) == bit_bh;
}

static bool
osw_plat_bcm_map_changed(const char *vif_name,
                         const int val)
{
    const int state = atoi(WL(vif_name, "map") ?: "0");
    return state != val;
}

static bool
osw_plat_bcm_map_is_coherent(const struct osw_drv_vif_sta_network *net)
{
    bool seen_true = false;
    bool seen_false = false;
    while (net != NULL) {
        if (net->multi_ap) {
            seen_true = true;
        }
        else {
            seen_false = true;
        }
        net = net->next;
    }

    const bool not_coherent = (seen_true && seen_false);
    if (not_coherent) {
        return false;
    }

    return true;
}

static bool
osw_plat_bcm_map_changed_for_vif(struct osw_drv_vif_config *vif)
{
    const struct osw_drv_vif_config_sta *sta = &vif->u.sta;

    WARN_ON(osw_plat_bcm_map_is_coherent(sta->network) == false);
    const struct osw_drv_vif_sta_network *first = sta->network;
    if (sta->network_changed == false) return false;
    if (first == NULL) return false;

    const char *vif_name = vif->vif_name;
    const int val = osw_plat_bcm_map_from_osw_sta(first->multi_ap);
    return osw_plat_bcm_map_changed(vif_name, val);
}

static void
osw_plat_bcm_phy_each_cb(const struct nl_80211_phy *info,
                         void *priv)
{
    const char *phy_name = info->name;
    if (bcmwl_is_phy(phy_name)) {
        struct osw_plat_bcm_phy_each_arg *arg = priv;
        struct osw_plat_bcm *m = arg->m;
        struct nl_80211_sub *sub = m->nl_sub;
        if (sub == NULL) return;

        struct osw_plat_bcm_phy *phy = nl_80211_sub_phy_get_priv(sub, info);
        if (phy == NULL) return;

        arg->fn(arg->m, phy, arg->priv);
    }
}

static void
osw_plat_bcm_phy_each(struct osw_plat_bcm *m,
                      osw_plat_bcm_phy_each_fn_t *fn,
                      void *priv)
{
    struct osw_plat_bcm_phy_each_arg arg = {
        .m = m,
        .fn = fn,
        .priv = priv,
    };

    struct osw_drv_nl80211_ops *nl_ops = m->nl_ops;
    if (nl_ops == NULL) return;

    struct nl_80211 *nl = nl_ops->get_nl_80211_fn(nl_ops);
    if (nl == NULL) return;

    nl_80211_phy_each(nl, osw_plat_bcm_phy_each_cb, &arg);
}

static void
osw_plat_bcm_vif_each_cb(const struct nl_80211_vif *info,
                         void *priv)
{
    const char *vif_name = info->name;
    if (bcmwl_is_phy(vif_name) || bcmwl_is_vif(vif_name)) {
        struct osw_plat_bcm_vif_each_arg *arg = priv;
        struct osw_plat_bcm *m = arg->m;
        struct nl_80211_sub *sub = m->nl_sub;
        if (sub == NULL) return;

        struct osw_plat_bcm_vif *vif = nl_80211_sub_vif_get_priv(sub, info);
        if (vif == NULL) return;

        arg->fn(arg->m, vif, arg->priv);
    }
}

static void
osw_plat_bcm_vif_each(struct osw_plat_bcm *m,
                      osw_plat_bcm_vif_each_fn_t *fn,
                      void *priv)
{
    struct osw_plat_bcm_vif_each_arg arg = {
        .m = m,
        .fn = fn,
        .priv = priv,
    };

    struct osw_drv_nl80211_ops *nl_ops = m->nl_ops;
    if (nl_ops == NULL) return;

    struct nl_80211 *nl = nl_ops->get_nl_80211_fn(nl_ops);
    if (nl == NULL) return;

    nl_80211_vif_each(nl, NULL, osw_plat_bcm_vif_each_cb, &arg);
}

static const struct nl_80211_phy *
osw_plat_bcm_vif_into_phy_nl(struct osw_plat_bcm_vif *vif)
{
    if (vif == NULL) return NULL;
    if (vif->info == NULL) return NULL;

    struct osw_plat_bcm *m = vif->m;
    struct osw_drv_nl80211_ops *nl_ops = m->nl_ops;
    if (WARN_ON(nl_ops == NULL)) return NULL;

    struct nl_80211 *nl = nl_ops->get_nl_80211_fn(nl_ops);
    if (nl == NULL) return NULL;

    const uint32_t wiphy = vif->info->wiphy;
    const struct nl_80211_phy *phy = nl_80211_phy_by_wiphy(nl, wiphy);
    if (phy == NULL) return NULL;

    return phy;
}

static struct osw_plat_bcm_phy *
osw_plat_bcm_vif_into_phy(struct osw_plat_bcm_vif *vif)
{
    const struct nl_80211_phy *info = osw_plat_bcm_vif_into_phy_nl(vif);
    if (info == NULL) return NULL;

    struct osw_plat_bcm *m = vif->m;
    struct nl_80211_sub *sub = m->nl_sub;
    if (sub == NULL) return NULL;

    struct osw_plat_bcm_phy *phy = nl_80211_sub_phy_get_priv(sub, info);
    return phy;
}

static const char *
osw_plat_bcm_vif_into_phy_name(struct osw_plat_bcm_vif *vif)
{
    const struct nl_80211_phy *info = osw_plat_bcm_vif_into_phy_nl(vif);
    if (info == NULL) return NULL;

    return info->name;
}

static void
osw_plat_bcm_report_phy_changed(struct osw_plat_bcm *m,
                                const char *phy_name)
{
    struct osw_drv *drv = m->drv_nl80211;
    if (drv == NULL) return;

    osw_drv_report_phy_changed(drv, phy_name);
}

static void
osw_plat_bcm_report_vif_changed(struct osw_plat_bcm *m,
                                const char *vif_name)
{
    struct osw_drv *drv = m->drv_nl80211;
    if (drv == NULL) return;

    int ri;
    int vi;
    const bool parse_err = (bcmwl_parse_vap(vif_name, &ri, &vi) == false);
    if (parse_err) return;

    const char *phy_name = strfmta("wl%d", ri);
    osw_drv_report_vif_changed(drv, phy_name, vif_name);
}

static void
osw_plat_bcm_vif_report_sta_changed(struct osw_plat_bcm_vif *vif,
                                    const struct osw_hwaddr *sta_addr)
{
    struct osw_plat_bcm *m = vif->m;
    struct osw_drv *drv = m->drv_nl80211;
    if (drv == NULL) return;

    const char *phy_name = osw_plat_bcm_vif_into_phy_name(vif);
    if (phy_name == NULL) return;

    const char *vif_name = vif->info->name;
    osw_drv_report_sta_changed(drv, phy_name, vif_name, sta_addr);
}

static bool
osw_plat_bcm_conf_need_phy_disable(struct osw_drv_phy_config *phy)
{
    size_t i;
    for (i = 0; i < phy->vif_list.count; i++) {
        struct osw_drv_vif_config *vif = &phy->vif_list.list[i];
        switch (vif->vif_type) {
            case OSW_VIF_AP:
                if (vif->u.ap.mode_changed)
                    return true;
                if (vif->u.ap.multi_ap_changed)
                    return true;
                break;
            case OSW_VIF_AP_VLAN:
                break;
            case OSW_VIF_STA:
                if (osw_plat_bcm_map_changed_for_vif(vif))
                    return true;
                break;
            case OSW_VIF_UNDEFINED:
                break;
        }
    }

    return false;
}

static void
osw_plat_bcm_conf_disable_phys(struct osw_drv_conf *drv_conf)
{
    size_t i;
    for (i = 0; i < drv_conf->n_phy_list; i++) {
        struct osw_drv_phy_config *phy = &drv_conf->phy_list[i];
        const char *phy_name = phy->phy_name;

        if (osw_plat_bcm_conf_need_phy_disable(phy)) {
            LOGI(LOG_PREFIX_PHY(phy_name, "disabling for reconfig"));
            WARN_ON(WL(phy_name, "down") == NULL);
        }
    }
}

static void
osw_plat_bcm_conf_enable_phys(struct osw_drv_conf *drv_conf)
{
    size_t i;
    for (i = 0; i < drv_conf->n_phy_list; i++) {
        struct osw_drv_phy_config *phy = &drv_conf->phy_list[i];
        const char *phy_name = phy->phy_name;

        if (phy->enabled) {
            if (osw_plat_bcm_conf_need_phy_disable(phy)) {
                LOGI(LOG_PREFIX_PHY(phy_name, "enabling after reconfig"));
            }
            WARN_ON(WL(phy_name, "up") == NULL);
            WARN_ON(os_nif_up((const char *)phy_name, true) == false);
        }
    }
}

static void
osw_plat_bcm_conf_vif_ap_enabled(struct osw_drv_phy_config *phy,
                                 struct osw_drv_vif_config *vif)
{
    if (vif->enabled_changed == false) return;

    const char *vif_name = vif->vif_name;
    const char *arg = vif->enabled ? "up" : "down";

    WARN_ON(!WL(vif_name, "bss", arg));
}

static void
osw_plat_bcm_conf_vif_ap_ssid(struct osw_drv_phy_config *phy,
                              struct osw_drv_vif_config *vif)
{
    struct osw_drv_vif_config_ap *ap = &vif->u.ap;
    if (ap->ssid_changed == false) return;

    const char *vif_name = vif->vif_name;
    WARN_ON(!WL(vif_name, "ssid", ap->ssid.buf));
}

static void
osw_plat_bcm_conf_vif_ap_mcast2ucast(struct osw_drv_phy_config *phy,
                                     struct osw_drv_vif_config *vif)
{
    struct osw_drv_vif_config_ap *ap = &vif->u.ap;
    if (ap->mcast2ucast_changed == false) return;

    const char *phy_name = phy->phy_name;
    const char *vif_name = vif->vif_name;
    const bool is_dhd = bcmwl_radio_is_dhd(phy_name);
    const char *arg = ap->mcast2ucast ? "1" : "0";

    if (is_dhd) {
        WARN_ON(!DHD(vif_name, "wmf_bss_enable", arg));
    }
    else {
        WARN_ON(!WL(vif_name, "wmf_bss_enable", arg));
    }
}

static void
osw_plat_bcm_conf_vif_ap_acl(struct osw_drv_phy_config *phy,
                             struct osw_drv_vif_config *vif)
{
    struct osw_drv_vif_config_ap *ap = &vif->u.ap;
    if (ap->acl_changed == false) return;

    const char *vif_name = vif->vif_name;
    WARN_ON(WL(vif_name, "mac", "none") == NULL);

    size_t i;
    for (i = 0; i < ap->acl.count; i++) {
        const struct osw_hwaddr *mac = &ap->acl.list[i];
        struct osw_hwaddr_str buf;
        const char *str = osw_hwaddr2str(mac, &buf);
        WARN_ON(str == NULL);
        WARN_ON(WL(vif_name, "mac", str) == NULL);
    }
}

static void
osw_plat_bcm_conf_vif_ap_acl_policy(struct osw_drv_phy_config *phy,
                                    struct osw_drv_vif_config *vif)
{
    struct osw_drv_vif_config_ap *ap = &vif->u.ap;
    if (ap->acl_policy_changed == false) return;

    const char *vif_name = vif->vif_name;
    switch (ap->acl_policy) {
        case OSW_ACL_NONE:
            WARN_ON(WL(vif_name, "macmode", "0") == NULL);
            break;
        case OSW_ACL_ALLOW_LIST:
            WARN_ON(WL(vif_name, "macmode", "2") == NULL);
            break;
        case OSW_ACL_DENY_LIST:
            WARN_ON(WL(vif_name, "macmode", "1") == NULL);
            break;
    }
}

#define OSW_PLAT_BCM_BTM_BIT 0x1
#define OSW_PLAT_BCM_RRM_BIT 0x2

static void
osw_plat_bcm_conf_vif_ap_mode(struct osw_drv_phy_config *phy,
                              struct osw_drv_vif_config *vif)
{
    struct osw_drv_vif_config_ap *ap = &vif->u.ap;
    const struct osw_ap_mode *mode = &ap->mode;
    const char *vif_name = vif->vif_name;

    if (ap->mode_changed == false) return;

    WARN_ON(WL(vif_name, "nmode", strfmta("%d", mode->ht_enabled)) == NULL);
    WARN_ON(WL(vif_name, "vhtmode", strfmta("%d", mode->vht_enabled)) == NULL);
    WARN_ON(WL(vif_name, "he", "enab", strfmta("%d", mode->he_enabled)) == NULL);

    {
        uint32_t btm = strtol(WL(vif_name, "wnm") ?: "0", NULL, 16);
        btm &= ~OSW_PLAT_BCM_BTM_BIT;
        if (ap->mode.wnm_bss_trans) {
            btm |= OSW_PLAT_BCM_BTM_BIT;
        }
        WARN_ON(WL(vif_name, "wnm", strfmta("%x", btm)) == NULL);
    }

    {
        uint32_t rrm = strtol(WL(vif_name, "rrm") ?: "0", NULL, 16);
        rrm &= ~OSW_PLAT_BCM_RRM_BIT;
        if (ap->mode.rrm_neighbor_report) {
            rrm |= OSW_PLAT_BCM_RRM_BIT;
        }
        WARN_ON(WL(vif_name, "rrm", strfmta("%x", rrm)) == NULL);
        WL(vif_name, "rrm_nbr_static_disabled", "1");
    }
}

static char *
osw_plat_bcm_chanspec_from_osw(const struct osw_channel *c)
{
    const int freq = c->control_freq_mhz;
    const int chan = osw_freq_to_chan(freq);
    const enum osw_band band = osw_freq_to_band(freq);
    const bool primary_is_lower = (c->control_freq_mhz < c->center_freq0_mhz);
    switch (band) {
        case OSW_BAND_2GHZ:
        case OSW_BAND_5GHZ:
            switch (c->width) {
                case OSW_CHANNEL_20MHZ: return strfmt("%d", chan);
                case OSW_CHANNEL_40MHZ:
                    WARN_ON(c->control_freq_mhz == c->center_freq0_mhz);
                    WARN_ON(c->center_freq0_mhz == 0);
                    if (primary_is_lower) {
                        return strfmt("%dl", chan);
                    }
                    else {
                        return strfmt("%du", chan);
                    }
                case OSW_CHANNEL_80MHZ: return strfmt("%d/80", chan);
                case OSW_CHANNEL_160MHZ: return strfmt("%d/160", chan);
                case OSW_CHANNEL_320MHZ: return NULL;
                case OSW_CHANNEL_80P80MHZ: return NULL;
            }
            break;
        case OSW_BAND_6GHZ:
            switch (c->width) {
                case OSW_CHANNEL_20MHZ: return strfmt("6g%d", chan);
                case OSW_CHANNEL_40MHZ: return strfmt("6g%d/40", chan);
                case OSW_CHANNEL_80MHZ: return strfmt("6g%d/80", chan);
                case OSW_CHANNEL_160MHZ: return strfmt("6g%d/160", chan);
                case OSW_CHANNEL_320MHZ: return strfmt("6g%d/320-1", chan); /* FIXME, +/- */
                case OSW_CHANNEL_80P80MHZ: return NULL;
            }
            break;
        case OSW_BAND_UNDEFINED:
            return NULL;
    }
    return NULL;
}

static void
osw_plat_bcm_conf_vif_ap_channel(struct osw_drv_phy_config *phy,
                                 struct osw_drv_vif_config *vif)
{
    struct osw_drv_vif_config_ap *ap = &vif->u.ap;
    if (ap->channel_changed == false) return;

    const char *vif_name = vif->vif_name;
    char *chanspec = osw_plat_bcm_chanspec_from_osw(&ap->channel);
    if (WARN_ON(chanspec == NULL)) return;

    WARN_ON(WL(vif_name, "chanspec", chanspec) == NULL);

    if (ap->csa_required) {
        WARN_ON(WL(vif_name, "csa", "0", "15", chanspec) == NULL);
    }

    FREE(chanspec);
}

static void
osw_plat_bcm_conf_vif_ap_multi_ap(struct osw_drv_phy_config *phy,
                                  struct osw_drv_vif_config *vif)
{
    const struct osw_drv_vif_config_ap *ap = &vif->u.ap;
    if (ap->multi_ap_changed == false) return;

    const char *vif_name = vif->vif_name;
    const int val = osw_plat_bcm_map_from_osw_ap(&ap->multi_ap);
    WARN_ON(WL(vif_name, "map", strfmta("%d", val)) == NULL);
}

static void
osw_plat_bcm_conf_vif_sta_multi_ap(struct osw_drv_phy_config *phy,
                                   struct osw_drv_vif_config *vif)
{
    const struct osw_drv_vif_config_sta *sta = &vif->u.sta;
    const struct osw_drv_vif_sta_network *first = sta->network;
    if (sta->network_changed == false) return;
    if (first == NULL) return;

    const char *vif_name = vif->vif_name;
    const int val = osw_plat_bcm_map_from_osw_sta(first->multi_ap);
    if (osw_plat_bcm_map_changed(vif_name, val) == false) return;

    WARN_ON(WL(vif_name, "map", strfmta("%d", val)) == NULL);
}

static void
osw_plat_bcm_conf_each_vif(struct osw_drv_phy_config *phy,
                           struct osw_drv_vif_config *vif)
{
    (void)phy;
    (void)vif;

    switch (vif->vif_type) {
        case OSW_VIF_AP:
            osw_plat_bcm_conf_vif_ap_mcast2ucast(phy, vif);
            osw_plat_bcm_conf_vif_ap_acl(phy, vif);
            osw_plat_bcm_conf_vif_ap_acl_policy(phy, vif);
            osw_plat_bcm_conf_vif_ap_mode(phy, vif);
            osw_plat_bcm_conf_vif_ap_channel(phy, vif);
            osw_plat_bcm_conf_vif_ap_multi_ap(phy, vif);
            break;
        case OSW_VIF_AP_VLAN:
            break;
        case OSW_VIF_STA:
            osw_plat_bcm_conf_vif_sta_multi_ap(phy, vif);
            break;
        case OSW_VIF_UNDEFINED:
            break;
    }
}

static void
osw_plat_bcm_conf_each_vif_when_phy_enabled(struct osw_drv_phy_config *phy,
                                            struct osw_drv_vif_config *vif)
{
    (void)phy;
    (void)vif;

    switch (vif->vif_type) {
        case OSW_VIF_AP:
            osw_plat_bcm_conf_vif_ap_ssid(phy, vif);
            osw_plat_bcm_conf_vif_ap_enabled(phy, vif);
            break;
        case OSW_VIF_AP_VLAN:
            break;
        case OSW_VIF_STA:
            break;
        case OSW_VIF_UNDEFINED:
            break;
    }
}

static void
osw_plat_bcm_conf_phy_txchain(struct osw_drv_phy_config *phy)
{
    const char *phy_name = phy->phy_name;

    if (phy->tx_chainmask_changed) {
        WARN_ON(WL(phy_name, "txchain", strfmta("0x%x", phy->tx_chainmask)) == NULL);
    }
}

static int
osw_plat_bcm_radar_from_osw(enum osw_radar_detect radar)
{
    switch (radar) {
        case OSW_RADAR_UNSUPPORTED: return 0;
        case OSW_RADAR_DETECT_ENABLED: return 1;
        case OSW_RADAR_DETECT_DISABLED: return 0;
    }
    return 0;
}

static void
osw_plat_bcm_conf_phy_radar(struct osw_drv_phy_config *phy)
{
    const char *phy_name = phy->phy_name;

    if (phy->radar_changed) {
        const int value = osw_plat_bcm_radar_from_osw(phy->radar);
        WARN_ON(WL(phy_name, "radar", strfmta("%d", value)));
    }
}

static void
osw_plat_bcm_conf_each_phy(struct osw_drv_conf *drv_conf)
{
    size_t i;
    for (i = 0; i < drv_conf->n_phy_list; i++) {
        struct osw_drv_phy_config *phy = &drv_conf->phy_list[i];
        size_t j;
        for (j = 0; j < phy->vif_list.count; j++) {
            struct osw_drv_vif_config *vif = &phy->vif_list.list[j];
            osw_plat_bcm_conf_each_vif(phy, vif);
        }
        osw_plat_bcm_conf_phy_txchain(phy);
        osw_plat_bcm_conf_phy_radar(phy);
    }
}

static void
osw_plat_bcm_conf_each_phy_enabled(struct osw_drv_conf *drv_conf)
{
    size_t i;
    for (i = 0; i < drv_conf->n_phy_list; i++) {
        struct osw_drv_phy_config *phy = &drv_conf->phy_list[i];
        size_t j;
        for (j = 0; j < phy->vif_list.count; j++) {
            struct osw_drv_vif_config *vif = &phy->vif_list.list[j];
            osw_plat_bcm_conf_each_vif_when_phy_enabled(phy, vif);
        }
    }
}

static void
osw_plat_bcm_pre_request_config_cb(struct osw_drv_nl80211_hook *hook,
                                   struct osw_drv_conf *drv_conf,
                                   void *priv)
{
    struct osw_plat_bcm *m = priv;
    (void)m;

    osw_plat_bcm_conf_disable_phys(drv_conf);
    osw_plat_bcm_conf_each_phy(drv_conf);
    osw_plat_bcm_conf_enable_phys(drv_conf);
    osw_plat_bcm_conf_each_phy_enabled(drv_conf);
}

static void
osw_plat_bcm_drv_added_cb(struct osw_state_observer *obs,
                               struct osw_drv *drv)
{
    struct osw_plat_bcm *m = container_of(obs, struct osw_plat_bcm, state_obs);
    const struct osw_drv_ops *ops = osw_drv_get_ops(drv);
    const char *drv_name = ops->name;
    const bool is_nl80211 = (strstr(drv_name, "nl80211") != NULL);
    const bool is_not_nl80211 = !is_nl80211;

    if (is_not_nl80211) return;

    /* Knowing the osw_drv pointer of nl80211 makes it
     * possible to inject / supplement extra events as if
     * the nl80211 driver did it. For example probe_req
     * reports, channel switch changes, DFS events -- any
     * event that may be unavailable in the vendor's vanilla
     * nl80211 behavior.
     */
    m->drv_nl80211 = drv;

    LOGI(LOG_PREFIX("bound to nl80211"));
}

static void
osw_plat_bcm_drv_removed_cb(struct osw_state_observer *obs,
                                 struct osw_drv *drv)
{
    struct osw_plat_bcm *m = container_of(obs, struct osw_plat_bcm, state_obs);
    const bool is_not_nl80211 = (m->drv_nl80211 != drv);

    if (is_not_nl80211) return;

    m->drv_nl80211 = NULL;
    LOGI(LOG_PREFIX("unbound from nl80211"));
}

static void
osw_plat_bcm_init(struct osw_plat_bcm *m)
{
    const struct osw_state_observer obs = {
        .name = __FILE__,
        .drv_added_fn = osw_plat_bcm_drv_added_cb,
        .drv_removed_fn = osw_plat_bcm_drv_removed_cb,
    };
    m->state_obs = obs;
}

static void
osw_plat_bcm_ap_conf_mutate_cb(struct osw_hostap_hook *hook,
                               const char *phy_name,
                               const char *vif_name,
                               struct osw_drv_conf *drv_conf,
                               struct osw_hostap_conf_ap_config *hapd_conf,
                               void *priv)
{
    OSW_HOSTAP_CONF_SET_VAL(hapd_conf->send_probe_response, 0);
    OSW_HOSTAP_CONF_UNSET(hapd_conf->beacon_rate); // FIXME: detect at runtime
    OSW_HOSTAP_CONF_UNSET(hapd_conf->ieee80211ax);
    OSW_HOSTAP_CONF_UNSET(hapd_conf->ieee80211ac);
    OSW_HOSTAP_CONF_UNSET(hapd_conf->multi_ap); /* mapped to `map` iovar */
}

static void
osw_plat_bcm_sta_conf_mutate_strip_multi_ap(struct osw_hostap_conf_sta_network_config *net)
{
    while (net != NULL) {
        /* This is later mapped to `map` iovar */
        OSW_HOSTAP_CONF_UNSET(net->multi_ap_backhaul_sta);
        net = net->next;
    }
}

static void
osw_plat_bcm_sta_conf_mutate_cb(struct osw_hostap_hook *hook,
                                const char *phy_name,
                                const char *vif_name,
                                struct osw_drv_conf *drv_conf,
                                struct osw_hostap_conf_sta_config *wpas_conf,
                                void *priv)
{
    osw_plat_bcm_sta_conf_mutate_strip_multi_ap(wpas_conf->network);
}

static void
osw_plat_bcm_phy_stats_set_cb(struct osw_plat_bcm *m,
                              struct osw_plat_bcm_phy *phy,
                              void *priv)
{
    unsigned int *stats_mask = priv;
    const unsigned int old_mask = phy->stats_mask_pending;
    const unsigned int new_mask = (phy->stats_mask_pending | *stats_mask);
    if (old_mask == new_mask) return;
    const char *phy_name = phy->info->name;
    LOGT(LOG_PREFIX_PHY(phy_name, "stats: requesting: %08x -> %08x", old_mask, new_mask));
    phy->stats_mask_pending = new_mask;
}

static void
osw_plat_bcm_vif_stats_set_cb(struct osw_plat_bcm *m,
                              struct osw_plat_bcm_vif *vif,
                              void *priv)
{
    unsigned int *stats_mask = priv;
    const unsigned int old_mask = vif->stats_mask_pending;
    const unsigned int new_mask = (vif->stats_mask_pending | *stats_mask);
    if (old_mask == new_mask) return;
    const char *vif_name = vif->info->name;
    const char *phy_name = osw_plat_bcm_vif_into_phy_name(vif);
    if (phy_name == NULL) return;
    LOGT(LOG_PREFIX_VIF(phy_name, vif_name, "stats: requesting: %08x -> %08x", old_mask, new_mask));
    vif->stats_mask_pending = new_mask;
}

static void
osw_plat_bcm_sta_tx_avg(struct osw_plat_bcm_vif *vif,
                        const struct osw_hwaddr *sta_addr)
{
    const char *vif_name = vif->info->name;
    const char *phy_name = osw_plat_bcm_vif_into_phy_name(vif);
    const os_macaddr_t *hwaddr = (const os_macaddr_t *)sta_addr->octet;

    bcmwl_sta_info_t info = {0};
    const bool found = bcmwl_sta_get_sta_info(vif_name, hwaddr, &info);
    const bool not_found = !found;
    if (not_found) return;

    struct osw_hwaddr_str mac_buf;
    const char *mac_str = osw_hwaddr2str(sta_addr, &mac_buf);
    if (WARN_ON(mac_str == NULL)) return;

    struct bcmwl_sta_rate rate = {0};
    const int tx_err = bcmwl_sta_get_tx_avg_rate(vif_name, mac_str, &rate);
    if (WARN_ON(tx_err)) return;

    const int snr_raw = info.rssi - info.nf;
    const uint32_t snr = (snr_raw < 0) ? 0 : snr_raw;

    const uint32_t tx_mbps = rate.mbps_perceived;
    const uint32_t mpdu = rate.tried * rate.psr;
    const uint32_t retry = rate.tried - mpdu;
    const uint32_t tx_bytes = info.tx_total_bytes;
    const uint32_t rx_bytes = info.rx_total_bytes;
    const uint32_t tx_pkts = info.tx_total_pkts;
    const uint32_t rx_pkts = info.rx_total_pkts;
    const uint32_t tx_retries = info.tx_total_retries;
    const uint32_t rx_retries = info.rx_total_retries;

    struct osw_plat_bcm *m = vif->m;
    struct osw_drv *drv = m->drv_nl80211;
    if (drv == NULL) return;

    struct osw_tlv t = {0};
    {
        const size_t off = osw_tlv_put_nested(&t, OSW_STATS_STA);
        osw_tlv_put_string(&t, OSW_STATS_STA_PHY_NAME, phy_name);
        osw_tlv_put_string(&t, OSW_STATS_STA_VIF_NAME, vif_name);
        osw_tlv_put_hwaddr(&t, OSW_STATS_STA_MAC_ADDRESS, sta_addr);
        osw_tlv_put_u32(&t, OSW_STATS_STA_SNR_DB, snr);
        if (mpdu > 0) {
            osw_tlv_put_u32(&t, OSW_STATS_STA_TX_RATE_MBPS, tx_mbps);
        }
        osw_tlv_put_u32(&t, OSW_STATS_STA_TX_BYTES, tx_bytes);
        osw_tlv_put_u32(&t, OSW_STATS_STA_TX_FRAMES, tx_pkts);
        osw_tlv_put_u32(&t, OSW_STATS_STA_TX_RETRIES, tx_retries);
        osw_tlv_put_u32(&t, OSW_STATS_STA_RX_BYTES, rx_bytes);
        osw_tlv_put_u32(&t, OSW_STATS_STA_RX_FRAMES, rx_pkts);
        osw_tlv_put_u32(&t, OSW_STATS_STA_RX_RETRIES, rx_retries);
        osw_tlv_end_nested(&t, off);

        LOGT(LOG_PREFIX_STA(phy_name, vif_name, sta_addr,
                            " tx_mbps=%"PRIu32
                            " tx_mpdu=%"PRIu32
                            " tx_retry=%"PRIu32
                            " tx_bytes=%"PRIu32
                            " rx_bytes=%"PRIu32
                            " snr=%"PRIu32,
                            tx_mbps,
                            mpdu,
                            retry,
                            tx_bytes,
                            rx_bytes,
                            snr));
    }
    osw_drv_report_stats(drv, &t);
    osw_tlv_fini(&t);
}

static void
osw_plat_bcm_sta_rx_avg_cb(const char *vif_name,
                           const char *mac_octet,
                           const struct bcmwl_sta_rate *rate,
                           void *priv)
{
    struct osw_plat_bcm_vif *vif = priv;
    const char *phy_name = osw_plat_bcm_vif_into_phy_name(vif);
    if (phy_name == NULL) return;

    const struct osw_hwaddr *sta_addr = osw_hwaddr_from_cptr_unchecked(mac_octet);
    const uint32_t rx_mbps = rate->mbps_perceived;
    const uint32_t mpdu = rate->tried * rate->psr;
    const uint32_t retry = rate->tried - mpdu;

    if (mpdu == 0) return;

    struct osw_plat_bcm *m = vif->m;
    struct osw_drv *drv = m->drv_nl80211;
    if (drv == NULL) return;

    struct osw_tlv t = {0};
    {
        const size_t off = osw_tlv_put_nested(&t, OSW_STATS_STA);
        osw_tlv_put_string(&t, OSW_STATS_STA_PHY_NAME, phy_name);
        osw_tlv_put_string(&t, OSW_STATS_STA_VIF_NAME, vif_name);
        osw_tlv_put_hwaddr(&t, OSW_STATS_STA_MAC_ADDRESS, sta_addr);
        osw_tlv_put_u32(&t, OSW_STATS_STA_RX_RATE_MBPS, rx_mbps);
        osw_tlv_end_nested(&t, off);

        LOGT(LOG_PREFIX_STA(phy_name, vif_name, sta_addr,
                            " rx_mbps=%"PRIu32
                            " rx_mpdu=%"PRIu32
                            " rx_retry=%"PRIu32,
                            rx_mbps,
                            mpdu,
                            retry));
    }
    osw_drv_report_stats(drv, &t);
    osw_tlv_fini(&t);
}

static bool
osw_plat_bcm_vif_stats_run_sta(struct osw_plat_bcm_phy *phy,
                               struct osw_plat_bcm_vif *vif)
{
    const char *phy_name = phy->info->name;
    const char *vif_name = vif->info->name;

    LOGT(LOG_PREFIX_VIF(phy_name, vif_name, "stats: running: sta"));

    /* Can't really rely on nl_80211 object mapping because
     * the driver does not properly advertise station
     * add/del events. It does allow dumping them but that
     * can't be easily handled here for iteration.
     */
    char *assoclist = WL(vif_name, "assoclist") ?: "";
    char *line;
    while ((line = strsep(&assoclist, "\r\n")) != NULL) {
        const char *identifier = strsep(&line, " ");
        const bool wrong_identifier = (identifier == NULL)
                                   || (strcmp(identifier, "assoclist") != 0);
        if (wrong_identifier) continue;

        const char *macstr = strsep(&line, "") ?: "";
        struct osw_hwaddr addr;
        const bool invalid_macstr = (osw_hwaddr_from_cstr(macstr, &addr) == false);
        if (invalid_macstr) continue;

        osw_plat_bcm_sta_tx_avg(vif, &addr);
    }

    const bool rx_err = bcmwl_sta_get_rx_avg_rate(vif_name, osw_plat_bcm_sta_rx_avg_cb, vif);
    WARN_ON(rx_err);

    return true;
}

static bool
osw_plat_bcm_vif_stats_run_bss_scan(struct osw_plat_bcm_phy *phy,
                                    struct osw_plat_bcm_vif *vif)
{
    const char *phy_name = phy->info->name;
    const char *vif_name = vif->info->name;

    LOGT(LOG_PREFIX_VIF(phy_name, vif_name, "stats: running: bss scan"));

    channel_info_t ci;
    if (WARN_ON(bcmwl_GIOC(vif_name, WLC_GET_CHANNEL, NULL, &ci) == false)) {
        return false;
    }

    const struct bcmwl_ioctl_num_conv *conv = bcmwl_ioctl_lookup_num_conv(vif_name);
    if (WARN_ON(conv == NULL)) {
        return false;
    }

    const int32_t oper_chan = conv->dtoh32(ci.hw_channel);
    const char *oper_chan_str = strfmta("%"PRIi32, oper_chan);

    const bool scan_failed = (WL(vif_name, "escan", "-t", "lowpriority", "-c", oper_chan_str) == NULL);
    if (scan_failed) {
        if (phy->scan_failed == false) {
            LOGN(LOG_PREFIX_PHY(phy_name, "on-scan started failing, is cac running?"));
        }
    }
    else {
        if (phy->scan_failed) {
            LOGN(LOG_PREFIX_PHY(phy_name, "on-scan stopped failing, has cac finished?"));
        }
    }
    phy->scan_failed = scan_failed;

    return scan_failed ? false : true;
}

static void
osw_plat_bcm_cim_to_tlv(const char *phy_name,
                        const struct bcmwl_cim *cim,
                        struct osw_tlv *t)
{
    if (cim->channel == 0) {
        return;
    }

    const int cs = cim->chanspec;
    const int chan = cim->channel;
    const enum osw_band band = osw_plat_bcm_cs_into_band(cs);
    const int freq_mhz = osw_chan_to_freq(band, chan);
    const int noise = cim->nf;

    const size_t off1 = osw_tlv_put_nested(t, OSW_STATS_CHAN);
    osw_tlv_put_string(t, OSW_STATS_CHAN_PHY_NAME, phy_name);
    osw_tlv_put_u32(t, OSW_STATS_CHAN_FREQ_MHZ, freq_mhz);
    osw_tlv_put_float(t, OSW_STATS_CHAN_NOISE_FLOOR_DBM, noise);
    if (cim->usec.total > 0) {
        const uint64_t active_usec = cim->usec.total;
        const uint64_t active_msec = active_usec / 1000;
        osw_tlv_put_u32(t, OSW_STATS_CHAN_ACTIVE_MSEC, active_msec);

        const uint32_t tx = cim->usec.tx / 1000;
        const uint32_t rx = cim->usec.rx / 1000;
        const uint32_t inbss = cim->usec.rx_self / 1000;
        const uint32_t busy = cim->usec.busy / 1000;

        const size_t off2 = osw_tlv_put_nested(t, OSW_STATS_CHAN_CNT_MSEC);
        osw_tlv_put_u32(t, OSW_STATS_CHAN_CNT_TX, tx);
        osw_tlv_put_u32(t, OSW_STATS_CHAN_CNT_RX, rx);
        osw_tlv_put_u32(t, OSW_STATS_CHAN_CNT_RX_INBSS, inbss);
        osw_tlv_put_u32(t, OSW_STATS_CHAN_CNT_BUSY, busy);
        osw_tlv_end_nested(t, off2);
    }
    else {
        osw_tlv_put_u32(t, OSW_STATS_CHAN_ACTIVE_MSEC, cim->percent.timestamp);

        const uint32_t tx = cim->percent.tx;
        const uint32_t rx = cim->percent.rx;
        const uint32_t inbss = cim->percent.rx_self;
        const uint32_t busy = cim->percent.busy;

        const size_t off2 = osw_tlv_put_nested(t, OSW_STATS_CHAN_CNT_PERCENT);
        osw_tlv_put_u32(t, OSW_STATS_CHAN_CNT_TX, tx);
        osw_tlv_put_u32(t, OSW_STATS_CHAN_CNT_RX, rx);
        osw_tlv_put_u32(t, OSW_STATS_CHAN_CNT_RX_INBSS, inbss);
        osw_tlv_put_u32(t, OSW_STATS_CHAN_CNT_BUSY, busy);
        osw_tlv_end_nested(t, off2);
    }
    osw_tlv_end_nested(t, off1);
}

static bool
osw_plat_bcm_vif_stats_run_chan(struct osw_plat_bcm_phy *phy,
                                struct osw_plat_bcm_vif *vif)
{
    const char *phy_name = phy->info->name;
    const char *vif_name = vif->info->name;

    LOGT(LOG_PREFIX_VIF(phy_name, vif_name, "stats: running: chan"));

    struct bcmwl_cim arr[64] = {0};
    size_t len = ARRAY_SIZE(arr);
    const bool ok = bcmwl_cim_get(phy_name, arr, len);
    const bool failed = !ok;
    if (failed) return false;

    struct osw_plat_bcm *m = vif->m;
    struct osw_drv *drv = m->drv_nl80211;
    if (drv == NULL) return false;

    struct osw_tlv t = {0};
    size_t i;
    for (i = 0; i < len; i++) {
        osw_plat_bcm_cim_to_tlv(phy_name, &arr[i], &t);
    }
    osw_drv_report_stats(drv, &t);
    osw_tlv_fini(&t);

    return true;
}

static void
osw_plat_bcm_vif_stats_run_cb(struct osw_plat_bcm *m,
                              struct osw_plat_bcm_vif *vif,
                              void *priv)
{
    struct osw_plat_bcm_phy *phy = osw_plat_bcm_vif_into_phy(vif);
    if (phy == NULL) return;
    if (phy->info == NULL) return;
    if (vif->info == NULL) return;

    const int bit_bss_scan = (1 << OSW_STATS_BSS_SCAN);
    const int bit_chan = (1 << OSW_STATS_CHAN);
    const int bit_sta = (1 << OSW_STATS_STA);

    const char *phy_name = phy->info->name;
    const char *vif_name = vif->info->name;
    const bool is_phy = bcmwl_is_phy(phy_name);
    const bool is_phy_up = (atoi(WL(phy_name, "isup") ?: "0") != 0);
    bool is_netdev_up = false;
    (void)os_nif_is_up((char *)vif_name, &is_netdev_up);

    const bool capable_bss_scan = is_phy && is_netdev_up;
    const bool capable_chan = is_phy;
    const bool capable_sta = is_netdev_up && is_phy_up;

    LOGT(LOG_PREFIX_VIF(phy_name, vif_name,
                        "stats: run: pending=%08x is_netdev_up=%d is_phy_up=%d is_phy=%d capable_chan=%d capable_bss_scan=%d capable_sta=%d",
                        phy->stats_mask_pending,
                        is_netdev_up,
                        is_phy_up,
                        is_phy,
                        capable_chan,
                        capable_bss_scan,
                        capable_sta));

    if ((phy->stats_mask_pending & bit_bss_scan) && capable_bss_scan) {
        const bool ok = osw_plat_bcm_vif_stats_run_bss_scan(phy, vif);
        if (ok) {
            phy->stats_mask_pending &= ~bit_bss_scan;
        }
    }

    if ((phy->stats_mask_pending & bit_chan) && capable_chan) {
        const bool ok = osw_plat_bcm_vif_stats_run_chan(phy, vif);
        if (ok) {
            phy->stats_mask_pending &= ~bit_chan;
        }
    }

    if ((vif->stats_mask_pending & bit_sta) && capable_sta) {
        const bool ok = osw_plat_bcm_vif_stats_run_sta(phy, vif);
        if (ok) {
            vif->stats_mask_pending &= ~bit_sta;
        }
    }
}

static void
osw_plat_bcm_pre_request_stats_cb(struct osw_drv_nl80211_hook *hook,
                                  unsigned int stats_mask,
                                  void *priv)
{
    struct osw_plat_bcm *m = priv;
    const unsigned int phy_mask_allowed = (1 << OSW_STATS_BSS_SCAN)
                                        | (1 << OSW_STATS_CHAN);
    const unsigned int vif_mask_allowed = (1 << OSW_STATS_STA);
    unsigned int phy_stats_mask = (stats_mask & phy_mask_allowed);
    unsigned int vif_stats_mask = (stats_mask & vif_mask_allowed);

    osw_plat_bcm_phy_each(m, osw_plat_bcm_phy_stats_set_cb, &phy_stats_mask);
    osw_plat_bcm_vif_each(m, osw_plat_bcm_vif_stats_set_cb, &vif_stats_mask);
    osw_plat_bcm_vif_each(m, osw_plat_bcm_vif_stats_run_cb, NULL);
}

static void
osw_plat_bcm_get_vif_list_supplement_wds(const char *phy_name,
                                         osw_drv_report_vif_fn_t *report_vif_fn,
                                         void *fn_priv,
                                         struct osw_plat_bcm *m)
{
    const bool not_a_wl_phy = (bcmwl_is_phy(phy_name) == false);
    if (not_a_wl_phy) return;

    int ri;
    int vi;
    const bool phy_parse_err = (bcmwl_parse_vap(phy_name, &ri, &vi) == false);
    if (phy_parse_err) return;

    glob_t g;
    const char *pattern = strfmta("/sys/class/net/wds%d.*", ri);
    const int err = glob(pattern, 0, NULL, &g);
    if (err) return;
    size_t i;
    for (i = 0; i < g.gl_pathc; i++) {
        char *path = strdupa(g.gl_pathv[i]);
        char *if_name = basename(path);
        if (if_name == NULL) continue;
        report_vif_fn(if_name, fn_priv);
    }
    globfree(&g);
}

static void
osw_plat_bcm_get_vif_state_supplement_wds(const char *phy_name,
                                          const char *vif_name,
                                          struct osw_drv_vif_state *state,
                                          struct osw_plat_bcm *m)
{
    const bool is_not_wds = (strstr(vif_name, "wds") != vif_name);
    if (is_not_wds) return;

    bool is_up;
    state->exists = os_nif_is_up((char *)vif_name, &is_up);
    if (state->exists) {
        const enum osw_vif_status status = is_up
                                         ? OSW_VIF_ENABLED
                                         : OSW_VIF_DISABLED;
        osw_vif_status_set(&state->status, status);
    }
    state->vif_type = OSW_VIF_AP_VLAN;

    os_macaddr_t mac;
    const bool mac_addr_is_valid = os_nif_macaddr((char *)vif_name, &mac);
    if (mac_addr_is_valid) {
        memcpy(state->mac_addr.octet, mac.addr, sizeof(mac.addr));
    }
}

static void
osw_plat_bcm_get_vif_list_cb(struct osw_drv_nl80211_hook *hook,
                             const char *phy_name,
                             osw_drv_report_vif_fn_t *report_vif_fn,
                             void *fn_priv,
                             void *priv)
{
    struct osw_plat_bcm *m = priv;
    osw_plat_bcm_get_vif_list_supplement_wds(phy_name, report_vif_fn, fn_priv, m);
}

static void
osw_plat_bcm_get_vif_state_cb(struct osw_drv_nl80211_hook *hook,
                              const char *phy_name,
                              const char *vif_name,
                              struct osw_drv_vif_state *state,
                              void *priv)
{
    struct osw_plat_bcm *m = priv;
    osw_plat_bcm_get_vif_state_supplement_wds(phy_name, vif_name, state, m);
}

static char *
osw_plat_bcm_wiphy_to_vif_name(const uint32_t wiphy)
{
    glob_t g;
    const char *pattern = "/sys/class/net/*/phy80211/index";
    const int err = glob(pattern, 0, NULL, &g);
    if (err) return false;
    char *vif_name = NULL;
    size_t i;
    for (i = 0; i < g.gl_pathc; i++) {
        char *path = strdupa(g.gl_pathv[i]);
        char *index = file_geta(path);
        if (WARN_ON(index == NULL)) continue;
        const long long idx = atoll(index);
        if (WARN_ON(idx < 0)) continue;
        if (WARN_ON(idx >= UINT32_MAX)) continue;
        if ((uint32_t)idx != wiphy) continue;
        if (dirname(path) == NULL) continue;
        if (dirname(path) == NULL) continue;
        char *name = basename(path);
        if (bcmwl_is_phy(name) == false) continue;
        vif_name = STRDUP(name);
        break;
    }
    globfree(&g);
    return vif_name;
}

static bool
osw_plat_bcm_phy_try_rename(const struct nl_80211_phy *info)
{
    const uint32_t wiphy = info->wiphy;
    const char *phy_name = info->name;
    const char *wiphy_name = strfmta("phy#%"PRIu32, wiphy);
    char *vif_name = osw_plat_bcm_wiphy_to_vif_name(wiphy);
    if (vif_name == NULL) return false;
    if (bcmwl_is_phy(vif_name) == false) return false;

    const bool mismatched = (strcmp(phy_name, vif_name) != 0);
    if (mismatched) {
        LOGN(LOG_PREFIX_PHY(wiphy_name, "renaming to: %s", vif_name));

        /* For a reason I cannot figure out, and I did look
         * at kernel source, if this isn't done, the rename
         * event is not seen on the system, at all, even
         * when running side-by-side an `iw event`.
         */
        WARN_ON(os_nif_up((char *)vif_name, true) == false);
        WARN_ON(os_nif_up((char *)vif_name, false) == false);

        WARN_ON(strexa("iw", wiphy_name, "set", "name", vif_name) == NULL);
    }
    FREE(vif_name);

    return mismatched;
}

static void
osw_plat_bcm_phy_set_apsta(const struct nl_80211_phy *info)
{
    const uint32_t wiphy = info->wiphy;
    char *vif_name = osw_plat_bcm_wiphy_to_vif_name(wiphy);
    if (vif_name == NULL) return;

    const char *apsta = WL(vif_name, "apsta");
    if (WARN_ON(apsta == NULL)) {
        FREE(vif_name);
        return;
    }

    const bool primary_as_sta = getenv("OSW_PLAT_BCM_STA_VIF_ENABLED");
    const bool apsta_desired = (primary_as_sta ? 1 : 0);
    const bool apsta_state = atoi(apsta);

    if (apsta_desired != apsta_state) {
        LOGD(LOG_PREFIX_PHY(vif_name, "iovar: apsta: %d -> %d", apsta_state, apsta_desired));

        const bool was_up = atoi(WL(vif_name, "isup") ?: "0");
        WARN_ON(WL(vif_name, "down") == NULL);

        if (apsta_desired) {
            WARN_ON(WL(vif_name, "ap", "0") == NULL);
            WARN_ON(WL(vif_name, "apsta", "1") == NULL);
        }
        else {
            WARN_ON(WL(vif_name, "apsta", "0") == NULL);
            WARN_ON(WL(vif_name, "ap", "0") == NULL);
            WARN_ON(WL(vif_name, "ap", "1") == NULL);
        }

        if (was_up) {
            WARN_ON(WL(vif_name, "up") == NULL);
        }
    }
}

static void
osw_plat_bcm_phy_fix_channels(const struct nl_80211_phy *info)
{
    const uint32_t wiphy = info->wiphy;
    char *vif_name = osw_plat_bcm_wiphy_to_vif_name(wiphy);
    if (vif_name == NULL) return;

    bool is_up = false;
    WARN_ON(os_nif_is_up(vif_name, &is_up) == false);

    /* After booting, or after reloading the driver, channel
     * list reported over nl80211 is not constrained
     * properly to the regulatory and factory limits. It
     * gets updated when first interface is brought up. If
     * the interface is up then it is already correct.
     */
    const bool chanlist_possibly_wrong = (is_up == false);
    if (chanlist_possibly_wrong) {
        WARN_ON(os_nif_up(vif_name, true) == false);
        WARN_ON(os_nif_up(vif_name, false) == false);
    }

    FREE(vif_name);
}

static void
osw_plat_bcm_phy_fix_radar(const struct nl_80211_phy *info)
{
    const uint32_t wiphy = info->wiphy;
    char *vif_name = osw_plat_bcm_wiphy_to_vif_name(wiphy);
    if (vif_name == NULL) return;
    WL(vif_name, "radar", "1");
}

static void
osw_plat_bcm_phy_added_cb(const struct nl_80211_phy *info,
                          void *priv)
{
    struct osw_plat_bcm *m = priv;
    struct nl_80211_sub *sub = m->nl_sub;
    struct osw_plat_bcm_phy *phy = nl_80211_sub_phy_get_priv(sub, info);
    if (phy == NULL) return;

    (void)osw_plat_bcm_phy_try_rename(info);
    osw_plat_bcm_phy_set_apsta(info);
    osw_plat_bcm_phy_fix_channels(info);
    osw_plat_bcm_phy_fix_radar(info);

    phy->info = info;
    phy->m = m;
}

static void
osw_plat_bcm_phy_renamed_cb(const struct nl_80211_phy *info,
                            const char *old_name,
                            const char *new_name,
                            void *priv)
{
    struct osw_plat_bcm *m = priv;
    struct nl_80211_sub *sub = m->nl_sub;
    struct osw_plat_bcm_phy *phy = nl_80211_sub_phy_get_priv(sub, info);
    if (phy == NULL) return;

    const bool re_renamed = osw_plat_bcm_phy_try_rename(info);
    WARN_ON(re_renamed);
}

static void
osw_plat_bcm_phy_removed_cb(const struct nl_80211_phy *info,
                            void *priv)
{
    struct osw_plat_bcm *m = priv;
    struct nl_80211_sub *sub = m->nl_sub;
    struct osw_plat_bcm_phy *phy = nl_80211_sub_phy_get_priv(sub, info);
    if (phy == NULL) return;

    phy->info = NULL;
    phy->m = NULL;
}

static void
osw_plat_bcm_vif_wl_init_rrm(const char *vif_name)
{
    int ri;
    int vi;
    const bool parse_err = (bcmwl_parse_vap(vif_name, &ri, &vi) == false);
    if (parse_err) return;
    switch (vi) {
        case 2:
        case 6:
            /* Best-effort enable on an interface if the phy
             * is down. It should be down when system boots.
             * Otherwise it should leave it untouched in
             * practice.
             */
            WL(vif_name, "rrm", "+2");
            WL(vif_name, "wnm", "+1");
            break;
    }
}

static void
osw_plat_bcm_vif_wl_init(const char *vif_name)
{
    if (bcmwl_is_vif(vif_name)) {
        WARN_ON(WL(vif_name, "mbo", "ap_enable", "0") == NULL);
    }

    if (bcmwl_is_phy(vif_name)) {
        WL(vif_name, "bw_cap", "2g", "0xff");
        WL(vif_name, "bw_cap", "5g", "0xff");
        WL(vif_name, "bw_cap", "6g", "0xff");
        WARN_ON(WL(vif_name, "dfs_handle_radar_onsta", "1") == NULL);
        WARN_ON(WL(vif_name, "keep_ap_up", "1") == NULL);
        WARN_ON(WL(vif_name, "mpc", "0") == NULL);

        if (bcmwl_vap_is_sta(vif_name)) {
            WARN_ON(WL(vif_name, "assoc_retry_max", "6") == NULL);
            WARN_ON(WL(vif_name, "sta_retry_time", "0") == NULL);
            WARN_ON(WL(vif_name, "roam_off", "1") == NULL);
        }
    }
}

static unsigned int
osw_plat_bcm_rssi_into_snr(struct osw_plat_bcm_vif *vif,
                           const int rssi)
{
    const char *vif_name = vif->info->name;
    /* FIXME: NF readout could be cached to reduce rate of
     * syscalls.
     */
    const int raw_nf = atoi(WL(vif_name, "noise") ?: "0");
    const int standard_nf = -95;
    const int insane_nf = -50;
    /* Chances of NF being -50 is more likely due to buggy
     * reporting than actual interference.
     */
    const int snr = rssi - (raw_nf < insane_nf ? raw_nf : standard_nf);
    const int snr_clipped_to_0 = (snr < 0) ? 0 : snr;
    return snr_clipped_to_0;
}

static bool
osw_plat_bcm_vif_event_handle_rx_frame_probe_req(struct osw_plat_bcm_vif *vif,
                                                 const bcm_event_t *ev,
                                                 const wl_event_rx_frame_data_t *rxd,
                                                 const struct osw_drv_dot11_frame_header *hdr,
                                                 const size_t len_after_hdr)
{
    const void *ies = (const void *)hdr + sizeof(*hdr);
    const size_t ies_len = len_after_hdr;

    struct osw_ssid ssid;
    const uint8_t ssid_eid = 0;
    const void *ssid_start = osw_ie_find(ies, ies_len, ssid_eid, &ssid.len);
    const bool ssid_found = osw_ssid_from_cbuf(&ssid, ssid_start, ssid.len);
    (void)ssid_found; /* dont care; its fine to consider no ssid as wildcard */

    const int rssi = ntohl(rxd->rssi);
    const unsigned int snr = osw_plat_bcm_rssi_into_snr(vif, rssi);

    const struct osw_hwaddr *sta_addr = osw_hwaddr_from_cptr_unchecked(&ev->event.addr);
    const struct osw_drv_report_vif_probe_req probe_req = {
        .sta_addr = *sta_addr,
        .snr = snr,
        .ssid = ssid,
    };

    struct osw_plat_bcm *m = vif->m;
    struct osw_drv *drv = m->drv_nl80211;
    if (drv == NULL) return false;

    const char *phy_name = osw_plat_bcm_vif_into_phy_name(vif);
    const char *vif_name = vif->info->name;

    LOGT(LOG_PREFIX_VIF(phy_name, vif_name,
                        "probe req: ta="OSW_HWADDR_FMT" ssid="OSW_SSID_FMT" snr=%u",
                        OSW_HWADDR_ARG(&probe_req.sta_addr),
                        OSW_SSID_ARG(&probe_req.ssid),
                        probe_req.snr));

    osw_drv_report_vif_probe_req(drv, phy_name, vif_name, &probe_req);
    return true;
}

static bool
osw_plat_bcm_vif_event_handle_rx_frame_data(struct osw_plat_bcm_vif *vif,
                                            const bcm_event_t *ev,
                                            const wl_event_rx_frame_data_t *rxd,
                                            const size_t len_after_rxd)
{
    const void *pkt = (const void *)rxd + sizeof(*rxd);
    const size_t pkt_len = len_after_rxd;

    size_t len_after_hdr;
    const struct osw_drv_dot11_frame_header *hdr = ieee80211_frame_into_header(pkt, pkt_len, len_after_hdr);
    const uint16_t fc = le16toh(hdr->frame_control);
    const uint16_t type = (fc & DOT11_FRAME_CTRL_TYPE_MASK);
    const uint16_t subtype = (fc & DOT11_FRAME_CTRL_SUBTYPE_MASK);

    LOGT("%s: type=%"PRIu16" subtype=%"PRIu16,
         __func__,
         type,
         subtype);

    const int rssi = ntohl(rxd->rssi);
    const unsigned int snr = osw_plat_bcm_rssi_into_snr(vif, rssi);

    const struct osw_drv_vif_frame_rx rx = {
        .data = pkt,
        .len = pkt_len,
        .snr = snr,
    };

    struct osw_plat_bcm *m = vif->m;
    struct osw_drv *drv = m->drv_nl80211;
    if (drv == NULL) {
        return false;
    }

    const char *phy_name = osw_plat_bcm_vif_into_phy_name(vif);
    const char *vif_name = vif->info->name;

    osw_drv_report_vif_frame_rx(drv, phy_name, vif_name, &rx);

    if (1) return true;

    /* FIXME: This ideally can, and should be unified as a
     * single OSW report call with parsed rx metadata like
     * signal strength, frequency.
     */
    switch (type) {
        case DOT11_FRAME_CTRL_TYPE_MGMT:
            switch (subtype) {
                case DOT11_FRAME_CTRL_SUBTYPE_PROBE_REQ:
                    return osw_plat_bcm_vif_event_handle_rx_frame_probe_req(vif, ev, rxd, hdr, len_after_hdr);
            }
            break;
    }

    return true;
}

static bool
osw_plat_bcm_vif_event_handle_probe_req_msg_rx(struct osw_plat_bcm_vif *vif,
                                               const bcm_event_t *ev,
                                               const size_t len_after_ev)
{
    const wl_event_rx_frame_data_t *rxd = (const void *)ev + sizeof(*ev);
    size_t size = sizeof(*rxd);
    LOGT("%s: rxd=%zu len_after_ev=%zu", __func__, size, len_after_ev);
    if (WARN_ON(len_after_ev < size)) return false;
    const size_t len_after_rxd = len_after_ev - size;

    return osw_plat_bcm_vif_event_handle_rx_frame_data(vif, ev, rxd, len_after_rxd);
}

static bool
osw_plat_bcm_vif_event_handle_action_frame(struct osw_plat_bcm_vif *vif,
                                           const bcm_event_t *ev,
                                           const size_t len_after_ev)
{
    const void *body = (const void *)ev + sizeof(*ev);
    const size_t body_len = len_after_ev;

    const struct osw_hwaddr *sta_addr = osw_hwaddr_from_cptr_unchecked(&ev->event.addr);
    struct osw_drv_dot11_frame_header hdr;
    uint8_t pkt[4096];
    const size_t pkt_len = sizeof(hdr) + body_len;
    if (WARN_ON(pkt_len > sizeof(pkt))) return false; /* unlikely */

    struct osw_plat_bcm *m = vif->m;
    struct osw_drv *drv = m->drv_nl80211;
    if (drv == NULL) return false;

    const char *vif_name = vif->info->name;
    const char *phy_name = osw_plat_bcm_vif_into_phy_name(vif);
    if (phy_name == NULL) return false;

    const uint16_t type = DOT11_FRAME_CTRL_TYPE_MGMT;
    const uint16_t subtype = DOT11_FRAME_CTRL_SUBTYPE_ACTION;
    hdr.frame_control = htole16(type | subtype);
    memcpy(hdr.sa, sta_addr->octet, sizeof(hdr.sa));
    memcpy(pkt, &hdr, sizeof(hdr));
    memcpy(pkt + sizeof(hdr), body, body_len);

    const struct osw_drv_vif_frame_rx rx = {
        .data = pkt,
        .len = pkt_len,
    };
    osw_drv_report_vif_frame_rx(drv, phy_name, vif_name, &rx);
    return true;
}

static bool
osw_plat_bcm_vif_event_handle_assoc_reassoc_ind(struct osw_plat_bcm_vif *vif,
                                                const bcm_event_t *ev,
                                                const size_t len_after_ev)
{
    struct osw_plat_bcm *m = vif->m;
    struct osw_drv *drv = m->drv_nl80211;
    if (drv == NULL) return true;

    const char *phy_name = osw_plat_bcm_vif_into_phy_name(vif);
    if (WARN_ON(phy_name == NULL)) return true;

    const char *vif_name = vif->info->name;
    const struct osw_hwaddr *sta_addr = osw_hwaddr_from_cptr_unchecked(&ev->event.addr);
    const void *ies = (const void *)ev + sizeof(*ev);
    const size_t fcs_len = 0; /* FIXME: Is this still being appended? */
    const size_t ies_len = len_after_ev - fcs_len;

    osw_drv_report_sta_assoc_ies(drv, phy_name, vif_name, sta_addr, ies, ies_len);
    return true;
}

static bool
osw_plat_bcm_report_bss(struct osw_plat_bcm_vif *vif,
                        const struct osw_hwaddr *bssid,
                        const int freq_mhz,
                        const int rssi_dbm,
                        const int noise_dbm,
                        const void *ies,
                        const size_t ies_len)
{
    if (WARN_ON(bssid == NULL)) return false;

    const char *phy_name = osw_plat_bcm_vif_into_phy_name(vif);
    if (WARN_ON(phy_name == NULL)) return false;
    struct osw_tlv t = {0};

    const int snr_raw = rssi_dbm - noise_dbm;
    const uint32_t snr_db = (snr_raw < 0) ? 0 : snr_raw;
    const size_t off = osw_tlv_put_nested(&t, OSW_STATS_BSS_SCAN);
    osw_tlv_put_string(&t, OSW_STATS_BSS_SCAN_PHY_NAME, phy_name);
    osw_tlv_put_hwaddr(&t, OSW_STATS_BSS_SCAN_MAC_ADDRESS, bssid);
    osw_tlv_put_u32(&t, OSW_STATS_BSS_SCAN_SNR_DB, snr_db);
    osw_tlv_put_u32(&t, OSW_STATS_BSS_SCAN_FREQ_MHZ, freq_mhz);

    if (ies != NULL && ies_len > 0) {
        osw_tlv_put_buf(&t, OSW_STATS_BSS_SCAN_IES, ies, ies_len);
    }
    //osw_tlv_put_u32(&t, OSW_STATS_BSS_SCAN_WIDTH_MHZ, width_mhz);
    //osw_tlv_put_buf(&t, OSW_STATS_BSS_SCAN_SSID, ssid, ssid_len);
    osw_tlv_end_nested(&t, off);

    LOGT(LOG_PREFIX_PHY(phy_name,
                        "report: bss: "OSW_HWADDR_FMT" on freq=%dMHz rssi=%ddBm noise=%ddBm snr_db=%udB ies=%zuB",
                        OSW_HWADDR_ARG(bssid),
                        freq_mhz,
                        rssi_dbm,
                        noise_dbm,
                        snr_db,
                        ies_len));

    struct osw_plat_bcm *m = vif->m;
    struct osw_drv *drv = m->drv_nl80211;
    if (drv == NULL) return false;

    osw_drv_report_stats(drv, &t);
    osw_tlv_fini(&t);
    return true;
}

static int
osw_plat_bcm_cs_into_pri_freq(const int cs)
{
    const enum osw_band band = osw_plat_bcm_cs_into_band(cs);
    const int primary_chan = bcmwl_chanspec_get_primary(cs);
    const int primary_freq = osw_chan_to_freq(band, primary_chan);
    return primary_freq;
}

static size_t
osw_plat_bcm_vif_event_handle_escan_result_partial_v107(struct osw_plat_bcm_vif *vif,
                                                        const bcm_event_t *ev,
                                                        const wl_bss_info_107_t *bi,
                                                        size_t rem)
{
    const uint16_t ies_off = sizeof(*bi);
    const uint32_t ies_len = ntohl(bi->ie_length);
    const void *ies = (void *)bi + ies_off;
    const void *ies_end = ies + ies_len;
    const size_t bi_len = (ies_end - (const void *)bi);
    if (bi_len <= rem) {
        const struct osw_hwaddr *bssid = osw_hwaddr_from_cptr_unchecked(bi->BSSID.octet);
        const int16_t rssi_dbm = ntohs(bi->RSSI);
        const int8_t noise_dbm = bi->phy_noise;
        const int chan = bi->channel;
        const enum osw_band band = osw_chan_to_band_guess(chan);
        const int freq_mhz = osw_chan_to_freq(band, chan);
        osw_plat_bcm_report_bss(vif, bssid, freq_mhz, rssi_dbm, noise_dbm, ies, ies_len);
    }
    return bi_len;
}

static size_t
osw_plat_bcm_vif_event_handle_escan_result_partial_v108(struct osw_plat_bcm_vif *vif,
                                                        const bcm_event_t *ev,
                                                        const wl_bss_info_108_t *bi,
                                                        size_t rem)
{
    const uint16_t ies_off = ntohs(bi->ie_offset);
    const uint32_t ies_len = ntohl(bi->ie_length);
    const void *ies = (void *)bi + ies_off;
    const void *ies_end = ies + ies_len;
    const size_t bi_len = (ies_end - (const void *)bi);
    if (bi_len <= rem) {
        const struct osw_hwaddr *bssid = osw_hwaddr_from_cptr_unchecked(bi->BSSID.octet);
        const int16_t rssi_dbm = ntohs(bi->RSSI);
        const int8_t noise_dbm = bi->phy_noise;
        const int cs = ntohs(bi->chanspec);
        const int freq_mhz = osw_plat_bcm_cs_into_pri_freq(cs);
        osw_plat_bcm_report_bss(vif, bssid, freq_mhz, rssi_dbm, noise_dbm, ies, ies_len);
    }
    return bi_len;
}

static size_t
osw_plat_bcm_vif_event_handle_escan_result_partial_v109(struct osw_plat_bcm_vif *vif,
                                                        const bcm_event_t *ev,
                                                        const wl_bss_info_v109_t *bi,
                                                        size_t rem)
{
    const uint16_t ies_off = bi->ie_offset; // byte swap?
    const uint32_t ies_len = bi->ie_length; // byte swap?
    const void *ies = (void *)bi + ies_off;
    const void *ies_end = ies + ies_len;
    const size_t bi_len = (ies_end - (const void *)bi);
    LOGT("%s: bi=%p ies=%p ies_end=%p sizeof(*bi)=%zu ies_off=%zu ies_len=%zu",
        __func__,
        bi,
        ies,
        ies_end,
        sizeof(*bi),
        ies_off,
        ies_len);

    if (bi_len <= rem) {
        const struct osw_hwaddr *bssid = osw_hwaddr_from_cptr_unchecked(bi->BSSID.octet);
        const int16_t rssi_dbm = (bi->RSSI); // swap?
        const int8_t noise_dbm = bi->phy_noise;
        const int cs = (bi->chanspec); // swap?
        const int freq_mhz = osw_plat_bcm_cs_into_pri_freq(cs);
        osw_plat_bcm_report_bss(vif, bssid, freq_mhz, rssi_dbm, noise_dbm, ies, ies_len);
    }
    return bi_len;
}

static bool
osw_plat_bcm_vif_event_handle_escan_result_partial(struct osw_plat_bcm_vif *vif,
                                                   const bcm_event_t *ev,
                                                   const size_t len_after_ev)
{
    const wl_escan_result_v2_t *result = (void *)ev + sizeof(*ev);
    if (WARN_ON(len_after_ev < sizeof(*result))) return false;

    const size_t len_after_result = len_after_ev - sizeof(*result);
    const wl_bss_info_107_t *bi = (const void *)result->bss_info;
    size_t rem = len_after_result;
    while (rem >= sizeof(*bi)) {
        const uint32_t bi_version = bi->version; // shouldn't this be byte-swapped depending on dongle type?
        LOGT("%s: bi_version = %u", __func__, bi_version);
        size_t consumed = rem + 1;
        switch (bi_version) {
            case 107:
                consumed = osw_plat_bcm_vif_event_handle_escan_result_partial_v107(vif, ev, (const void *)bi, rem);
                break;
            case 108:
                consumed = osw_plat_bcm_vif_event_handle_escan_result_partial_v108(vif, ev, (const void *)bi, rem);
                break;
            case 109:
                consumed = osw_plat_bcm_vif_event_handle_escan_result_partial_v109(vif, ev, (const void *)bi, rem);
                break;
            default:
                WARN_ON(1);
                break;
        }
        LOGT("%s: rem=%zu consumed=%zu", __func__, rem, consumed);
        if (WARN_ON(consumed > rem)) {
            break;
        }

        rem -= consumed;
    }

    const size_t alignment = 4;
    const size_t max_padding_len = (alignment - 1);
    WARN_ON(rem > max_padding_len);

    return true;
}

static bool
osw_plat_bcm_vif_event_handle_escan_result(struct osw_plat_bcm_vif *vif,
                                           const bcm_event_t *ev,
                                           const size_t len_after_ev)
{
    const uint32_t status = ntohl(ev->event.status);
    switch (status) {
        case WLC_E_STATUS_PARTIAL:
            /* This will report BSS per call over OSW stats.
             * This could be optimized to batch and report
             * them upon WLC_E_STATUS_SUCCESS. There's a few
             * gotchas to handle, so better stick with this
             * for now. If this proves to be inefficient
             * this can be fixed.
             */
            return osw_plat_bcm_vif_event_handle_escan_result_partial(vif, ev, len_after_ev);
        case WLC_E_STATUS_SUCCESS:
            /* finished successfully */
            break;
        default:
            /* aborted or error */
            break;
    }
    return true;
}

static bool
osw_plat_bcm_vif_event_phy_is_invalidated(const int e)
{
    switch (e) {
        case WLC_E_DFS_AP_RESUME:
        case WLC_E_DFS_AP_STOP:
        case WLC_E_RADIO:
        case WLC_E_RADAR_DETECTED:
        case WLC_E_DFS_HIT:
        case WLC_E_CAC_STATE_CHANGE:
            return true;
    }
    return false;
}

static bool
osw_plat_bcm_vif_event_vif_is_invalidated(const int e)
{
    switch (e) {
        case WLC_E_LINK:
        case WLC_E_JOIN:
        case WLC_E_AP_STARTED:
        case WLC_E_IF:
        case WLC_E_AP_CHAN_CHANGE:
        case WLC_E_CSA_START_IND:
        case WLC_E_CSA_DONE_IND:
        case WLC_E_CSA_FAILURE_IND:
        case WLC_E_CSA_COMPLETE_IND:
        case WLC_E_CSA_RECV_IND:
        case WLC_E_ASSOC:
        case WLC_E_ASSOC_IND:
        case WLC_E_AUTH:
        case WLC_E_AUTH_IND:
        case WLC_E_AUTHORIZED:
        case WLC_E_DEAUTH:
        case WLC_E_DEAUTH_IND:
        case WLC_E_DISASSOC:
        case WLC_E_DISASSOC_IND:
            return true;
    }
    return false;
}

static bool
osw_plat_bcm_vif_event_sta_is_invalidated(const int e)
{
    switch (e) {
        case WLC_E_ASSOC:
        case WLC_E_ASSOC_IND:
        case WLC_E_AUTH:
        case WLC_E_AUTH_IND:
        case WLC_E_AUTHORIZED:
        case WLC_E_DEAUTH:
        case WLC_E_DEAUTH_IND:
        case WLC_E_DISASSOC:
        case WLC_E_DISASSOC_IND:
            return true;
    }
    return false;
}

static struct osw_plat_bcm_vif *
osw_plat_bcm_lookup_vif(struct osw_plat_bcm *m,
                        const char *vif_name)
{
    struct osw_drv_nl80211_ops *nl_ops = m->nl_ops;
    if (nl_ops == NULL) return NULL;

    struct nl_80211 *nl = nl_ops->get_nl_80211_fn(nl_ops);
    if (nl == NULL) return NULL;

    struct nl_80211_sub *sub = m->nl_sub;
    if (sub == NULL) return NULL;

    const struct nl_80211_vif *info = nl_80211_vif_by_name(nl, vif_name);
    if (info == NULL) return NULL;

    struct osw_plat_bcm_vif *vif = nl_80211_sub_vif_get_priv(sub, info);
    return vif;
}

static bool
osw_plat_bcm_event_handle(struct osw_plat_bcm *m,
                          const bcm_event_t *ev,
                          const ssize_t len_after_ev)
{
    const char *vif_name = ev->event.ifname;
    const int e = ntohl(ev->event.event_type);

    if (osw_plat_bcm_vif_event_phy_is_invalidated(e)) {
        osw_plat_bcm_report_phy_changed(m, vif_name);
    }

    if (osw_plat_bcm_vif_event_vif_is_invalidated(e)) {
        osw_plat_bcm_report_vif_changed(m, vif_name);
    }

    struct osw_plat_bcm_vif *vif = osw_plat_bcm_lookup_vif(m, vif_name);
    if (vif == NULL) return false;

    if (osw_plat_bcm_vif_event_sta_is_invalidated(e)) {
        const struct osw_hwaddr *sta_addr = osw_hwaddr_from_cptr_unchecked(&ev->event.addr);
        osw_plat_bcm_vif_report_sta_changed(vif, sta_addr);
    }

    switch (e) {
        case WLC_E_PROBREQ_MSG_RX:
            return osw_plat_bcm_vif_event_handle_probe_req_msg_rx(vif, ev, len_after_ev);
        case WLC_E_ACTION_FRAME:
            return osw_plat_bcm_vif_event_handle_action_frame(vif, ev, len_after_ev);
        case WLC_E_ASSOC_IND:
            return osw_plat_bcm_vif_event_handle_assoc_reassoc_ind(vif, ev, len_after_ev);
        case WLC_E_REASSOC_IND:
            return osw_plat_bcm_vif_event_handle_assoc_reassoc_ind(vif, ev, len_after_ev);
        case WLC_E_ESCAN_RESULT:
            return osw_plat_bcm_vif_event_handle_escan_result(vif, ev, len_after_ev);
        default:
            return false;
    }
    return false;
}

static bool
osw_plat_bcm_event_try(struct osw_plat_bcm *m,
                       bool *overrun)
{
    ev_io *io = &m->event_io;
    const int fd = io->fd;
    char buf[4096];
    const size_t size = sizeof(buf);
    const bcm_event_t *ev = (const void *)buf;

    const ssize_t rv = bcmwl_event_msg_read(fd, buf, size);
    LOGT(LOG_PREFIX("read(%d, %zu) = %zd, errno = %d", fd, size, rv, errno));

    if (rv < 0) {
        switch (errno) {
            case EAGAIN:
                break;
            case EINTR:
                break;
            case ENOBUFS:
                *overrun = true;
                break;
            default:
                WARN_ON(1);
                break;
        }
        return false;
    }

    /* Cast is safe: We've confirmed it's not a negative
     * above and therefore it will fit without underflows in
     * an unsigned variant.
     */
    const size_t len = (size_t)rv;
    if (WARN_ON(len < sizeof(*ev))) {
        return false;
    }
    const size_t observed_len_after_ev = len - sizeof(*ev);
    const size_t supposed_len_after_ev = ntohl(ev->event.datalen);
    const int wlc_e = ntohl(ev->event.event_type);
    LOGT("%s: id=%d len=%zu len_after_ev=%zu supposed_len_after_ev=%zu",
          __func__,
          wlc_e,
          len,
          observed_len_after_ev,
          supposed_len_after_ev);
    if (WARN_ON(supposed_len_after_ev > observed_len_after_ev)) {
        return false;
    }

    const size_t len_after_ev = supposed_len_after_ev;
    const bool handled = osw_plat_bcm_event_handle(m, ev, len_after_ev);
    (void)handled;

    return true;
}

static size_t
osw_plat_bcm_event_try_n(struct osw_plat_bcm *m,
                         size_t budget,
                         bool *overrun)
{
    size_t count = 0;
    while (budget > 0) {
        const bool more = osw_plat_bcm_event_try(m, overrun);
        const bool done = !more;
        if (done) break;
        budget--;
        count++;
    }

    ev_io *io = &m->event_io;
    const int fd = io->fd;
    const int dropped = bcmwl_event_get_dropped(fd);
    if (dropped > 0) {
        *overrun = true;
    }

    return count;
}

static void
osw_plat_bcm_event_io_cb(struct ev_loop *loop,
                         ev_io *io,
                         int events)
{
    struct osw_plat_bcm *m = io->data;

    bool overrun = false;
    const size_t budget = 256;
    const size_t count = osw_plat_bcm_event_try_n(m, budget, &overrun);

    if (count == budget) {
        LOGI(LOG_PREFIX("event io is very busy"));
    }

    if (overrun) {
        LOGI(LOG_PREFIX("event io suffered overrun"));

        struct osw_drv *drv = m->drv_nl80211;
        if (drv != NULL) {
            osw_drv_report_overrun(drv);
        }
    }
}

static int
osw_plat_bcm_event_init_fd(int fd)
{
    const int size_2mbyte = 2 * 1024 * 1024;
    const int bufsize = size_2mbyte;
    const int opt_err = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsize,  sizeof(bufsize));
    if (WARN_ON(opt_err < 0)) {
        return -1;
    }

    struct sockaddr_ll sll;
    struct sockaddr *sa = (struct sockaddr *)&sll;
    const size_t sa_len = sizeof(sll);
    MEMZERO(sll);
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETHER_TYPE_BRCM);
    sll.sll_ifindex = 0;
    const int bind_err = bind(fd, sa, sa_len);
    if (WARN_ON(bind_err < 0)) {
        return -1;
    }

    return 0;
}

static void
osw_plat_bcm_event_init(struct osw_plat_bcm *m)
{
    struct ev_loop *loop = m->loop;
    ev_io *io = &m->event_io;

    const int fd = socket(PF_PACKET, SOCK_RAW, htons(ETHER_TYPE_BRCM));
    if (WARN_ON(fd < 0)) {
        return;
    }

    ev_io_init(io, osw_plat_bcm_event_io_cb, fd, EV_READ);
    io->data = m;

    const int err = osw_plat_bcm_event_init_fd(fd);
    if (err) {
        close(fd);
        return;
    }

    ev_io_start(loop, io);
}

/*
static void
osw_plat_bcm_event_fini(struct osw_plat_bcm *m)
{
    struct ev_loop *loop = vif->m->loop;
    ev_io *io = &m->event_io;
    const int fd = io->fd;

    ev_io_stop(loop, io);
    close(fd);
}
*/

#define util_nl_each_msg(buf, hdr, len) \
    for (hdr = buf; NLMSG_OK(hdr, len); hdr = NLMSG_NEXT(hdr, len))

#define util_nl_each_msg_type(buf, hdr, len, type) \
    util_nl_each_msg(buf, hdr, len) \
        if (hdr->nlmsg_type == type)

#define util_nl_each_attr(hdr, attr, attrlen) \
    for (attr = NLMSG_DATA(hdr) + NLMSG_ALIGN(sizeof(struct ifinfomsg)), \
         attrlen = NLMSG_PAYLOAD(hdr, sizeof(struct ifinfomsg)); \
         RTA_OK(attr, attrlen); \
         attr = RTA_NEXT(attr, attrlen))

#define util_nl_each_attr_type(hdr, attr, attrlen, type) \
    util_nl_each_attr(hdr, attr, attrlen) \
        if (attr->rta_type == type)

#define util_nl_iwe_data(iwe) \
    ((void *)(iwe) + IW_EV_LCP_LEN)

#define util_nl_iwe_payload(iwe) \
    ((iwe)->len - IW_EV_POINT_LEN)

#define util_nl_iwe_next(iwe, iwelen) \
    ( (iwelen) -= (iwe)->len, (void *)(iwe) + (iwe)->len )

#define util_nl_iwe_ok(iwe, iwelen) \
    ((iwelen) >= (iwe)->len && (iwelen) > 0)

#define util_nl_each_iwe(attr, iwe, iwelen) \
    for (iwe = RTA_DATA(attr), \
         iwelen = RTA_PAYLOAD(attr); \
         util_nl_iwe_ok(iwe, iwelen); \
         iwe = util_nl_iwe_next(iwe, iwelen))

#define util_nl_each_iwe_type(attr, iwe, iwelen, type) \
    util_nl_each_iwe(attr, iwe, iwelen) \
        if (iwe->cmd == type)

static void
osw_plat_bcm_nl_stop(struct osw_plat_bcm *m)
{
    ev_io_stop(m->loop, &m->nl_io);
}

static void
osw_plat_bcm_nl_rx(struct osw_plat_bcm *m,
                   const void *data,
                   size_t len)
{
    const struct nlmsghdr *hdr;
    const struct rtattr *attr;
    char ifname[32];
    int attrlen;

    util_nl_each_msg(data, hdr, len)
        if (hdr->nlmsg_type == RTM_NEWLINK ||
            hdr->nlmsg_type == RTM_DELLINK) {

            memset(ifname, 0, sizeof(ifname));

            util_nl_each_attr_type(hdr, attr, attrlen, IFLA_IFNAME)
                memcpy(ifname, RTA_DATA(attr), RTA_PAYLOAD(attr));

            if (strlen(ifname) == 0)
                continue;

            if (bcmwl_is_netdev(ifname)) {
                if (bcmwl_is_phy(ifname)) {
                    osw_plat_bcm_report_phy_changed(m, ifname);
                }
                else {
                    osw_plat_bcm_report_vif_changed(m, ifname);
                }
            }
        }
}

static void
osw_plat_bcm_nl_io_cb(EV_P_ ev_io *io, int events)
{
    struct osw_plat_bcm *m = io->data;
    if (events == EV_READ) {
        const int fd = io->fd;
        char buf[4096];
        ssize_t len = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (len > 0) {
            osw_plat_bcm_nl_rx(m, buf, (size_t)len);
        }
        else {
            switch (errno) {
                case EAGAIN: return;
                case ENOBUFS: return;
                default:
                    LOGE(LOG_PREFIX("nl socket died: errno=%d (%s)",
                                    errno, strerror(errno)));
                    osw_plat_bcm_nl_stop(m);
                    break;
            }
        }
    }
}

static int
osw_plat_bcm_nl_open(void)
{
     const int fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
     const bool failed_to_create_socket = (fd < 0);
     if (WARN_ON(failed_to_create_socket)) return -1;

     struct sockaddr_nl addr;
     MEMZERO(addr);
     addr.nl_family = AF_NETLINK;
     addr.nl_groups = RTMGRP_LINK;
     const int bind_err = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
     const bool failed_to_bind = (bind_err != 0);
     if (WARN_ON(failed_to_bind)) {
        close(fd);
        return -1;
     }

     return fd;
}

static void
osw_plat_bcm_nl_init(struct osw_plat_bcm *m)
{
    const int fd = osw_plat_bcm_nl_open();
    const bool failed_to_open = (fd < 0);
    if (WARN_ON(failed_to_open)) return;

    ev_io_init(&m->nl_io, osw_plat_bcm_nl_io_cb, fd, EV_READ);
    ev_io_start(m->loop, &m->nl_io);
    m->nl_io.data = m;
}

static void
osw_plat_bcm_vif_added_cb(const struct nl_80211_vif *info,
                          void *priv)
{
    struct osw_plat_bcm *m = priv;
    struct nl_80211_sub *sub = m->nl_sub;
    struct osw_plat_bcm_vif *vif = nl_80211_sub_vif_get_priv(sub, info);
    if (vif == NULL) return;

    vif->info = info;
    vif->m = m;

    const char *vif_name = info->name;
    osw_plat_bcm_vif_wl_init(vif_name);
    osw_plat_bcm_vif_wl_init_rrm(vif_name);
}

static void
osw_plat_bcm_vif_removed_cb(const struct nl_80211_vif *info,
                            void *priv)
{
    struct osw_plat_bcm *m = priv;
    struct nl_80211_sub *sub = m->nl_sub;
    struct osw_plat_bcm_vif *vif = nl_80211_sub_vif_get_priv(sub, info);
    if (vif == NULL) return;

    vif->info = NULL;
    vif->m = NULL;
}

static void
osw_plat_bcm_sta_added_cb(const struct nl_80211_sta *info,
                          void *priv)
{
    struct osw_plat_bcm *m = priv;
    struct nl_80211_sub *sub = m->nl_sub;
    struct osw_plat_bcm_sta *sta = nl_80211_sub_sta_get_priv(sub, info);
    if (sta == NULL) return;

    sta->info = info;
    sta->m = m;
}

static void
osw_plat_bcm_sta_removed_cb(const struct nl_80211_sta *info,
                            void *priv)
{
    struct osw_plat_bcm *m = priv;
    struct nl_80211_sub *sub = m->nl_sub;
    struct osw_plat_bcm_sta *sta = nl_80211_sub_sta_get_priv(sub, info);
    if (sta == NULL) return;

    sta->info = NULL;
    sta->m = NULL;
}

static void
osw_plat_bcm_nl_conn_event_cb(struct nl_conn_subscription *sub,
                              struct nl_msg *msg,
                              void *priv)
{
    const uint8_t cmd = genlmsg_hdr(nlmsg_hdr(msg))->cmd;
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    const int err = genlmsg_parse(nlmsg_hdr(msg), 0, tb, NL80211_ATTR_MAX, NULL);
    if (err) return;

    struct osw_plat_bcm *m = priv;
    struct osw_drv_nl80211_ops *nl_ops = m->nl_ops;
    struct nl_80211 *nl = nl_ops->get_nl_80211_fn(nl_ops);
    const struct nl_80211_phy *phy_info = nl_80211_phy_by_nla(nl, tb);
    const struct nl_80211_vif *vif_info = nl_80211_vif_by_nla(nl, tb);
    const char *phy_name = phy_info ? phy_info->name : NULL;
    const char *vif_name = vif_info ? vif_info->name : NULL;

    (void)phy_name;
    (void)vif_name;

    struct nlattr *vendor_id = tb[NL80211_ATTR_VENDOR_ID];
    struct nlattr *vendor_subcmd = tb[NL80211_ATTR_VENDOR_SUBCMD];
    struct nlattr *vendor_data = tb[NL80211_ATTR_VENDOR_DATA];

    (void)cmd;
    (void)vendor_id;
    (void)vendor_subcmd;
    (void)vendor_data;
}

static void
osw_plat_bcm_fix_phy_txchain(const char *phy_name,
                             struct osw_drv_phy_state *state)
{
    const char *buf = WL(phy_name, "txchain");
    if (WARN_ON(buf == NULL)) return;
    state->tx_chainmask = atoi(buf);
}

static void
osw_plat_bcm_fix_phy_regulatory(const char *phy_name,
                                struct osw_drv_phy_state *state)
{
    struct osw_reg_domain *rd = &state->reg_domain;
    const char *buf = WL(phy_name, "country");
    if (WARN_ON(buf == NULL)) return;
    if (WARN_ON(strlen(buf) < 2)) return;

    rd->ccode[0] = buf[0];
    rd->ccode[1] = buf[1];
    rd->ccode[2] = '\0';
}

static uint16_t
osw_plat_bcm_into_chanspec_band(const enum osw_band band)
{
    switch (band) {
        case OSW_BAND_UNDEFINED: break;
        case OSW_BAND_2GHZ: return WL_CHANSPEC_BAND_2G;
        case OSW_BAND_5GHZ: return WL_CHANSPEC_BAND_5G;
        case OSW_BAND_6GHZ:
#ifdef WL_CHANSPEC_BAND_6G
            return WL_CHANSPEC_BAND_6G;
#else
            break;
#endif
    }
    WARN_ON(1);
    return 0;
}

static uint16_t
osw_plat_bcm_into_chanspec_width(const enum osw_channel_width width)
{
    switch (width) {
        case OSW_CHANNEL_20MHZ: return WL_CHANSPEC_BW_20;
        case OSW_CHANNEL_40MHZ: return WL_CHANSPEC_BW_40;
        case OSW_CHANNEL_80MHZ: return WL_CHANSPEC_BW_80;
        case OSW_CHANNEL_160MHZ: return WL_CHANSPEC_BW_160;
        case OSW_CHANNEL_80P80MHZ: break;
        case OSW_CHANNEL_320MHZ: break;
    }
    WARN_ON(1);
    return 0;
}

static uint16_t
osw_plat_bcm_into_chanspec_sb(const enum osw_channel_width width,
                              const int primary,
                              const int center)
{
    switch (width) {
        case OSW_CHANNEL_20MHZ:
                 return WL_CHANSPEC_CTL_SB_NONE;
        case OSW_CHANNEL_40MHZ:
             if (center > primary) return WL_CHANSPEC_CTL_SB_L;
             if (primary > center) return WL_CHANSPEC_CTL_SB_U;
             break;
        case OSW_CHANNEL_80MHZ:
             if (center > primary) {
                 const int center40 = center - 4;
                 if (center40 > primary) return WL_CHANSPEC_CTL_SB_LL;
                 if (primary > center40) return WL_CHANSPEC_CTL_SB_LU;
             }
             if (primary > center) {
                 const int center40 = center + 4;
                 if (center40 > primary) return WL_CHANSPEC_CTL_SB_UL;
                 if (primary > center40) return WL_CHANSPEC_CTL_SB_UU;
             }
             break;
        case OSW_CHANNEL_160MHZ:
             if (center > primary) {
                 const int center80 = center - 8;
                 if (center80 > primary) {
                    const int center40 = center80 - 4;
                    if (center40 > primary) return WL_CHANSPEC_CTL_SB_LLL;
                    if (primary > center40) return WL_CHANSPEC_CTL_SB_LLU;
                 }
                 if (primary > center80) {
                    const int center40 = center80 + 4;
                    if (center40 > primary) return WL_CHANSPEC_CTL_SB_LUL;
                    if (primary > center40) return WL_CHANSPEC_CTL_SB_LUU;
                 }
             }
             if (primary > center) {
                 const int center80 = center + 8;
                 if (center80 > primary) {
                    const int center40 = center80 - 4;
                    if (center40 > primary) return WL_CHANSPEC_CTL_SB_ULL;
                    if (primary > center40) return WL_CHANSPEC_CTL_SB_ULU;
                 }
                 if (primary > center80) {
                    const int center40 = center80 + 4;
                    if (center40 > primary) return WL_CHANSPEC_CTL_SB_UUL;
                    if (primary > center40) return WL_CHANSPEC_CTL_SB_UUU;
                 }
             }
            break;
        case OSW_CHANNEL_80P80MHZ:
            break;
        case OSW_CHANNEL_320MHZ:
            break;
    }
    WARN_ON(1);
    return 0;
}

static uint16_t
osw_plat_bcm_into_chanspec(const struct osw_channel *c)
{
    const int freq = c->control_freq_mhz;
    const int primary = osw_freq_to_chan(c->control_freq_mhz);
    const int center = osw_freq_to_chan(c->center_freq0_mhz);
    const enum osw_band band = osw_freq_to_band(freq);
    const enum osw_channel_width width = c->width;
    WARN_ON(center == 0 && width != OSW_CHANNEL_20MHZ);
    const uint16_t cs_band = osw_plat_bcm_into_chanspec_band(band);
    const uint16_t cs_width = osw_plat_bcm_into_chanspec_width(width);
    const uint16_t cs_sb = osw_plat_bcm_into_chanspec_sb(width, primary, center);
    const uint16_t cs_chan = center ? center : primary;
    const uint16_t cs = cs_band
                      | cs_width
                      | cs_sb
                      | cs_chan;
    return cs;
}

static enum osw_channel_state_dfs
osw_plat_bcm_into_dfs_state(const uint32_t chan_info,
                            const wl_dfs_sub_status_t *sub)
{
    const bool is_radar = (chan_info & WL_CHAN_RADAR);
    const bool is_passive = (chan_info & WL_CHAN_PASSIVE);
    const bool is_inactive = (chan_info & WL_CHAN_INACTIVE);

    if (is_radar) {
        if (is_inactive) {
            return OSW_CHANNEL_DFS_NOL;
        }
        if (is_passive) {
            if (sub != NULL) {
                switch (sub->state) {
                    case WL_DFS_CACSTATE_IDLE: break;
                    case WL_DFS_CACSTATE_PREISM_CAC: return OSW_CHANNEL_DFS_CAC_IN_PROGRESS;
                    case WL_DFS_CACSTATE_ISM: break;
                    case WL_DFS_CACSTATE_CSA: break;
                    case WL_DFS_CACSTATE_POSTISM_CAC: break;
                    case WL_DFS_CACSTATE_PREISM_OOC: break;
                    case WL_DFS_CACSTATE_POSTISM_OOC: break;
                    case WL_DFS_CACSTATE_ABORT_CAC: break;
                }
            }
            return OSW_CHANNEL_DFS_CAC_POSSIBLE;
        }
        else {
            return OSW_CHANNEL_DFS_CAC_COMPLETED;
        }
    }
    else {
        return OSW_CHANNEL_NON_DFS;
    }
}

static void
osw_plat_bcm_byteswap_wl_dfs_status_all(const struct bcmwl_ioctl_num_conv *conv,
                                        wl_dfs_status_all_t *all)
{
    all->version = conv->dtoh16(all->version);
    all->num_sub_status = conv->dtoh16(all->num_sub_status);

    size_t i;
    for (i = 0; i < all->num_sub_status; i++) {
        wl_dfs_sub_status_t *sub = &all->dfs_sub_status[i];
        sub->state = conv->dtoh32(sub->state);
        sub->duration = conv->dtoh32(sub->duration);
        sub->chanspec = conv->dtoh32(sub->chanspec);
        sub->chanspec_last_cleared = conv->dtoh32(sub->chanspec_last_cleared);
        sub->sub_type = conv->dtoh16(sub->sub_type);
    }
}

static void
osw_plat_bcm_fix_phy_dfs(const char *phy_name,
                         struct osw_drv_phy_state *state)
{
    const struct bcmwl_ioctl_num_conv *conv = bcmwl_ioctl_lookup_num_conv(phy_name);
    if (WARN_ON(conv == NULL)) return;

    union {
        wl_dfs_status_all_t all;
        char buf[WLC_IOCTL_MAXLEN];
    } dfs;
    MEMZERO(dfs);
    const bool dfs_status_ok = bcmwl_GIOV(phy_name, "dfs_status_all", NULL, &dfs);
    if (dfs_status_ok == false) return;
    osw_plat_bcm_byteswap_wl_dfs_status_all(conv, &dfs.all);

    const size_t n_cs = state->n_channel_states;
    size_t i;
    for (i = 0; i < n_cs; i++) {
        struct osw_channel_state *cs = &state->channel_states[i];
        const struct osw_channel *c = &cs->channel;
        const int freq = c->control_freq_mhz;
        const int chan = osw_freq_to_chan(freq);
        const uint32_t chanspec = osw_plat_bcm_into_chanspec(c);
        const uint32_t in = conv->dtoh32(chanspec);
        uint32_t out;

        const bool ok = bcmwl_GIOV(phy_name, "per_chan_info", &in, &out);
        const bool failed = !ok;
        if (WARN_ON(failed)) continue;

        const uint32_t info = conv->dtoh32(out);
        const uint32_t minutes = (info >> 24) & 0xff;
        const int nol_rem_seconds = minutes * 60;

        const bool not_valid_hw = ((info & WL_CHAN_VALID_HW) == false);
        const bool not_valid_sw = ((info & WL_CHAN_VALID_SW) == false);
        const bool not_valid = not_valid_hw || not_valid_sw;
        if (WARN_ON(not_valid)) continue;

        enum osw_channel_state_dfs state = osw_plat_bcm_into_dfs_state(info, NULL);

        size_t j;
        for (j = 0; j < dfs.all.num_sub_status; j++) {
            const wl_dfs_sub_status_t *sub = &dfs.all.dfs_sub_status[j];
            int each_20mhz_chan;

            OSW_PLAT_BCM_CHSPEC_FOREACH_SBC(each_20mhz_chan, sub->chanspec) {
                if (each_20mhz_chan == chan) {
                    state = osw_plat_bcm_into_dfs_state(info, sub);
                }
            }
        }

        if (cs->dfs_state != state) {
            LOGT(LOG_PREFIX_PHY(phy_name, "dfs: "OSW_CHANNEL_FMT" state: %s -> %s",
                                OSW_CHANNEL_ARG(c),
                                osw_channel_dfs_state_to_str(cs->dfs_state),
                                osw_channel_dfs_state_to_str(state)));
            cs->dfs_state = state;
        }

        if (cs->dfs_nol_remaining_seconds != nol_rem_seconds) {
            LOGT(LOG_PREFIX_PHY(phy_name, "dfs: "OSW_CHANNEL_FMT" nol remaining seconds: %d -> %d",
                                OSW_CHANNEL_ARG(c),
                                cs->dfs_nol_remaining_seconds,
                                nol_rem_seconds));
            cs->dfs_nol_remaining_seconds = nol_rem_seconds;
        }
    }
}

static void
osw_plat_bcm_fix_phy_radar(const char *phy_name,
                           struct osw_drv_phy_state *state)
{
    const char *radar = WL(phy_name, "radar");
    state->radar = (radar == NULL)
                 ? OSW_RADAR_UNSUPPORTED
                 : (atoi(radar) == 0
                   ? OSW_RADAR_DETECT_DISABLED
                   : OSW_RADAR_DETECT_ENABLED);
}

static void
osw_plat_bcm_fix_phy_state_cb(struct osw_drv_nl80211_hook *hook,
                              const char *phy_name,
                              struct osw_drv_phy_state *state,
                              void *priv)
{
    osw_plat_bcm_fix_phy_txchain(phy_name, state);
    osw_plat_bcm_fix_phy_regulatory(phy_name, state);
    osw_plat_bcm_fix_phy_dfs(phy_name, state);
    osw_plat_bcm_fix_phy_radar(phy_name, state);
}

static void
osw_plat_bcm_fix_vif_ap_enabled(const char *phy_name,
                                const char *vif_name,
                                struct osw_drv_vif_state *state)
{
    const char *buf = WL(vif_name, "bss");
    if (WARN_ON(buf == NULL)) return;
    const bool is_up = (strcmp(buf, "up") == 0);
    const enum osw_vif_status status = is_up
                                     ? OSW_VIF_ENABLED
                                     : OSW_VIF_DISABLED;
    osw_vif_status_set(&state->status, status);
}

static void
osw_plat_bcm_fix_vif_ap_mcast2ucast(const char *phy_name,
                                    const char *vif_name,
                                    struct osw_drv_vif_state *state)
{
    const bool is_dhd = bcmwl_radio_is_dhd(phy_name);
    const char *buf = is_dhd
                    ? DHD(vif_name, "wmf_bss_enable")
                    : WL(vif_name, "wmf_bss_enable");
    if (WARN_ON(buf == NULL)) return;
    const int arg = atoi(buf);
    const bool in_range = (arg == 0 || arg == 1);
    const bool not_in_range = !in_range;

    WARN_ON(not_in_range);
    state->u.ap.mcast2ucast = arg ? true : false;
}

static void
osw_plat_bcm_fix_vif_ap_acl(const char *phy_name,
                            const char *vif_name,
                            struct osw_drv_vif_state *state)
{
    struct osw_hwaddr_list *acl = &state->u.ap.acl;

    char *buf = WL(vif_name, "mac");
    if (WARN_ON(acl == NULL)) return;

    const char *word;
    while ((word = strsep(&buf, " \r\n")) != NULL) {
        struct osw_hwaddr mac;
        const bool valid = osw_hwaddr_from_cstr(word, &mac);
        if (valid) {
            const size_t i = acl->count;
            acl->count++;
            const size_t new_size = (acl->count * sizeof(*acl->list));
            acl->list = REALLOC(acl->list, new_size);
            acl->list[i] = mac;
        }
    }
}

static void
osw_plat_bcm_fix_vif_ap_acl_policy(const char *phy_name,
                                   const char *vif_name,
                                   struct osw_drv_vif_state *state)
{
    enum osw_acl_policy *policy = &state->u.ap.acl_policy;

    const char *buf = WL(vif_name, "macmode");
    if (WARN_ON(buf == NULL)) return;

    switch (atoi(buf)) {
        case 0:
            *policy = OSW_ACL_NONE;
            break;
        case 1:
            *policy = OSW_ACL_DENY_LIST;
            break;
        case 2:
            *policy = OSW_ACL_ALLOW_LIST;
            break;
        default:
            WARN_ON(1);
            break;
    }
}

static void
osw_plat_bcm_fix_vif_ap_mode(const char *phy_name,
                             const char *vif_name,
                             struct osw_drv_vif_state *state)
{
    struct osw_ap_mode *mode = &state->u.ap.mode;

    mode->ht_enabled = (atoi(WL(vif_name, "nmode") ?: "0") != 0);
    mode->vht_enabled = (atoi(WL(vif_name, "vhtmode") ?: "0") != 0);
    mode->he_enabled = (atoi(WL(vif_name, "he", "enab") ?: "0") != 0);
}

static void
osw_plat_bcm_cs_into_osw(long cs, struct osw_channel *c)
{
    const int bw_mhz = bcmwl_chanspec_get_bw_mhz(cs);
    const int center_freq = bcmwl_chanspec_get_center_freq(cs);
    const int primary_chan = bcmwl_chanspec_get_primary(cs);

    switch (bw_mhz) {
        case 20:
            c->width = OSW_CHANNEL_20MHZ;
            break;
        case 40:
            c->width = OSW_CHANNEL_40MHZ;
            break;
        case 80:
            c->width = OSW_CHANNEL_80MHZ;
            break;
        case 160:
            c->width = OSW_CHANNEL_160MHZ;
            break;
    }

    c->center_freq0_mhz = center_freq;

    const enum osw_band band = osw_freq_to_band(center_freq);
    const int primary_freq = osw_chan_to_freq(band, primary_chan);
    c->control_freq_mhz = primary_freq;
}

static long
osw_plat_bcm_cs_from_buf(const char *buf)
{
    if (WARN_ON(buf == NULL)) return 0;

    buf = strstr(buf, "(");
    if (WARN_ON(buf == NULL)) return 0;
    buf++;

    return strtol(buf, NULL, 16);
}

static void
osw_plat_bcm_fix_vif_channel(const char *phy_name,
                             const char *vif_name,
                             struct osw_channel *c)
{
    const char *buf = WL(vif_name, "chanspec");
    const long cs = osw_plat_bcm_cs_from_buf(buf);
    osw_plat_bcm_cs_into_osw(cs, c);
}

static void
osw_plat_bcm_fix_vif_ap_neigh(const char *phy_name,
                              const char *vif_name,
                              struct osw_drv_vif_state *state)
{
    struct osw_drv_vif_state_ap *ap = &state->u.ap;

    if (atoi(WL(vif_name, "rrm_nbr_static_disabled") ?: "0") == 1) {
        return;
    }

    FREE(ap->neigh_list.list);
    ap->neigh_list.list = NULL;
    ap->neigh_list.count = 0;
}

static void
osw_plat_bcm_fix_vif_ap_multi_ap(const char *phy_name,
                                 const char *vif_name,
                                 struct osw_drv_vif_state *state)
{
    struct osw_drv_vif_state_ap *ap = &state->u.ap;

    const char *map_str = WL(vif_name, "map");
    if (WARN_ON(map_str == NULL)) return;
    const int val = atoi(map_str);

    osw_plat_bcm_map_to_osw_ap(val, &ap->multi_ap);
}

static void
osw_plat_bcm_fix_vif_sta_multi_ap_networks(const char *phy_name,
                                           const char *vif_name,
                                           struct osw_drv_vif_state *state)
{
    struct osw_drv_vif_state_sta *sta = &state->u.sta;
    struct osw_drv_vif_sta_network *net = sta->network;

    /* micro-optimization to avoid iovar call */
    const bool no_networks_to_fixup = (net == NULL);
    if (no_networks_to_fixup) return;

    const int val = atoi(WL(vif_name, "map") ?: "0");
    const bool multi_ap = osw_plat_bcm_map_to_osw_sta(val);
    while (net != NULL) {
        net->multi_ap = multi_ap;
        net = net->next;
    }
}

static void
osw_plat_bcm_fix_vif_sta_multi_ap_link(const char *phy_name,
                                       const char *vif_name,
                                       struct osw_drv_vif_state *state)
{
    struct osw_drv_vif_state_sta *sta = &state->u.sta;

    switch (sta->link.status) {
        case OSW_DRV_VIF_STATE_STA_LINK_CONNECTED:
            {
                os_macaddr_t hwaddr;
                memcpy(hwaddr.addr, sta->link.bssid.octet, sizeof(hwaddr.addr));
                bcmwl_sta_info_t info = {0};
                const bool info_is_valid = bcmwl_sta_get_sta_info(vif_name, &hwaddr, &info);
                if (info_is_valid) {
                    sta->link.multi_ap = info.multi_ap;
                }
            }
            break;
        case OSW_DRV_VIF_STATE_STA_LINK_UNKNOWN:
        case OSW_DRV_VIF_STATE_STA_LINK_CONNECTING:
        case OSW_DRV_VIF_STATE_STA_LINK_DISCONNECTED:
            break;
    }
}

static void
osw_plat_bcm_fix_vif_sta_multi_ap(const char *phy_name,
                                  const char *vif_name,
                                  struct osw_drv_vif_state *state)
{
    osw_plat_bcm_fix_vif_sta_multi_ap_networks(phy_name, vif_name, state);
    osw_plat_bcm_fix_vif_sta_multi_ap_link(phy_name, vif_name, state);
}

static void
osw_plat_bcm_fix_vif_ap_state(const char *phy_name,
                              const char *vif_name,
                              struct osw_drv_vif_state *state)
{
    struct osw_drv_vif_state_ap *ap = &state->u.ap;

    (void)phy_name;
    (void)vif_name;
    (void)ap;

    osw_plat_bcm_fix_vif_channel(phy_name, vif_name, &state->u.ap.channel);
    osw_plat_bcm_fix_vif_ap_enabled(phy_name, vif_name, state);
    osw_plat_bcm_fix_vif_ap_mcast2ucast(phy_name, vif_name, state);
    osw_plat_bcm_fix_vif_ap_acl(phy_name, vif_name, state);
    osw_plat_bcm_fix_vif_ap_acl_policy(phy_name, vif_name, state);
    osw_plat_bcm_fix_vif_ap_mode(phy_name, vif_name, state);
    osw_plat_bcm_fix_vif_ap_neigh(phy_name, vif_name, state);
    osw_plat_bcm_fix_vif_ap_multi_ap(phy_name, vif_name, state);

    ap->mode.wnm_bss_trans = strtol(WL(vif_name, "wnm") ?: "0", NULL, 16) & OSW_PLAT_BCM_BTM_BIT;
    ap->mode.rrm_neighbor_report = strtol(WL(vif_name, "rrm") ?: "0", NULL, 16) & OSW_PLAT_BCM_RRM_BIT;
}

static void
osw_plat_bcm_fix_vif_ap_vlan_addrs(const char *phy_name,
                                   const char *vif_name,
                                   struct osw_drv_vif_state *state)
{
    const char *sta_addr_str = WL(vif_name, "wds_remote_mac");
    if (sta_addr_str == NULL) return;

    struct osw_hwaddr sta_addr;
    const bool mac_is_not_valid = (osw_hwaddr_from_cstr(sta_addr_str, &sta_addr) == false);
    if (mac_is_not_valid) return;

    struct osw_drv_vif_state_ap_vlan *ap_vlan = &state->u.ap_vlan;
    osw_hwaddr_list_append(&ap_vlan->sta_addrs, &sta_addr);
}

static void
osw_plat_bcm_fix_vif_ap_vlan_state(const char *phy_name,
                                   const char *vif_name,
                                   struct osw_drv_vif_state *state)
{
    osw_plat_bcm_fix_vif_ap_vlan_addrs(phy_name, vif_name, state);
}

static void
osw_plat_bcm_fix_vif_sta_state(const char *phy_name,
                               const char *vif_name,
                               struct osw_drv_vif_state *state)
{
    osw_plat_bcm_fix_vif_channel(phy_name, vif_name, &state->u.sta.link.channel);
    osw_plat_bcm_fix_vif_sta_multi_ap(phy_name, vif_name, state);
}

static void
osw_plat_bcm_fix_vif_state_cb(struct osw_drv_nl80211_hook *hook,
                              const char *phy_name,
                              const char *vif_name,
                              struct osw_drv_vif_state *state,
                              void *priv)
{
    switch (state->vif_type) {
        case OSW_VIF_AP:
            osw_plat_bcm_fix_vif_ap_state(phy_name, vif_name, state);
            break;
        case OSW_VIF_AP_VLAN:
            osw_plat_bcm_fix_vif_ap_vlan_state(phy_name, vif_name, state);
            break;
        case OSW_VIF_STA:
            osw_plat_bcm_fix_vif_sta_state(phy_name, vif_name, state);
            break;
        case OSW_VIF_UNDEFINED:
            break;
    }
}

static void
osw_plat_bcm_init_wl(void)
{
    bcmwl_vap_prealloc_all();

    bcmwl_event_enable_all(WLC_E_ACTION_FRAME);
    bcmwl_event_enable_all(WLC_E_AP_CHAN_CHANGE);
    bcmwl_event_enable_all(WLC_E_AP_STARTED);
    bcmwl_event_enable_all(WLC_E_ASSOC);
    bcmwl_event_enable_all(WLC_E_ASSOC_IND);
    bcmwl_event_enable_all(WLC_E_AUTH);
    bcmwl_event_enable_all(WLC_E_AUTHORIZED);
    bcmwl_event_enable_all(WLC_E_AUTH_IND);
    bcmwl_event_enable_all(WLC_E_CAC_STATE_CHANGE);
    bcmwl_event_enable_all(WLC_E_CSA_COMPLETE_IND);
    bcmwl_event_enable_all(WLC_E_CSA_DONE_IND);
    bcmwl_event_enable_all(WLC_E_CSA_FAILURE_IND);
    bcmwl_event_enable_all(WLC_E_CSA_RECV_IND);
    bcmwl_event_enable_all(WLC_E_CSA_START_IND);
    bcmwl_event_enable_all(WLC_E_DEAUTH);
    bcmwl_event_enable_all(WLC_E_DEAUTH_IND);
    bcmwl_event_enable_all(WLC_E_DFS_AP_RESUME);
    bcmwl_event_enable_all(WLC_E_DFS_AP_STOP);
    bcmwl_event_enable_all(WLC_E_DFS_HIT);
    bcmwl_event_enable_all(WLC_E_DISASSOC);
    bcmwl_event_enable_all(WLC_E_DISASSOC_IND);
    bcmwl_event_enable_all(WLC_E_EAPOL_MSG);
    bcmwl_event_enable_all(WLC_E_ESCAN_RESULT);
    bcmwl_event_enable_all(WLC_E_IF);
    bcmwl_event_enable_all(WLC_E_JOIN);
    bcmwl_event_enable_all(WLC_E_LINK);
    bcmwl_event_enable_all(WLC_E_PROBREQ_MSG);
    bcmwl_event_enable_all(WLC_E_PROBREQ_MSG_RX);
    bcmwl_event_enable_all(WLC_E_PRUNE);
    bcmwl_event_enable_all(WLC_E_RADAR_DETECTED);
    bcmwl_event_enable_all(WLC_E_RADIO);
    bcmwl_event_enable_all(WLC_E_REASSOC_IND);
    bcmwl_event_enable_all(WLC_E_SCAN_COMPLETE);
    bcmwl_event_enable_all(WLC_E_SET_SSID);
}

static void
osw_plat_bcm_start(struct osw_plat_bcm *m)
{
    if (osw_plat_bcm_is_disabled()) return;

    static const struct osw_drv_nl80211_hook_ops nl_hook_ops = {
        .fix_phy_state_fn = osw_plat_bcm_fix_phy_state_cb,
        .fix_vif_state_fn = osw_plat_bcm_fix_vif_state_cb,
        .pre_request_config_fn = osw_plat_bcm_pre_request_config_cb,
        .pre_request_stats_fn = osw_plat_bcm_pre_request_stats_cb,
        .get_vif_list_fn = osw_plat_bcm_get_vif_list_cb,
        .get_vif_state_fn = osw_plat_bcm_get_vif_state_cb,
    };

    static const struct nl_80211_sub_ops nl_sub_ops = {
        .phy_added_fn = osw_plat_bcm_phy_added_cb,
        .phy_renamed_fn = osw_plat_bcm_phy_renamed_cb,
        .phy_removed_fn = osw_plat_bcm_phy_removed_cb,
        .vif_added_fn = osw_plat_bcm_vif_added_cb,
        .vif_removed_fn = osw_plat_bcm_vif_removed_cb,
        .sta_added_fn = osw_plat_bcm_sta_added_cb,
        .sta_removed_fn = osw_plat_bcm_sta_removed_cb,
        .priv_phy_size = sizeof(struct osw_plat_bcm_phy),
        .priv_vif_size = sizeof(struct osw_plat_bcm_vif),
        .priv_sta_size = sizeof(struct osw_plat_bcm_sta),
    };

    static const struct osw_hostap_hook_ops hapd_hook_ops = {
        .ap_conf_mutate_fn = osw_plat_bcm_ap_conf_mutate_cb,
        .sta_conf_mutate_fn = osw_plat_bcm_sta_conf_mutate_cb,
    };

    m->loop = OSW_MODULE_LOAD(osw_ev);
    if (m->loop == NULL) return;

    osw_plat_bcm_init_wl();

    m->nl_ops = OSW_MODULE_LOAD(osw_drv_nl80211);
    if (m->nl_ops == NULL) return;

    m->nl_hook = m->nl_ops->add_hook_ops_fn(m->nl_ops, &nl_hook_ops, m);
    if (WARN_ON(m->nl_hook == NULL)) return;

    struct osw_drv_nl80211_ops *nl_ops = m->nl_ops;
    struct nl_80211 *nl = nl_ops->get_nl_80211_fn(nl_ops);
    m->nl_sub = nl_80211_alloc_sub(nl, &nl_sub_ops, m);
    if (WARN_ON(m->nl_sub == NULL)) return;

    m->nl_conn = nl_80211_get_conn(nl);
    m->nl_conn_sub = nl_conn_subscription_alloc();
    if (WARN_ON(m->nl_conn_sub == NULL)) return;
    nl_conn_subscription_set_event_fn(m->nl_conn_sub, osw_plat_bcm_nl_conn_event_cb, m);
    nl_conn_subscription_start(m->nl_conn_sub, m->nl_conn);

    m->hostap = OSW_MODULE_LOAD(osw_hostap);
    m->hostap_hook = osw_hostap_hook_alloc(m->hostap, &hapd_hook_ops, m);
    if (WARN_ON(m->hostap_hook == NULL)) return;

    osw_plat_bcm_event_init(m);
    osw_plat_bcm_nl_init(m);

    osw_state_register_observer(&m->state_obs);
}

static struct osw_plat_bcm g_osw_plat_bcm;

OSW_MODULE(osw_plat_bcm)
{
    struct osw_plat_bcm *m = &g_osw_plat_bcm;
    osw_plat_bcm_init(m);
    osw_plat_bcm_start(m);
    return m;
}

OSW_UT(osw_plat_bcm_chanspec)
{
    const struct osw_channel c1ht20 = {
        .control_freq_mhz = 2412,
        .center_freq0_mhz = 2412,
        .width = OSW_CHANNEL_20MHZ,
    };
    const uint16_t cs1ht20 = 0x1001;
    const struct osw_channel c1ht40plus = {
        .control_freq_mhz = 2412,
        .center_freq0_mhz = 2422,
        .width = OSW_CHANNEL_40MHZ,
    };
    const uint16_t cs1ht40plus = 0x1803;
    const struct osw_channel c5ht40minus = {
        .control_freq_mhz = 2432,
        .center_freq0_mhz = 2422,
        .width = OSW_CHANNEL_40MHZ,
    };
    const uint16_t cs5ht40minus = 0x1903;
    const struct osw_channel c36ht40 = {
        .control_freq_mhz = 5180,
        .center_freq0_mhz = 5190,
        .width = OSW_CHANNEL_40MHZ,
    };
    const uint16_t cs36ht40 = 0xd826;
    const struct osw_channel c52ht160 = {
        .control_freq_mhz = 5260,
        .center_freq0_mhz = 5250,
        .width = OSW_CHANNEL_160MHZ,
    };
    const uint16_t cs52ht160 = 0xec32;

    assert(osw_plat_bcm_into_chanspec(&c1ht20) == cs1ht20);
    assert(osw_plat_bcm_into_chanspec(&c1ht40plus) == cs1ht40plus);
    assert(osw_plat_bcm_into_chanspec(&c5ht40minus) == cs5ht40minus);
    assert(osw_plat_bcm_into_chanspec(&c36ht40) == cs36ht40);
    assert(osw_plat_bcm_into_chanspec(&c52ht160) == cs52ht160);
}
