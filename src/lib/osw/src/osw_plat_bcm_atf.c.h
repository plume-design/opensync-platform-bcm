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

#include <log.h>
#include <osw_conf.h>
#include <osw_drv.h>
#include <osw_etc.h>
#include <osw_module.h>
#include <osw_state.h>
#include <osw_types.h>
#include <stdlib.h>
#include <util.h>

/**
 * Airtime Fairness module
 *
 * This module handles configuring airtime fairness in BCM driver.
 * It translates OSW priority per VIF to wl's scheduler per station.
 *
 * It observes station connections and it executes correct wl commands to set
 * right scheduler for each connected station. Schedulers are used instead of
 * priorities because of their different consequence. BCM driver schedulers
 * work in a way that higher priority scheduler is a queue which is being
 * emptied first. That way, station with lower priority isn't served later,
 * it's being served less, which was the goal.
 *
 * wl command usage:
 *
 * wl taf <sta_mac> <scheduler> <precedence>
 *
 * Schedulers in BCM driver:
 * - ebos (0) - the first queue to empty
 * - atos (2) - default priority, precedence configuration regards this scheduler
 * - atos2 (3) - when atos is empty, this one is used
 *
 * This component "offloads" airtime precedence configuration. This means that
 * setter configures the driver, but getter returns the configured value
 *
 * There's no need for sta_disconnected_fn because when station disconnects,
 * its entry is removed from wl records. No need to deconfigure. When it
 * reconnects on any vif, sta_connected_fn occurs, so it's being configured.
 */

#define OSW_PLAT_BCM_ATF_ENABLED_DEFAULT true
#define LOG_PREFIX_ATF(fmt, ...) LOG_PREFIX("atf: " fmt, ##__VA_ARGS__)
#define LOG_PREFIX_ATF_VIF(vif_name, fmt, ...) LOG_PREFIX_ATF("%s: " fmt, vif_name, ##__VA_ARGS__)

#define OSW_PLAT_BCM_ATF_EBOS_SCHEDULER 0
#define OSW_PLAT_BCM_ATF_ATOS_SCHEDULER 2
#define OSW_PLAT_BCM_ATF_ATOS2_SCHEDULER 3

#define OSW_PLAT_BCM_ATF_EBOS_PRIORITY 1
#define OSW_PLAT_BCM_ATF_ATOS_PRIORITY 0
#define OSW_PLAT_BCM_ATF_ATOS2_PRIORITY 0

struct osw_plat_bcm_atf
{
    ds_tree_t phys;
    struct osw_state_observer state_obs;
};

struct osw_plat_bcm_atf_phy
{
    ds_tree_node_t node;
    ds_tree_t vifs;
    char *phy_name;
    struct osw_plat_bcm_atf *m;
};

struct osw_plat_bcm_atf_vif
{
    ds_tree_node_t node;
    char *vif_name;
    enum osw_airtime_precedence precedence;
    struct osw_plat_bcm_atf_phy *phy;
};

static struct osw_plat_bcm_atf_vif *osw_plat_bcm_atf_vif_alloc(const char *vif_name, struct osw_plat_bcm_atf_phy *phy)
{
    struct osw_plat_bcm_atf_vif *vif = CALLOC(1, sizeof(*vif));
    vif->vif_name = STRDUP(vif_name);
    vif->precedence = OSW_AIRTIME_PRECEDENCE_DISABLED;
    vif->phy = phy;
    ds_tree_insert(&phy->vifs, vif, vif->vif_name);
    LOGI(LOG_PREFIX_ATF_VIF(vif_name, "added to atf tracking"));
    return vif;
}

static void osw_plat_bcm_atf_vif_free(struct osw_plat_bcm_atf_vif *vif)
{
    LOGI(LOG_PREFIX_ATF_VIF(vif->vif_name, "removed from atf tracking"));
    ds_tree_remove(&vif->phy->vifs, vif);
    FREE(vif->vif_name);
    FREE(vif);
}

static struct osw_plat_bcm_atf_phy *osw_plat_bcm_atf_phy_alloc(const char *phy_name, struct osw_plat_bcm_atf *m)
{
    struct osw_plat_bcm_atf_phy *phy = CALLOC(1, sizeof(*phy));
    phy->phy_name = STRDUP(phy_name);
    phy->m = m;
    ds_tree_init(&phy->vifs, ds_str_cmp, struct osw_plat_bcm_atf_vif, node);
    ds_tree_insert(&m->phys, phy, phy->phy_name);
    LOGI(LOG_PREFIX_ATF("%s: allocated", phy_name));
    return phy;
}

static void osw_plat_bcm_atf_phy_drop_vifs(struct osw_plat_bcm_atf_phy *phy)
{
    struct osw_plat_bcm_atf_vif *vif;
    while ((vif = ds_tree_head(&phy->vifs)) != NULL)
    {
        osw_plat_bcm_atf_vif_free(vif);
    }
}

static void osw_plat_bcm_atf_phy_free(struct osw_plat_bcm_atf_phy *phy)
{
    LOGI(LOG_PREFIX_ATF("%s: dropped", phy->phy_name));
    ds_tree_remove(&phy->m->phys, phy);
    osw_plat_bcm_atf_phy_drop_vifs(phy);
    FREE(phy->phy_name);
    FREE(phy);
}

static void osw_plat_bcm_atf_register_observer(struct osw_plat_bcm_atf *m)
{
    osw_state_register_observer(&m->state_obs);
}
static void osw_plat_bcm_atf_unregister_observer(struct osw_plat_bcm_atf *m)
{
    osw_state_unregister_observer(&m->state_obs);
}

static void osw_plat_bcm_atf_reload(struct osw_plat_bcm_atf *m)
{
    // this is called even when precedence is configured on the interface
    // that doesn't have any sta connected
    osw_plat_bcm_atf_unregister_observer(m);
    osw_plat_bcm_atf_register_observer(m);
}

static void osw_plat_bcm_atf_set_vif_precedence(
        struct osw_plat_bcm_atf *m,
        const char *phy_name,
        const char *vif_name,
        const enum osw_airtime_precedence precedence)
{
    struct osw_plat_bcm_atf_phy *phy = ds_tree_find(&m->phys, phy_name);
    if (phy == NULL) return;

    struct osw_plat_bcm_atf_vif *vif = ds_tree_find(&phy->vifs, vif_name);
    if (vif == NULL)
    {
        vif = osw_plat_bcm_atf_vif_alloc(vif_name, phy);
    }

    LOGT(LOG_PREFIX_ATF_VIF(vif_name, "set precedence %s", osw_airtime_precedence_to_str(precedence)));
    vif->precedence = precedence;

    osw_plat_bcm_atf_reload(m);
}

static enum osw_airtime_precedence osw_plat_bcm_atf_get_vif_precedence(
        struct osw_plat_bcm_atf *m,
        const char *phy_name,
        const char *vif_name)
{
    struct osw_plat_bcm_atf_phy *phy = ds_tree_find(&m->phys, phy_name);
    if (phy != NULL)
    {
        struct osw_plat_bcm_atf_vif *vif = ds_tree_find(&phy->vifs, vif_name);
        if (vif != NULL)
        {
            LOGT(LOG_PREFIX_ATF_VIF(vif_name, "precedence: %s", osw_airtime_precedence_to_str(vif->precedence)));
            return vif->precedence;
        }
    }

    return OSW_AIRTIME_PRECEDENCE_DISABLED;
}

static int osw_plat_bcm_atf_get_wl_scheduler(struct osw_plat_bcm_atf_phy *phy, const char *vif_name)
{
    struct osw_plat_bcm_atf_vif *vif = ds_tree_find(&phy->vifs, vif_name);
    if (vif == NULL) return OSW_PLAT_BCM_ATF_ATOS_SCHEDULER;

    const enum osw_airtime_precedence precedence = vif->precedence;
    /* Sanity check, should have meaningful values */
    WARN_ON(precedence == OSW_AIRTIME_PRECEDENCE_DISABLED);
    WARN_ON(precedence == OSW_AIRTIME_PRECEDENCE_UNSUPPORTED);

    switch (precedence)
    {
        case OSW_AIRTIME_PRECEDENCE_UNSUPPORTED:
            return OSW_PLAT_BCM_ATF_ATOS_SCHEDULER;
        case OSW_AIRTIME_PRECEDENCE_HIGH:
            return OSW_PLAT_BCM_ATF_EBOS_SCHEDULER;
        case OSW_AIRTIME_PRECEDENCE_MEDIUM:
            return OSW_PLAT_BCM_ATF_ATOS_SCHEDULER;
        case OSW_AIRTIME_PRECEDENCE_LOW:
            return OSW_PLAT_BCM_ATF_ATOS2_SCHEDULER;
        case OSW_AIRTIME_PRECEDENCE_DISABLED:
            return OSW_PLAT_BCM_ATF_ATOS_SCHEDULER;
    }
    return OSW_PLAT_BCM_ATF_ATOS_SCHEDULER;
}

static int osw_plat_bcm_atf_get_wl_scheduler_priority(const int wl_scheduler)
{
    // Return lowest priority integer value for each scheduler
    // (lower numeric might mean higher priority)
    switch (wl_scheduler)
    {
        case OSW_PLAT_BCM_ATF_EBOS_SCHEDULER:
            return OSW_PLAT_BCM_ATF_EBOS_PRIORITY;
        case OSW_PLAT_BCM_ATF_ATOS_SCHEDULER:
            return OSW_PLAT_BCM_ATF_ATOS_PRIORITY;
        case OSW_PLAT_BCM_ATF_ATOS2_SCHEDULER:
            return OSW_PLAT_BCM_ATF_ATOS2_PRIORITY;
    }
    return OSW_PLAT_BCM_ATF_ATOS_PRIORITY;
}

static void osw_plat_bcm_atf_sta_connected_cb(
        struct osw_state_observer *observer,
        const struct osw_state_sta_info *info)
{
    struct osw_plat_bcm_atf *m = container_of(observer, typeof(*m), state_obs);
    struct osw_plat_bcm_atf_phy *phy = ds_tree_find(&m->phys, info->vif->phy->phy_name);
    if (phy == NULL) return;

    struct osw_hwaddr_str addr_str;
    const char *sta_mac_str = osw_hwaddr2str(info->mac_addr, &addr_str);
    const char *vif_name = info->vif->vif_name;

    const int wl_scheduler = osw_plat_bcm_atf_get_wl_scheduler(phy, vif_name);
    const int wl_scheduler_priority = osw_plat_bcm_atf_get_wl_scheduler_priority(wl_scheduler);

    WARN_ON(!WL(vif_name, "taf", sta_mac_str, strfmta("%d", wl_scheduler), strfmta("%d", wl_scheduler_priority)));
}

static void osw_plat_bcm_atf_phy_set_enabled(struct osw_plat_bcm_atf_phy *phy, const bool enable)
{
    WARN_ON(!WL(phy->phy_name, "taf", "enable", strfmta("%d", enable)));
}

/* This function handles both enabling and disabling ATF per PHY.
 * Since reading the state of ATF from the driver is not yet implemented, the
 * decision is made based on the existence of the _atf_phy structure. It means
 * that when enabled, structure should be allocated so vifs can be configured in
 * the future based on airtime_precedence. If disabled, we invalidate/clear state
 * in the driver and free phy/vifs.
 */
static void osw_plat_bcm_set_atf_enabled(struct osw_plat_bcm_atf *m, const char *phy_name, const bool enable)
{
    struct osw_plat_bcm_atf_phy *phy = ds_tree_find(&m->phys, phy_name);
    if (phy == NULL && enable)
    {
        phy = osw_plat_bcm_atf_phy_alloc(phy_name, m);
        osw_plat_bcm_atf_phy_set_enabled(phy, enable);
    }

    if (phy != NULL && !enable)
    {
        osw_plat_bcm_atf_phy_set_enabled(phy, enable);
        osw_plat_bcm_atf_phy_free(phy);
    }

    LOGD(LOG_PREFIX_ATF("phy %s: enabled = %d", phy_name, enable));
}

static bool osw_plat_bcm_get_atf_enabled(struct osw_plat_bcm_atf *m, const char *phy_name)
{
    const struct osw_plat_bcm_atf_phy *phy = ds_tree_find(&m->phys, phy_name);
    return (phy != NULL);
}

static void osw_plat_bcm_atf_init(struct osw_plat_bcm_atf *m)
{
    const struct osw_state_observer state_obs = {
        .name = __FILE__,
        .sta_connected_fn = osw_plat_bcm_atf_sta_connected_cb,
    };

    m->state_obs = state_obs;
    ds_tree_init(&m->phys, ds_str_cmp, struct osw_plat_bcm_atf_phy, node);
}

static void osw_plat_bcm_atf_attach(struct osw_plat_bcm_atf *m)
{
    OSW_MODULE_LOAD(osw_state);
    osw_plat_bcm_atf_register_observer(m);
}

static struct osw_plat_bcm_atf *osw_plat_bcm_atf_new(void)
{
    struct osw_plat_bcm_atf *m = CALLOC(1, sizeof(*m));
    osw_plat_bcm_atf_init(m);
    osw_plat_bcm_atf_attach(m);
    return m;
}
