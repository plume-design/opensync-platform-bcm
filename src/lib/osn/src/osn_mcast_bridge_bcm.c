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

#include <net/if.h>

#include "log.h"
#include "execsh.h"
#include "os_util.h"
#include "kconfig.h"

#include "osn_mcast_bcm.h"

#define MCPD_CONFIG_FILE    "/var/mcpd.conf"
/* Default number of apply retries before giving up */
#define MCPD_APPLY_RETRIES  5
#define OVS_APPLY_RETRIES  5

void osn_mcast_mcpd_apply_fn(struct ev_loop *loop, ev_debounce *w, int revent);
void osn_mcast_ovs_apply_fn(struct ev_loop *loop, ev_debounce *w, int revent);

static char set_mcast_snooping[] = _S(ovs-vsctl set Bridge "$1" mcast_snooping_enable="$2");
static char set_unknown_group[] = _S(ovs-vsctl set Bridge "$1" other_config:mcast-snooping-disable-flood-unregistered="$2");
static char set_static_mrouter[] = _S(ovs-vsctl set Port "$1" other_config:mcast-snooping-flood-reports="$2");
static char set_max_groups[] = _S(ovs-vsctl set Bridge "$1" other_config:mcast-snooping-table-size="$2");
static char set_igmp_age[] = _S(ovs-vsctl set Bridge "$1" other_config:mcast-snooping-aging-time="$2");

osn_mcast_bridge osn_mcast_bridge_base;

static osn_mcast_bridge *osn_mcast_bridge_init()
{
    osn_mcast_bridge *self = &osn_mcast_bridge_base;

    if (self->initialized)
        return self;

    /* MCPD should already be running */
    if (execsh_log(LOG_SEVERITY_DEBUG, _S(ps | grep "[m]cpd")) != 0)
    {
        LOG(ERR, "mcpd_util_init: MCPD should be already running");
        return false;
    }

    /* Initialize apply debounce */
    ev_debounce_init2(&self->mcpd_debounce, osn_mcast_mcpd_apply_fn, 0.4, 2.0);
    ev_debounce_init2(&self->ovs_debounce, osn_mcast_ovs_apply_fn, 0.4, 2.0);

    self->initialized = true;

    return self;
}

osn_igmp_t *osn_mcast_bridge_igmp_init()
{
    osn_mcast_bridge *self = osn_mcast_bridge_init();
    self->igmp_initialized = true;

    return &self->igmp;
}

osn_mld_t *osn_mcast_bridge_mld_init()
{
    osn_mcast_bridge *self = osn_mcast_bridge_init();
    self->mld_initialized = true;

    return &self->mld;
}

bool osn_mcast_apply()
{
    osn_mcast_bridge *self = &osn_mcast_bridge_base;
    self->mcpd_retry = MCPD_APPLY_RETRIES;
    self->ovs_retry = OVS_APPLY_RETRIES;
    ev_debounce_start(EV_DEFAULT, &self->mcpd_debounce);
    ev_debounce_start(EV_DEFAULT, &self->ovs_debounce);

    return true;
}

char *osn_mcast_other_config_get_string(
        const struct osn_mcast_other_config *other_config,
        const char *key)
{
    int ii;

    for (ii = 0; ii < other_config->oc_len; ii++)
    {
        if (strcmp(other_config->oc_config[ii].ov_key, key) == 0)
        {
            return other_config->oc_config[ii].ov_value;
        }
    }

    return NULL;
}

long osn_mcast_other_config_get_long(const struct osn_mcast_other_config *other_config, const char *key)
{
    char *str = osn_mcast_other_config_get_string(other_config, key);
    long val;

    if (str != NULL && os_strtoul(str, &val, 0) == true)
    {
        return val;
    }

    return 0;
}

bool osn_mcast_free_string_array(char **arr, int len) {
    int ii;

    for (ii = 0; ii < len; ii++)
    {
        FREE(arr[ii]);
    }
    FREE(arr);

    return true;
}

static bool osn_mcast_ovs_deconfigure(osn_mcast_bridge *self)
{
    int status;

    LOGI("osn_mcast_ovs_deconfigure: called with %s", self->snooping_bridge);

    if (self->snooping_bridge[0] == '\0')
        return true;

    /* Disable snooping */
    status = execsh_log(LOG_SEVERITY_DEBUG, set_mcast_snooping, self->snooping_bridge, "false");
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        LOG(INFO, "osn_mcast_ovs_deconfigure: Cannot disable snooping on bridge %s",
                self->snooping_bridge);
    }

    /* Reset unknown group behavior */
    status = execsh_log(LOG_SEVERITY_DEBUG, set_unknown_group, self->snooping_bridge, "false" );
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        LOG(INFO, "osn_mcast_ovs_deconfigure: Error resetting unknown group behiavor on bridge %s",
                self->snooping_bridge);
    }

    /* Unset static mrouter port */
    if (self->static_mrouter[0] != '\0')
    {
        status = execsh_log(LOG_SEVERITY_DEBUG, set_static_mrouter, self->static_mrouter, "false");
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        {
            LOG(INFO, "osn_mcast_ovs_deconfigure: Error unsetting old static multicast router %s",
                    self->static_mrouter);
        }
        self->static_mrouter[0] = '\0';
    }

    self->snooping_bridge[0] = '\0';
    return true;
}

/* Returns false, if reapply is needed */
bool osn_mcast_apply_ovs_config(osn_mcast_bridge *self)
{
    osn_igmp_t *igmp = &self->igmp;
    osn_mld_t *mld = &self->mld;
    bool snooping_enabled;
    char *snooping_bridge;
    bool snooping_bridge_up;
    char *static_mrouter;
    bool static_mrouter_up;
    bool flood_unknown;
    int max_groups;
    char _max_groups[C_INT32_LEN];
    int aging_time;
    char _aging_time[C_INT32_LEN];
    int status;

    if (igmp->snooping_enabled || !mld->snooping_enabled)
    {
        snooping_enabled = igmp->snooping_enabled;
        snooping_bridge = igmp->snooping_bridge;
        snooping_bridge_up = igmp->snooping_bridge_up;
        static_mrouter = igmp->static_mrouter;
        static_mrouter_up = igmp->static_mrouter_up;
        flood_unknown = igmp->unknown_group == OSN_MCAST_UNKNOWN_FLOOD;
        max_groups = igmp->max_groups;
        aging_time = igmp->aging_time;
    }
    else
    {
        snooping_enabled = mld->snooping_enabled;
        snooping_bridge = mld->snooping_bridge;
        snooping_bridge_up = mld->snooping_bridge_up;
        static_mrouter = mld->static_mrouter;
        static_mrouter_up = mld->static_mrouter_up;
        flood_unknown = mld->unknown_group == OSN_MCAST_UNKNOWN_FLOOD;
        max_groups = mld->max_groups;
        aging_time = mld->aging_time;
    }

    /* If snooping was turned off or snooping bridge was changed, deconfigure it first */
    if (snooping_bridge_up == false || strncmp(self->snooping_bridge, snooping_bridge, IFNAMSIZ) != 0)
        osn_mcast_ovs_deconfigure(self);

    if (snooping_bridge_up == false || snooping_bridge[0] == '\0')
        return true;

    /* Enable/disable snooping */
    status = execsh_log(LOG_SEVERITY_DEBUG, set_mcast_snooping, snooping_bridge,
                        snooping_enabled ? "true" : "false");
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        LOG(ERR, "osn_mcast_apply_ovs_config: Error enabling/disabling snooping, command failed for %s",
                snooping_bridge);
        return true;
    }
    STRSCPY_WARN(self->snooping_bridge, snooping_bridge);

    /* Set maximum groups */
    snprintf(_max_groups, sizeof(_max_groups), "%d", max_groups);
    status = execsh_log(LOG_SEVERITY_DEBUG, set_max_groups, snooping_bridge, _max_groups);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        LOG(ERR, "osn_mcast_apply_ovs_config: Error setting maximum groups, command failed for %s",
                snooping_bridge);
        return true;
    }

    /* Set aging time */
    snprintf(_aging_time, sizeof(_aging_time), "%d", aging_time);
    status = execsh_log(LOG_SEVERITY_DEBUG, set_igmp_age, snooping_bridge, _aging_time);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        LOG(ERR, "osn_mcast_apply_ovs_config: Error setting aging time, command failed for %s",
                snooping_bridge);
        return true;
    }

    /* Set behaviour of multicast with unknown group */
    status = execsh_log(LOG_SEVERITY_DEBUG, set_unknown_group, snooping_bridge,
                        (flood_unknown == true) ? "false" : "true");
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        LOG(ERR, "osn_mcast_apply_ovs_config: Error setting unknown group behiavor, command failed for %s",
                snooping_bridge);
        return true;
    }

    /* If static_mrouter port changed since last time, we need to disable the old port */
    if (strncmp(self->static_mrouter, static_mrouter, IFNAMSIZ) != 0 && self->static_mrouter[0] != '\0')
    {
        status = execsh_log(LOG_SEVERITY_DEBUG, set_static_mrouter, self->static_mrouter, "false");
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        {
            LOG(DEBUG, "osn_mcast_apply_ovs_config: Error unsetting old static mrouter, command failed for %s",
                    self->static_mrouter);
        }
        self->static_mrouter[0] = '\0';
    }

    if (static_mrouter[0] == '\0' || static_mrouter_up == false)
        return true;

    /* Set static_mrouter port */
    status = execsh_log(LOG_SEVERITY_DEBUG, set_static_mrouter,
                        static_mrouter, "true");
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        LOG(INFO, "osn_mcast_apply_ovs_config: Error setting static mrouter %s", static_mrouter);
        return false;
    }
    STRSCPY_WARN(self->static_mrouter, static_mrouter);

    return true;
}

void osn_mcast_ovs_apply_fn(struct ev_loop *loop, ev_debounce *w, int revent)
{
    osn_mcast_bridge *self = &osn_mcast_bridge_base;

    if (kconfig_enabled(CONFIG_TARGET_USE_NATIVE_BRIDGE)) return;

    if (!self->igmp_initialized && !self->mld_initialized)
        return;

    /* Apply OVS configuration */
    if (osn_mcast_apply_ovs_config(self) == false)
    {
        /* Schedule retry until retry limit reached */
        if (self->ovs_retry > 0)
        {
            LOG(INFO, "osn_mcast_ovs_apply_fn: retry %d", self->ovs_retry);
            self->ovs_retry--;
            ev_debounce_start(loop, w);
            return;
        }

        LOG(ERR, "osn_mcast_ovs_apply_fn: Unable to apply OVS configuration.");
    }

    return;
}

static bool osn_mcast_write_mcpd_config(osn_mcast_bridge *self)
{
    FILE *f = fopen(MCPD_CONFIG_FILE, "w");

    if (f == NULL)
    {
        LOG(ERR, "osn_mcast_write_mcpd_config: Unable to open config file: %s", MCPD_CONFIG_FILE);
        return false;
    }

    /* Handle if osn is initialized here instead */
    if (self->igmp_initialized)
        WARN_ON(osn_igmp_write_section(&self->igmp, f) == false);
    if (self->mld_initialized)
        WARN_ON(osn_mld_write_section(&self->mld, f) == false);

    fprintf(f, "# Begin mcast configuration\n");
    fprintf(f, "mcast-max-groups-port-list\n");
    fprintf(f, "mcpd-strict-wan 0\n");
    fprintf(f, "# End mcast configuration\n\n");

    fclose(f);

    return true;
}

static bool is_wan_wl_interface(const char* if_name)
{
    return strstr(if_name, "wl") != NULL;
}

void osn_mcast_mcpd_apply_fn(struct ev_loop *loop, ev_debounce *w, int revent)
{
    osn_mcast_bridge *self = &osn_mcast_bridge_base;
    char cmd[256];

    if (kconfig_enabled(CONFIG_TARGET_USE_NATIVE_BRIDGE)) return;

    /* Apply MCPD configuration */
    if (WARN_ON(osn_mcast_write_mcpd_config(self) == false))
        return;

    /*
     * Wait until mcpd is ready for accepting commands via the `mcpctl` tool. We
     * ensure this by checking netstat -anp to see if mcpd opened the control
     * socket.
     */
    if (execsh_log(LOG_SEVERITY_DEBUG, _S(netstat -anp | grep -q mcpd)) != 0)
    {
        /* Schedule retry until retry limit reached */
        if (self->mcpd_retry > 0)
        {
            LOG(INFO, "osn_mcast_mcpd_apply_fn: retry %d", self->mcpd_retry);
            self->mcpd_retry--;
            ev_debounce_start(loop, w);
            return;
        }

        LOG(ERR, "osn_mcast_mcpd_apply_fn: Unable to detect the MCPD socket.");
        return;
    }

    /* Setting WAN interface for Archer mcast acceleration, only if not g-wl* or not wl* type */
    if (!is_wan_wl_interface(self->igmp.mcast_interface))
    {
        if (kconfig_enabled(CONFIG_OSN_BACKEND_VLAN_BCM_VLANCTL))
            snprintf(cmd, sizeof(cmd), "ethswctl -c wan -i %s.vc -o enable", self->igmp.mcast_interface);
        else
            snprintf(cmd, sizeof(cmd), "ethswctl -c wan -i %s -o enable", self->igmp.mcast_interface);

        if (cmd_log(cmd) != 0)
            LOG(ERR, "osn_mcast_mcpd_apply_fn: '%s' failed", cmd);
    }

    if (cmd_log("mcpctl reload") != 0)
        LOG(ERR, "osn_mcast_mcpd_apply_fn: 'mcpctl reload' failed");

    if (cmd_log("mcpctl mcgrpmode firstin") != 0)
        LOG(ERR, "osn_mcast_mcpd_apply_fn: 'mcpctl mcgrpmode firstin' failed");

    return;
}
