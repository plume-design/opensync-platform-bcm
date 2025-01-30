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
#include <string.h>

#include "log.h"
#include "execsh.h"
#include "os_util.h"
#include "kconfig.h"

#include "osn_mcast_bcm.h"

#define MCPD_CONFIG_FILE    "/var/mcpd.conf"
/* Default number of apply retries before giving up */
#define MCPD_APPLY_RETRIES  5
#define BRIDGE_APPLY_RETRIES  5

void osn_mcast_mcpd_apply_fn(struct ev_loop *loop, ev_debounce *w, int revent);
void osn_mcast_bridge_apply_fn(struct ev_loop *loop, ev_debounce *w, int revent);

/* Broadcom snooping tool configuration */
static char set_mcast_igmp_snooping_bridge[] = _S(bcmmcastctl mode -i "$1" -p 1 -m "$2");
static char set_mcast_mld_snooping_bridge[] = _S(bcmmcastctl mode -i "$1" -p 2 -m "$2");

static char set_mcast_igmp_snooping_l2l_bridge[] = _S(bcmmcastctl l2l -i "$1" -p 1 -e "$2");
static char set_mcast_mld_snooping_l2l_bridge[] = _S(bcmmcastctl l2l -i "$1" -p 2 -e "$2");

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
    ev_debounce_init2(&self->bridge_debounce, osn_mcast_bridge_apply_fn, 0.4, 2.0);

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
    ev_debounce_start(EV_DEFAULT, &self->mcpd_debounce);
    self->bridge_retry = BRIDGE_APPLY_RETRIES;
    ev_debounce_start(EV_DEFAULT, &self->bridge_debounce);

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

static bool osn_mcast_bridge_deconfigure(osn_mcast_bridge *self)
{
    int status;

    LOGI("osn_mcast_bridge_deconfigure: called with %s", self->snooping_bridge);

    if (self->snooping_bridge[0] == '\0')
        return true;

    /* Disable snooping */
    status = execsh_log(LOG_SEVERITY_DEBUG, set_mcast_igmp_snooping_bridge, self->snooping_bridge, "0");
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        LOG(INFO, "osn_mcast_bridge_deconfigure: Cannot disable igmp snooping on bridge %s",
                self->snooping_bridge);
    }

    status = execsh_log(LOG_SEVERITY_DEBUG, set_mcast_mld_snooping_bridge, self->snooping_bridge, "0");
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        LOG(INFO, "osn_mcast_bridge_deconfigure: Cannot disable mld snooping on bridge %s",
                self->snooping_bridge);
    }

    /* Don't configure l2l snooping for SDK 5.04L02 or newer */
    if (BCM_SDK_VERSION < 0x50402)
    {
        /* Disable l2l igmp snooping */
        status = execsh_log(LOG_SEVERITY_DEBUG, set_mcast_igmp_snooping_l2l_bridge, self->snooping_bridge, "0");
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        {
            LOG(INFO, "osn_mcast_bridge_deconfigure: Cannot disable igmp l2l on bridge %s",
                self->snooping_bridge);
        }

        /* Disable l2l snooping */
        status = execsh_log(LOG_SEVERITY_DEBUG, set_mcast_mld_snooping_l2l_bridge, self->snooping_bridge, "0");
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        {
            LOG(INFO, "osn_mcast_bridge_deconfigure: Cannot disable mld l2l on bridge %s",
                self->snooping_bridge);
        }
    }

    self->snooping_bridge[0] = '\0';
    return true;
}

/* Returns false, if reapply is needed */
bool osn_mcast_apply_bridge_config(osn_mcast_bridge *self)
{
    osn_igmp_t *igmp = &self->igmp;
    osn_mld_t *mld = &self->mld;
    bool snooping_enabled;
    char *snooping_bridge;
    bool snooping_bridge_up;
    bool fast_leave_enable;
    int status;

    if (igmp->snooping_enabled || !mld->snooping_enabled)
    {
        snooping_enabled = igmp->snooping_enabled;
        snooping_bridge = igmp->snooping_bridge;
        snooping_bridge_up = igmp->snooping_bridge_up;
        fast_leave_enable = igmp->fast_leave_enable;
    }
    else
    {
        snooping_enabled = mld->snooping_enabled;
        snooping_bridge = mld->snooping_bridge;
        snooping_bridge_up = mld->snooping_bridge_up;
        fast_leave_enable = mld->fast_leave_enable;
    }

    /* If snooping was turned off or snooping bridge was changed, deconfigure it first */
    if (snooping_bridge_up == false || strncmp(self->snooping_bridge, snooping_bridge, IFNAMSIZ) != 0)
        osn_mcast_bridge_deconfigure(self);

    if (snooping_bridge_up == false || snooping_bridge[0] == '\0')
        return true;

    /* Enable/disable snooping */
    status = execsh_log(LOG_SEVERITY_DEBUG, set_mcast_igmp_snooping_bridge, snooping_bridge, snooping_enabled ? "2" : "0");
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        LOG(ERR, "osn_mcast_apply_bridge_config: Error enabling/disabling igmp snooping, command failed for %s",
                snooping_bridge);
        return false;
    }

    status = execsh_log(LOG_SEVERITY_DEBUG, set_mcast_mld_snooping_bridge, snooping_bridge, snooping_enabled ? "2" : "0");
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        LOG(ERR, "osn_mcast_apply_bridge_config: Error enabling/disabling mld snooping, command failed for %s",
                snooping_bridge);
        return false;
    }
    STRSCPY_WARN(self->snooping_bridge, snooping_bridge);

    /* Don't configure l2l snooping for SDK 5.04L02 or newer */
    if (BCM_SDK_VERSION < 0x50402 && igmp->snooping_enabled && !igmp->proxy_enabled)
    {
        status = execsh_log(LOG_SEVERITY_DEBUG, set_mcast_igmp_snooping_l2l_bridge, snooping_bridge, snooping_enabled ? "1" : "0");
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        {
            LOG(ERR, "osn_mcast_apply_bridge_config: Error enabling igmp l2l, command failed for %s",
                snooping_bridge);
            return false;
        }
    }

    /* Don't configure l2l snooping for SDK 5.04L02 or newer */
    if (BCM_SDK_VERSION < 0x50402 && mld->snooping_enabled && !mld->proxy_enabled)
    {
        status = execsh_log(LOG_SEVERITY_DEBUG, set_mcast_mld_snooping_l2l_bridge, snooping_bridge, snooping_enabled ? "1" : "0");
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        {
            LOG(ERR, "osn_mcast_apply_bridge_config: Error enabling mld l2l, command failed for %s",
                snooping_bridge);
            return false;
        }
    }

    return true;
}

void osn_mcast_bridge_apply_fn(struct ev_loop *loop, ev_debounce *w, int revent)
{
    osn_mcast_bridge *self = &osn_mcast_bridge_base;

    if (!self->igmp_initialized && !self->mld_initialized)
        return;

    /* Apply bridge configuration */
    if (osn_mcast_apply_bridge_config(self) == false)
    {
        LOG(ERR, "osn_mcast_bridge_apply_fn: Unable to apply bridge configuration.");
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

static char* get_wan_from_mcast_interface(const char* mcast_interface)
{
    /*
     * The WAN interface for which multicast should be accelerated either has
     * the same name as the multicast interface or is followed by "." and a postfix
     * in case the multicast interface is a VLAN interface.
     */
    char *tmp = STRDUP(mcast_interface);
    return strtok(tmp, ".");
}

void osn_mcast_mcpd_apply_fn(struct ev_loop *loop, ev_debounce *w, int revent)
{
    osn_mcast_bridge *self = &osn_mcast_bridge_base;
    char *wan_interface;
    char cmd[256];

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
        wan_interface = get_wan_from_mcast_interface(self->igmp.mcast_interface);
        if (kconfig_enabled(CONFIG_OSN_BACKEND_VLAN_BCM_VLANCTL))
            snprintf(cmd, sizeof(cmd), "ethswctl -c wan -i %s.vc -o enable", wan_interface);
        else
            snprintf(cmd, sizeof(cmd), "ethswctl -c wan -i %s -o enable", wan_interface);
        FREE(wan_interface);

        LOG(TRACE, "osn_mcast_mcpd_apply_fn: Setting multicast acceleration on WAN interface: '%s'", cmd);

        if (cmd_log_check_safe(cmd) != 0)
            LOG(ERR, "osn_mcast_mcpd_apply_fn: '%s' failed", cmd);
    }

    if (cmd_log("mcpctl reload") != 0)
        LOG(ERR, "osn_mcast_mcpd_apply_fn: 'mcpctl reload' failed");

    if (cmd_log("mcpctl mcgrpmode firstin") != 0)
        LOG(ERR, "osn_mcast_mcpd_apply_fn: 'mcpctl mcgrpmode firstin' failed");

    return;
}
