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

/*
 * ===========================================================================
 *  Linux OSN MLD backend
 * ===========================================================================
 */

#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>

#include "log.h"
#include "const.h"
#include "util.h"
#include "memutil.h"
#include "ds_tree.h"
#include "kconfig.h"
#include "evx.h"
#include "execsh.h"
#include "os_util.h"

#include "osn_mld.h"
#include "osn_mcast_bcm.h"

osn_mld_t *osn_mld_new()
{
    osn_mld_t *self = osn_mcast_bridge_mld_init();

    if (self->initialized)
        return self;

    LOGI("Initializing MLD");

    /* Initialize defaults */
    self->version = OSN_MLDv2;
    self->unknown_group = OSN_MCAST_UNKNOWN_FLOOD;
    self->robustness_value = 2;
    self->max_groups = 10;
    self->max_sources = 10;
    self->aging_time = 300;
    self->fast_leave_enable = true;
    /* self->allowed_subnet = ???; */
    self->query_interval = 125;
    self->query_response_interval = 10;
    self->last_member_query_interval = 30;
    self->max_members = 10;
    self->initialized = true;

    return self;
}

bool osn_mld_del(osn_mld_t *self)
{
    /* Clean up */
    return true;
}

bool osn_mld_snooping_set(
        osn_mld_t *self,
        struct osn_mld_snooping_config *config)
{
    self->version = config->version;
    self->snooping_enabled = config->enabled;
    STRSCPY_WARN(self->snooping_bridge, (config->bridge != NULL) ? config->bridge : "");
    STRSCPY_WARN(self->static_mrouter, (config->static_mrouter != NULL) ? config->static_mrouter : "");
    self->unknown_group = config->unknown_group;
    self->robustness_value = (config->robustness_value != 0) ? config->robustness_value : 2;
    self->max_groups = (config->max_groups != 0) ? config->max_groups : 10;
    self->max_sources = (config->max_sources != 0) ? config->max_sources : 10;
    self->fast_leave_enable = config->fast_leave_enable;

    /* Exceptions */
    osn_mcast_free_string_array(self->mcast_exceptions, self->mcast_exceptions_len);
    self->mcast_exceptions_len = config->mcast_exceptions_len;
    self->mcast_exceptions = config->mcast_exceptions;

    return true;
}

bool osn_mld_proxy_set(
        osn_mld_t *self,
        struct osn_mld_proxy_config *config)
{
    self->proxy_enabled = config->enabled;
    STRSCPY_WARN(self->proxy_upstream_if, (config->upstream_if != NULL) ? config->upstream_if : "");
    STRSCPY_WARN(self->proxy_downstream_if, (config->downstream_if != NULL) ? config->downstream_if : "");

    /* Free unused strings */
    osn_mcast_free_string_array(config->group_exceptions, config->group_exceptions_len);
    osn_mcast_free_string_array(config->allowed_subnets, config->allowed_subnets_len);

    return true;
}

bool osn_mld_querier_set(
        osn_mld_t *self,
        struct osn_mld_querier_config *config)
{
    self->querier_enabled = config->enabled;
    self->query_interval = (config->interval != 0) ? config->interval : 125;
    self->query_response_interval = (config->resp_interval != 0) ? config->resp_interval : 10;
    self->last_member_query_interval = (config->last_member_interval != 0) ? config->last_member_interval : 30;

    return true;
}

bool osn_mld_other_config_set(
        osn_mld_t *self,
        const struct osn_mcast_other_config *other_config)
{
    long aging_time = osn_mcast_other_config_get_long(other_config, "aging_time");
    char max_members = osn_mcast_other_config_get_long(other_config, "maximum_members");
    char *mcast_bridge = osn_mcast_other_config_get_string(other_config, "mcast_bridge");
    char *mcast_interface = osn_mcast_other_config_get_string(other_config, "mcast_interface");

    self->aging_time = (aging_time != 0) ? aging_time : 300;
    self->max_members = (max_members != 0) ? max_members : 10;
    if (mcast_bridge != NULL)
        self->mcast_bridge = (strncmp(mcast_bridge, "true", 4) == 0) ? true : false;
    else
        self->mcast_bridge = false;
    STRSCPY_WARN(self->mcast_interface, (mcast_interface != NULL) ? mcast_interface : "");

    return true;
}

bool osn_mld_update_iface_status(
        osn_mld_t *self,
        char *ifname,
        bool enable)
{
    LOG(DEBUG, "osn_mld_update_iface_status: Updating interface %s status to: %s", ifname, enable ? "UP" : "DOWN");

    if (strncmp(ifname, self->snooping_bridge, IFNAMSIZ) == 0)
        self->snooping_bridge_up = enable;
    if (strncmp(ifname, self->static_mrouter, IFNAMSIZ) == 0)
        self->static_mrouter_up = enable;
    if (strncmp(ifname, self->proxy_upstream_if, IFNAMSIZ) == 0)
        self->proxy_upstream_if_up = enable;
    if (strncmp(ifname, self->proxy_downstream_if, IFNAMSIZ) == 0)
        self->proxy_downstream_if_up = enable;

    return true;
}

bool osn_mld_apply(osn_mld_t *self)
{
    return osn_mcast_apply();
}

bool osn_mld_write_section(osn_mld_t *self, FILE *f)
{
    bool snooping_enabled = self->snooping_enabled && self->snooping_bridge_up;
    char mld_version;
    char *uplink_if;
    int ii;

    switch (self->version)
    {
        case OSN_MLDv1:
            mld_version = '1';
            break;

        case OSN_MLDv2:
        default:
            mld_version = '2';
            break;
    }

    fprintf(f, "# Begin MLD configuration\n");
    fprintf(f, "mld-default-version %c\n", mld_version);

    fprintf(f, "mld-snooping-enable %d\n", (snooping_enabled) ? 1 : 0);
    fprintf(f, "mld-snooping-interfaces %s\n", (snooping_enabled) ? self->snooping_bridge : "");

    fprintf(f, "mld-proxy-enable %d\n", (self->proxy_upstream_if_up && self->proxy_enabled) ? 1 : 0);
    fprintf(f, "mld-proxy-interfaces %s\n", (self->proxy_upstream_if_up) ? self->proxy_upstream_if : "");

    /* Set correct uplink interface for acceleration */
    fprintf(f, "mld-mcast-interfaces ");

    if (BCM_SDK_VERSION < 0x50402 && self->mcast_bridge == true)
    {
        fprintf(f, "%s/", self->snooping_bridge);
    }

    /* Strip GRE prefix if needed */
    uplink_if = self->mcast_interface;
    if (strncmp(uplink_if, "g-wl", strlen("g-wl")) == 0)
    {
        uplink_if += strlen("g-");
    }
    fprintf(f, "%s\n", uplink_if);

    fprintf(f, "mld-query-interval %d\n", self->query_interval);
    fprintf(f, "mld-query-response-interval %d\n", self->query_response_interval);
    fprintf(f, "mld-last-member-query-interval %d\n", self->last_member_query_interval);
    fprintf(f, "mld-robustness-value %d\n", self->robustness_value);
    fprintf(f, "mld-max-groups %d\n", self->max_groups);
    fprintf(f, "mld-max-sources %d\n", self->max_sources);
    fprintf(f, "mld-max-members %d\n", self->max_members);
    fprintf(f, "mld-fast-leave %d\n", self->fast_leave_enable ? 1 : 0);
    fprintf(f, "mld-admission-required 0\n");
    fprintf(f, "mld-mcast-snoop-exceptions ");
    for (ii = 0; ii < self->mcast_exceptions_len; ii++)
    {
        if (ii != self->mcast_exceptions_len - 1)
            fprintf(f, "%s,", self->mcast_exceptions[ii]);
        else
            fprintf(f, "%s", self->mcast_exceptions[ii]);
    }
    fprintf(f, "\n# End MLD configuration\n\n");

    return true;
}
