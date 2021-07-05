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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <dirent.h>
#include <libgen.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include "target.h"
#include "log.h"

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include "util.h"

#include <linux/un.h>

#include "schema.h"
#include "mcpd_util.h"
#include "execsh.h"
#include "log.h"

#define MODULE_ID LOG_MODULE_ID_TARGET

bool target_set_igmp_mcproxy_params(target_mcproxy_params_t *mcparams)
{
    // Store the config
    if (mcpd_util_update_proxy_params(mcparams) == false)
        return false;

    return mcpd_util_apply();
}

bool target_set_igmp_mcproxy_sys_params(struct schema_IGMP_Config *iccfg)
{

    if (mcpd_util_update_igmp_sys_params(iccfg) == false)
        return false;

    return mcpd_util_apply();
}

bool target_set_mld_mcproxy_params(target_mcproxy_params_t *mcparams)
{
    // Store the config
    if (mcpd_util_update_proxy_params(mcparams) == false)
        return false;

    return mcpd_util_apply();
}

bool target_set_mld_mcproxy_sys_params(struct schema_MLD_Config *mlcfg)
{
    if (mcpd_util_update_mld_sys_params(mlcfg) == false)
        return false;

    return mcpd_util_apply();
}

bool ovs_set_snooping_flood_reports(const char *ifname, bool enable)
{
    int rc;

    rc = execsh_log(
            LOG_SEVERITY_DEBUG,
            _S(ovs-vsctl set Port "$1" other_config:mcast-snooping-flood-reports="$2"),
            (char *)ifname,
            enable ? "true" : "false");
    if (rc != 0)
    {
        LOG(DEBUG, "mcast: %s: Error enabling[%d] snooping-flood-reports.",
                ifname,
                enable);
        return false;
    }

    return true;
}

void mcast_set_snooping_flood_report(const char *ifname, bool enable, bool is_wan, const char *bridge)
{
    static char current_snooping_ifname[C_IFNAME_LEN];

    const char *sifname = NULL;

    if (is_wan)
    {
        /* Apply settings to the LAN bridge instead */
        sifname = CONFIG_TARGET_LAN_BRIDGE_NAME;
    }
    else if (bridge != NULL)
    {
        sifname = ifname;
    }

    if (sifname == NULL) return;

    if (!ovs_set_snooping_flood_reports(sifname, enable))
    {
        return;
    }

    if (enable)
    {
        if (current_snooping_ifname[0] != '\0' && strcmp(sifname, current_snooping_ifname) != 0)
        {
            LOG(INFO, "mcast: %s: snooping-flood-reports flag cleared.",
                    current_snooping_ifname);
            (void)ovs_set_snooping_flood_reports(current_snooping_ifname, false);
        }

        STRSCPY_WARN(current_snooping_ifname, sifname);
    }
    else if (strcmp(current_snooping_ifname, sifname) == 0)
    {
        current_snooping_ifname[0] = '\0';
    }

    LOG(INFO, "mcast: %s: snooping-flood-reports enabled=%d.",
            sifname,
            enable);
}

bool target_set_mcast_uplink(const char *ifname, bool enable, bool is_wan, const char *bridge)
{
    mcast_set_snooping_flood_report(ifname, enable, is_wan, bridge);

    // Store the config
    if (mcpd_util_update_uplink(ifname, enable, bridge) == false)
        return false;

    return mcpd_util_apply();
}

bool target_set_mcast_iptv(const char *ifname, bool enable)
{
    if (!mcpd_util_update_iptv(ifname, enable))
    {
        return false;
    }

    return mcpd_util_apply();
}

bool target_set_igmp_snooping(const char *ifname, bool enable)
{
    // Store the config
    if (mcpd_util_update_snooping(ifname, enable) == false)
        return false;

    return mcpd_util_apply();
}
