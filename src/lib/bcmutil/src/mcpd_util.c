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

#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

#include <errno.h>

#define LOG_MODULE_ID  LOG_MODULE_ID_OSA

#include "daemon.h"
#include "target.h"
#include "log.h"
#include "const.h"
#include "util.h"

#include "mcpd_util.h"


#define MCPD_DAEMON_PATH    "/bin/mcpd"
#define MCPD_CONFIG_FILE    "/var/mcpd.conf"
#define MCPD_PID_FILE       "/tmp/mcpd.pid"

static struct mcpd_mgr      mcpd_hdl;


static void mcpd_cleanup_proxycfg(target_mcproxy_params_t *proxy_param)
{
    memset(proxy_param->upstrm_if, 0, sizeof(proxy_param->upstrm_if));

    if (proxy_param->num_dwnstrifs)
        free(proxy_param->dwnstrm_ifs);

    proxy_param->num_dwnstrifs = 0;
}

static void mcpd_copy_proxycfg(
        target_mcproxy_params_t *to,
        const target_mcproxy_params_t  *from)
{
    int cnt = 0;

    mcpd_cleanup_proxycfg(to);
    to->protocol = from->protocol;
    STRSCPY_WARN(to->upstrm_if, from->upstrm_if);
    to->num_dwnstrifs = from->num_dwnstrifs;
    to->dwnstrm_ifs = calloc(1, to->num_dwnstrifs * sizeof(ifname));

    for (cnt = 0; cnt < to->num_dwnstrifs; cnt++)
    {
        STRSCPY_WARN(to->dwnstrm_ifs[cnt], from->dwnstrm_ifs[cnt]);
    }
    return;
}

/*
 * Initialize the mcpd params and daemon.
 * @return true if initialized
 */
bool mcpd_util_init(void)
{
    daemon_t *pdmn = &mcpd_hdl.mcpd_dmn_hdl;

    if (mcpd_hdl.initialized)
        return true;

    // Create daemon handler
    if (!daemon_init(pdmn, MCPD_DAEMON_PATH, DAEMON_LOG_ALL))
    {
        LOGE("mcpd_util_init: Unable to initialize mcpd daemon.");
        return false;
    }
    if (!daemon_pidfile_set(pdmn, MCPD_PID_FILE, true))
    {
        LOGW("mcpd_util_init: Error setting the PID file path.");
    }
    if (!daemon_restart_set(pdmn, true, 5.0, 5))
    {
        LOGW("mcpd_util_init: Error enabling daemon auto-restart.");
    }
    daemon_arg_add(pdmn, "-c", MCPD_CONFIG_FILE);
    mcpd_hdl.igmp_param.protocol = DISABLE_IGMP;
    mcpd_hdl.mld_param.protocol = DISABLE_MLD;
    mcpd_hdl.initialized = true;

    if (WARN_ON(mcpd_util_write_config() == false))
        return false;

    daemon_start(pdmn);
    sleep(1);

    // Until "mcp reload" is called mcpd's config is not taking effect
    cmd_log("mcp reload");

    return true;
}

/*
 * Update mcpd basic params.
 * @param proxy_param Proxy configuration
 * @return true if configured
 */
bool mcpd_update_proxy_params(const target_mcproxy_params_t *proxy_param)
{
    if (proxy_param->protocol == DISABLE_IGMP ||
        proxy_param->protocol == IGMPv1 ||
        proxy_param->protocol == IGMPv2 ||
        proxy_param->protocol == IGMPv3)
    {
        mcpd_copy_proxycfg(&mcpd_hdl.igmp_param, proxy_param);
    } else {
        mcpd_copy_proxycfg(&mcpd_hdl.mld_param, proxy_param);
    }
    return true;
}

/*
 * Update the igmp sys params.
 * @param iccfg tunable parameters for igmp
 * @return true if updated
 */
bool mcpd_util_update_igmp_sys_params(const struct schema_IGMP_Config *iccfg)
{
    memcpy(&mcpd_hdl.iccfg, iccfg, sizeof(struct schema_IGMP_Config));
    return true;
}

/*
 * Update the mld sys params.
 * All tunable parameters are defined here:
 * https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt
 * @param mlcfg tunable parameters for mld
 * @return true if updated
 */
bool mcpd_util_update_mld_sys_params(const struct schema_MLD_Config *mlcfg)
{
    memcpy(&mcpd_hdl.mlcfg, mlcfg, sizeof(struct schema_MLD_Config));
    return true;
}

static void mcpd_util_write_igmp_sys_params(FILE *f, const struct schema_IGMP_Config *pcfg)
{
    if (pcfg->query_interval != 0)
        fprintf(f, "igmp-query-interval %d\n", pcfg->query_interval);
    if (pcfg->query_response_interval != 0)
        fprintf(f, "igmp-query-response-interval %d\n", pcfg->query_response_interval);
    if (pcfg->last_member_query_interval != 0)
        fprintf(f, "igmp-last-member-query-interval %d\n", pcfg->last_member_query_interval);
    if (pcfg->query_robustness_value != 0)
        fprintf(f, "igmp-robustness-value %d\n", pcfg->query_robustness_value);
    if (pcfg->maximum_groups != 0)
        fprintf(f, "igmp-max-groups %d\n", pcfg->maximum_groups);
    if (pcfg->maximum_sources != 0)
        fprintf(f, "igmp-max-sources %d\n", pcfg->maximum_sources);
    if (pcfg->maximum_members != 0)
        fprintf(f, "igmp-max-members %d\n", pcfg->maximum_members);
    fprintf(f, "igmp-fast-leave %d\n", pcfg->fast_leave_enable ? 1 : 0);

    return;
}

static void mcpd_util_write_mld_sys_params(FILE *f, const struct schema_MLD_Config *pcfg)
{
    if (pcfg->query_interval != 0)
        fprintf(f, "mld-query-interval %d\n", pcfg->query_interval);
    if (pcfg->query_response_interval != 0)
        fprintf(f, "mld-query-response-interval %d\n", pcfg->query_response_interval);
    if (pcfg->last_member_query_interval != 0)
        fprintf(f, "mld-last-member-query-interval %d\n", pcfg->last_member_query_interval);
    if (pcfg->query_robustness_value != 0)
        fprintf(f, "mld-robustness-value %d\n", pcfg->query_robustness_value);
    if (pcfg->maximum_groups != 0)
        fprintf(f, "mld-max-groups %d\n", pcfg->maximum_groups);
    if (pcfg->maximum_sources != 0)
        fprintf(f, "mld-max-sources %d\n", pcfg->maximum_sources);
    if (pcfg->maximum_members != 0)
        fprintf(f, "mld-max-members %d\n", pcfg->maximum_members);
    fprintf(f, "mld-fast-leave %d\n", pcfg->fast_leave_enable ? 1 : 0);

    return;
}

static bool mcpd_util_write_proxy_param(FILE *f, const target_mcproxy_params_t *proxy_param)
{
    char        prtcl;
    char        prt_key[16] = {0};
    int         cnt = 0;

    switch (proxy_param->protocol)
    {
        case IGMPv1:
            prtcl = '1';
            STRSCPY_WARN(prt_key, "igmp");
            break;

        case IGMPv2:
            prtcl = '2';
            STRSCPY_WARN(prt_key, "igmp");
            break;

        case IGMPv3:
            prtcl = '3';
            STRSCPY_WARN(prt_key, "igmp");
            break;

        case MLDv1:
            prtcl = '1';
            STRSCPY_WARN(prt_key, "mld");
            break;

        case MLDv2:
             prtcl = '2';
             STRSCPY_WARN(prt_key, "mld");
             break;

        case DISABLE_IGMP:
             return true;

        case DISABLE_MLD:
             return true;

        default:
             return false;
    }

    fprintf(f, "# Beginning %s Configuration.\n", prt_key);
    fprintf(f, "%s-default-version %c\n", prt_key, prtcl);
    fprintf(f, "%s-proxy-interfaces %s\n", prt_key, proxy_param->upstrm_if);
    fprintf(f, "%s-snooping-interfaces ", prt_key);

    for (cnt = 0; cnt < proxy_param->num_dwnstrifs; cnt++)
    {
        fprintf(f, "%s ", proxy_param->dwnstrm_ifs[cnt]);
    }
    fprintf(f,"\n");
    fprintf(f, "%s-mcast-interfaces %s\n", prt_key, proxy_param->upstrm_if);

    if (!strncmp(prt_key, "igmp", 4))
        mcpd_util_write_igmp_sys_params(f, &mcpd_hdl.iccfg);
    else if (!strncmp(prt_key, "mld", 3))
        mcpd_util_write_mld_sys_params(f, &mcpd_hdl.mlcfg);

    return true;
}

/*
 * Write config file for mcpd daemon.
 * return true if successful
 */
bool mcpd_util_write_config(void)
{
    FILE    *f = NULL;

    f = fopen(MCPD_CONFIG_FILE, "w");
    if (f == NULL)
    {
        LOG(ERR, "mcpd_util: Unable to open config file: %s", MCPD_CONFIG_FILE);
        return false;
    }

    WARN_ON(mcpd_util_write_proxy_param(f, &mcpd_hdl.igmp_param) == false);
    WARN_ON(mcpd_util_write_proxy_param(f, &mcpd_hdl.mld_param) == false);

    fprintf(f, "mcpd-strict-wan 0\n");
    fprintf(f, "# End mcast configuration.\n");
    if (f != NULL) fclose(f);

    return true;
}

/*
 * Write the config and trigger a reload.
 * @return true if applied
 */
bool mcpd_util_apply(void)
{
    if (WARN_ON(mcpd_util_write_config() == false))
        return false;

    cmd_log("mcp reload");

    return true;
}
