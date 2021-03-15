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
#include "ds_tree.h"

#include "mcpd_util.h"

#define MCPD_DAEMON_PATH    "/bin/mcpd"
#define MCPD_CONFIG_FILE    "/var/mcpd.conf"
#define MCPD_PID_FILE       "/tmp/mcpd.pid"

typedef struct
{
    char ifname[IFNAMSIZ];
    char bridge[IFNAMSIZ];
    ds_tree_node_t node;
} mcpd_util_ifname_t;

typedef struct
{
    daemon_t                  mcpd_dmn_hdl;
    bool                      initialized;
    ds_tree_t                 snooping_ifs;
    ds_tree_t                 uplink_ifs;
    target_mcproxy_params_t   igmp_param;
    target_mcproxy_params_t   mld_param;
    struct schema_IGMP_Config iccfg;
    struct schema_MLD_Config  mlcfg;
} mcpd_util_mgr_t;

static bool mcpd_util_config_valid(void);

static mcpd_util_mgr_t g_mcpd_hdl;

/******************************************************************************
 *  PRIVATE definitions
 *****************************************************************************/

static void mcpd_util_cleanup_proxycfg(target_mcproxy_params_t *proxy_param)
{
    memset(proxy_param->upstrm_if, 0, sizeof(proxy_param->upstrm_if));

    if (proxy_param->num_dwnstrifs)
        free(proxy_param->dwnstrm_ifs);

    proxy_param->num_dwnstrifs = 0;
}

static void mcpd_util_copy_proxycfg(
        target_mcproxy_params_t *to,
        const target_mcproxy_params_t  *from)
{
    int cnt = 0;

    mcpd_util_cleanup_proxycfg(to);
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

static bool mcpd_util_update_tree(ds_tree_t *tree, const char *ifname, bool enable, const char *bridge)
{
    mcpd_util_ifname_t *node;

    node = ds_tree_find(tree, (char *)ifname);
    if (enable)
    {
        if (node == NULL)
        {
            node = calloc(1, sizeof(mcpd_util_ifname_t));
            if (node == NULL)
            {
                LOG(ERR, "mcpd_util: Error allocating mcpd_util_ifname_t object.");
                return false;
            }

            STRSCPY_WARN(node->ifname, ifname);
            ds_tree_insert(tree, node, node->ifname);
        }

        STRSCPY_WARN(node->bridge, bridge == NULL ? "" : bridge);
        return true;
    }
    else
    {
        if (node != NULL)
        {
            ds_tree_remove(tree, node);
            free(node);
            return true;
        }
    }

    // nothing to update
    return false;
}

static void mcpd_util_write_igmp_sys_params(FILE *f, const struct schema_IGMP_Config *pcfg)
{
    fprintf(f, "igmp-query-interval %d\n", pcfg->query_interval != 0 ? pcfg->query_interval : 125);
    fprintf(f, "igmp-query-response-interval %d\n", pcfg->query_response_interval != 0 ? pcfg->query_response_interval : 10);
    fprintf(f, "igmp-last-member-query-interval %d\n", pcfg->last_member_query_interval != 0 ? pcfg->last_member_query_interval : 30);
    fprintf(f, "igmp-robustness-value %d\n", pcfg->query_robustness_value != 0 ? pcfg->query_robustness_value : 2);
    fprintf(f, "igmp-max-groups %d\n", pcfg->maximum_groups != 0 ? pcfg->maximum_groups : 25);
    fprintf(f, "igmp-max-sources %d\n", pcfg->maximum_sources != 0 ? pcfg->maximum_sources : 10);
    fprintf(f, "igmp-max-members %d\n", pcfg->maximum_members != 0 ? pcfg->maximum_members : 25);
    fprintf(f, "igmp-fast-leave %d\n", pcfg->fast_leave_enable ? 1 : 0);
    fprintf(f, "igmp-admission-required 0\n");

    return;
}

static void mcpd_util_write_mld_sys_params(FILE *f, const struct schema_MLD_Config *pcfg)
{
    fprintf(f, "mld-query-interval %d\n", pcfg->query_interval != 0 ? pcfg->query_interval : 125);
    fprintf(f, "mld-query-response-interval %d\n", pcfg->query_response_interval != 0 ? pcfg->query_response_interval : 10);
    fprintf(f, "mld-last-member-query-interval %d\n", pcfg->last_member_query_interval != 0 ? pcfg->last_member_query_interval : 30);
    fprintf(f, "mld-robustness-value %d\n", pcfg->query_robustness_value != 0 ? pcfg->query_robustness_value : 2);
    fprintf(f, "mld-max-groups %d\n", pcfg->maximum_groups != 0 ? pcfg->maximum_groups : 10);
    fprintf(f, "mld-max-sources %d\n", pcfg->maximum_sources != 0 ? pcfg->maximum_sources : 10);
    fprintf(f, "mld-max-members %d\n", pcfg->maximum_members != 0 ? pcfg->maximum_members : 10 );
    fprintf(f, "mld-fast-leave %d\n", pcfg->fast_leave_enable ? 1 : 0);
    fprintf(f, "mld-admission-required 0\n");

    return;
}

static bool mcpd_util_write_section(FILE *f, const target_mcproxy_params_t *proxy_param)
{
    mcpd_util_ifname_t *node = NULL;
    char prtcl;
    char prt_key[16] = {0};

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

        case DISABLE_IGMP:
        case IGMPv3:
            prtcl = '3';
            STRSCPY_WARN(prt_key, "igmp");
            break;

        case MLDv1:
            prtcl = '1';
            STRSCPY_WARN(prt_key, "mld");
            break;

        case DISABLE_MLD:
        case MLDv2:
            prtcl = '2';
            STRSCPY_WARN(prt_key, "mld");
            break;

        default:
            LOG(ERR, "mcpd_util: Unknown protocol: %d", proxy_param->protocol);
            return false;
    }

    fprintf(f, "# Begin %s configuration\n", prt_key);
    fprintf(f, "%s-default-version %c\n", prt_key, prtcl);

    if (proxy_param->protocol == DISABLE_IGMP || proxy_param->protocol == DISABLE_MLD)
        fprintf(f, "%s-proxy-interfaces \n", prt_key);
    else
        fprintf(f, "%s-proxy-interfaces %s\n", prt_key, proxy_param->upstrm_if);

    fprintf(f, "%s-snooping-interfaces", prt_key);
    ds_tree_foreach(&g_mcpd_hdl.snooping_ifs, node)
    {
        fprintf(f, " %s", node->ifname);
    }
    fprintf(f,"\n");
    node = NULL;

    fprintf(f, "%s-mcast-interfaces", prt_key);
    ds_tree_foreach(&g_mcpd_hdl.uplink_ifs, node)
    {
        if (node->bridge[0] == '\0')
        {
            fprintf(f, " %s", node->ifname);
        }
        else
        {
            /*
             * TODO: mcpd always require the physical interface for proper
             * operation. In case a GRE backhaul tunnel is define as the
             * interfice, strip the "g-" prefix to map the GRE interface name to
             * the physical name.
             */
            char *nif = node->ifname;
            if (strncmp(nif, "g-wl", strlen("g-wl")) == 0)
            {
                nif += strlen("g-");
            }

            if (BCM_SDK_VERSION >= 0x50402) {
                fprintf(f, " %s", nif);
            } else {
                fprintf(f, " %s/%s", node->bridge, nif);
            }
        }
    }
    fprintf(f,"\n");

    if (!strncmp(prt_key, "igmp", 4))
        mcpd_util_write_igmp_sys_params(f, &g_mcpd_hdl.iccfg);
    else if (!strncmp(prt_key, "mld", 3))
        mcpd_util_write_mld_sys_params(f, &g_mcpd_hdl.mlcfg);

    fprintf(f, "# End %s configuration\n\n", prt_key);
    return true;
}

/*
 * Verify that the current MCPD configuration is valid. This checks if all
 * required MCPD parameters are set.
 */
bool mcpd_util_config_valid(void)
{
    if (ds_tree_is_empty(&g_mcpd_hdl.snooping_ifs))
    {
        LOG(INFO, "mcpd_util: Missing snooping interfaces configuration.");
        return false;
    }

    if (ds_tree_is_empty(&g_mcpd_hdl.uplink_ifs))
    {
        LOG(INFO, "mcpd_util: Missing uplink interfaces configuration.");
        return false;
    }

    return true;
}

/*
 * Write config file for mcpd daemon.
 * return true if successful
 */
static bool mcpd_util_write_config(void)
{
    FILE    *f = NULL;

    f = fopen(MCPD_CONFIG_FILE, "w");
    if (f == NULL)
    {
        LOG(ERR, "mcpd_util: Unable to open config file: %s", MCPD_CONFIG_FILE);
        return false;
    }

    WARN_ON(mcpd_util_write_section(f, &g_mcpd_hdl.igmp_param) == false);
    WARN_ON(mcpd_util_write_section(f, &g_mcpd_hdl.mld_param) == false);

    fprintf(f, "# Begin mcast configuration\n");
    fprintf(f, "mcast-max-groups-port-list\n");
    fprintf(f, "mcpd-strict-wan 0\n");
    fprintf(f, "igmp-mcast-snoop-exceptions 239.255.255.250/255.255.255.255 224.0.255.135/255.255.255.255\n");
    fprintf(f, "mld-mcast-snoop-exceptions ff05::0001:0003/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff\n");
    fprintf(f, "# End mcast configuration\n\n");

    if (f != NULL) fclose(f);

    return true;
}

/*
 * Initialize the mcpd params and daemon.
 * @return true if initialized
 */
bool mcpd_util_init(void)
{
    daemon_t *pdmn = &g_mcpd_hdl.mcpd_dmn_hdl;

    if (g_mcpd_hdl.initialized)
        return true;

    ds_tree_init(
            &g_mcpd_hdl.snooping_ifs,
            ds_str_cmp,
            mcpd_util_ifname_t,
            node);
    ds_tree_init(
            &g_mcpd_hdl.uplink_ifs,
            ds_str_cmp,
            mcpd_util_ifname_t,
            node);

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
    g_mcpd_hdl.igmp_param.protocol = DISABLE_IGMP;
    g_mcpd_hdl.mld_param.protocol = DISABLE_MLD;
    g_mcpd_hdl.initialized = true;

    if (WARN_ON(mcpd_util_write_config() == false))
        return false;

    return true;
}

/******************************************************************************
 *  PUBLIC definitions
 *****************************************************************************/

bool mcpd_util_apply(void)
{
    bool started;

    if (!mcpd_util_init())
        return false;

    if (!mcpd_util_config_valid())
    {
        /*
         * Silently ignore this error as we may still be waiting to receive all
         * the pieces of configuration to properly configure MCPD
         */
        daemon_stop(&g_mcpd_hdl.mcpd_dmn_hdl);
        return true;
    }

    if (WARN_ON(mcpd_util_write_config() == false))
        return false;

    if (daemon_is_started(&g_mcpd_hdl.mcpd_dmn_hdl, &started) && !started)
    {
        if (!daemon_start(&g_mcpd_hdl.mcpd_dmn_hdl))
        {
            LOG(ERR, "mcpd_util: failed to reload mcp");
            return false;
        }
        sleep(1);
    }
    else
    {
        if (cmd_log("mcp reload") != 0)
        {
            LOG(ERR, "mcpd_util: failed to reload mcp");
            return false;
        }
    }

    return true;
}

/*
 * Update mcpd basic params.
 * @param proxy_param Proxy configuration
 * @return true if configured
 */
bool mcpd_util_update_proxy_params(const target_mcproxy_params_t *proxy_param)
{
    if (proxy_param->protocol == DISABLE_IGMP ||
        proxy_param->protocol == IGMPv1 ||
        proxy_param->protocol == IGMPv2 ||
        proxy_param->protocol == IGMPv3)
    {
        mcpd_util_copy_proxycfg(&g_mcpd_hdl.igmp_param, proxy_param);
    } else {
        mcpd_util_copy_proxycfg(&g_mcpd_hdl.mld_param, proxy_param);
    }
    return true;
}

bool mcpd_util_update_igmp_sys_params(const struct schema_IGMP_Config *iccfg)
{
    memcpy(&g_mcpd_hdl.iccfg, iccfg, sizeof(struct schema_IGMP_Config));

    return mcpd_util_apply();
}

bool mcpd_util_update_mld_sys_params(const struct schema_MLD_Config *mlcfg)
{
    memcpy(&g_mcpd_hdl.mlcfg, mlcfg, sizeof(struct schema_MLD_Config));

    return mcpd_util_apply();
}

bool mcpd_util_update_uplink(const char *ifname, bool enable, const char *bridge)
{
    if (mcpd_util_update_tree(&g_mcpd_hdl.uplink_ifs, ifname, enable, bridge))
    {
        return mcpd_util_apply();
    }

    return true;
}

bool mcpd_util_update_snooping(const char *ifname, bool enable)
{
    if (mcpd_util_update_tree(&g_mcpd_hdl.snooping_ifs, ifname, enable, NULL))
    {
        return mcpd_util_apply();
    }

    return true;
}
