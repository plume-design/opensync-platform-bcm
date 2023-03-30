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
 * Flow Cache utilities
 */

#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include "bcmfc.h"
#include "hw_acc.h"
#include "os.h"
#include "log.h"
#include "execsh.h"
#include "kconfig.h"

#define FLOWMGR_CMD_FILE "/proc/driver/flowmgr/cmd"

static void hw_acc_print_flow(char *note, int *flow_id, struct hw_acc_flush_flow_t *flow)
{
    LOGD("%s (%d) %s", note, (flow_id) ? *flow_id : -1, \
        strfmta("%u, %u (%02x:%02x:%02x:%02x:%02x:%02x)@%u.%u.%u.%u:%u -> (%02x:%02x:%02x:%02x:%02x:%02x)@%u.%u.%u.%u:%u", \
        flow->protocol,flow->ip_version, \
        flow->src_mac[0], flow->src_mac[1], flow->src_mac[2], flow->src_mac[3], flow->src_mac[4], flow->src_mac[5], \
        flow->src_ip[0], flow->src_ip[1], flow->src_ip[2], flow->src_ip[3], \
        flow->src_port, \
        flow->dst_mac[0], flow->dst_mac[1], flow->dst_mac[2], flow->dst_mac[3], flow->dst_mac[4], flow->dst_mac[5], \
        flow->dst_ip[0], flow->dst_ip[1], flow->dst_ip[2], flow->dst_ip[3], \
        flow->dst_port));
}

bool hw_acc_flush(struct hw_acc_flush_flow_t *flow)
{
    const char* s;
    const char* p;
    int flowid;
    struct hw_acc_flush_flow_t flow_entry = {0};

    hw_acc_print_flow("hw_acc_flush: target_flow:", NULL, flow);

    if(flow->ip_version == 6)
    {
        LOGD("hw_acc_flush: IPv6 -> flushing all (TODO!)");
        return bcmfc_flush();
    }

    char *flows = strexa("cat", "/proc/fcache/nflist", "/proc/fcache/brlist") ?: "";
    char *line = strstr(flows, "\n\n");
    while (line)
    {
        s = strchr(line, '@');
        p = strchr(line, '<');

        if (s && p)
        {
            //find out how long is the protocol id
            p -= 3;
            while ((*p != ' ') && (p > line)) { p--; }

            if (sscanf(s+1, "%06d", &flowid) == 1)
            {
                if (sscanf((p+1), "%d  <%03u.%03u.%03u.%03u:%05u> <%03u.%03u.%03u.%03u:%05u>", \
                        (uint *)&flow_entry.protocol, \
                        (uint *)&flow_entry.src_ip[0], (uint *)&flow_entry.src_ip[1], (uint *)&flow_entry.src_ip[2], (uint *)&flow_entry.src_ip[3],
                        (uint *)&flow_entry.src_port, \
                        (uint *)&flow_entry.dst_ip[0], (uint *)&flow_entry.dst_ip[1], (uint *)&flow_entry.dst_ip[2], (uint *)&flow_entry.dst_ip[3],
                        (uint *)&flow_entry.dst_port) == 11)
                {
                    if (flow_entry.protocol == flow->protocol)
                    {
                        /**
                         * Try and find full match from lan -> wan
                         */
                        if ((flow_entry.src_port == flow->src_port) && (flow_entry.dst_port == flow->dst_port) &&
                            !memcmp(flow_entry.src_ip, flow->src_ip, 4) && \
                            !memcmp(flow_entry.dst_ip, flow->dst_ip, 4))
                        {
                            hw_acc_print_flow("hw_acc_flush: flush_exact:", &flowid, &flow_entry);
                            bcmfc_flush_flow(flowid);
                        }

                        /**
                         * now try and find reverse flow, before nat(), where dst should be our wan IP
                         */
                        else if ((flow_entry.src_port == flow->dst_port) && (flow_entry.dst_port == flow->src_port) &&
                            //!memcmp(flow_entry.src_ip, flow->src_ip, 4) &&
                            !memcmp(flow_entry.dst_ip, flow->src_ip, 4))
                        {
                            hw_acc_print_flow("hw_acc_flush: flush_partial:", &flowid, &flow_entry);
                            bcmfc_flush_flow(flowid);
                        }
                    }

                }
            }
        }
        else
        {
            break;
        }

        line = strstr(s, "\n\n");
    }

    return true;
}

bool hw_acc_flush_flow_per_device(int devid)
{
    return bcmfc_flush_device(devid);
}


bool hw_acc_flush_flow_per_mac(const char *mac) {
    char cmd[256];
    bool rc;

    if (kconfig_enabled(CONFIG_BCM_FCCTL_HW_ACC))
    {
        uint8_t macb[6] = {0};
        sscanf(mac, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", \
           &macb[0], &macb[1],&macb[2], &macb[3], &macb[4], &macb[5]);

        rc = (bcmfc_flush_per_mac(macb) == 0) ? true : false;

        LOGD("fcctl: flush mac %s: %s ", \
            strfmta("%02x:%02x:%02x:%02x:%02x:%02x", macb[0], macb[1], macb[2], macb[3], macb[4], macb[5]), \
            (rc == true) ? "OK" : "FAILED");

        return rc;
    }
    if (kconfig_enabled(CONFIG_BCM_FLOW_MGR_HW_ACC))
    {
        snprintf(cmd, sizeof(cmd), "flow_flushmac %s", mac);
        if (file_put(FLOWMGR_CMD_FILE, cmd) == -1)
        {
            return false;
        }
        LOGD("flow_mgr: flushed mac '%s'", mac);
        return true;
    }

    LOGW("hw_acc: hardware acceleration not enabled\n");
    return false;
}

bool hw_acc_flush_all_flows(void)
{
    char cmd[256];
    bool rc;

    if (kconfig_enabled(CONFIG_BCM_FCCTL_HW_ACC))
    {
        rc = (bcmfc_flush() == 0) ? true : false;

        LOGD("fcctl: flush all flows: %s ", (rc == true) ? "OK" : "FAILED");
        return rc;
    }
    if (kconfig_enabled(CONFIG_BCM_FLOW_MGR_HW_ACC))
    {
        snprintf(cmd, sizeof(cmd), "flow_delall");
        if (file_put(FLOWMGR_CMD_FILE, cmd) == -1)
        {
            return false;
        }
        LOGD("flow_mgr: flushed all flows\n");
        return true;
    }

    LOGW("hw_acc: hardware acceleration not enabled\n");
    return false;
}

void hw_acc_config(bool enable)
{
    int err;
    if (kconfig_enabled(CONFIG_BCM_FCCTL_HW_ACC))
    {
        err = bcmfc_enable(enable);
        LOGD("fcctl: %s hw acc %s\n", \
            (enable) ? "enabled" : "disabled", \
            (err == 0) ? "OK" : "FAILED");
    }
    if (kconfig_enabled(CONFIG_BCM_FLOW_MGR_HW_ACC))
    {
        LOGW("Not implemented for CONFIG_BCM_FLOW_MGR_HW_ACC devices.");
    }
}

void hw_acc_enable()
{
    hw_acc_config(true);
}

void hw_acc_disable()
{
    hw_acc_config(false);
    hw_acc_flush_all_flows();
}
