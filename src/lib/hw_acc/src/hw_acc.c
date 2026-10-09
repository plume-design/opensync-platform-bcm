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
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include "bcmfc.h"
#include "hw_acc.h"
#include "hw_acc_helpers.h"
#include "os.h"
#include "log.h"
#include "execsh.h"
#include "kconfig.h"

#define FLOWMGR_CMD_FILE "/proc/driver/flowmgr/cmd"

/* Max length example */
/* aaaa:bbbb:cccc:0000:0000:dddd:eeee:ffff:12345 */
/* 45 characters + null terminator */
#define MAX_ADDR_PORT_LEN 48

struct flow_str_tuple
{
    char original_src[MAX_ADDR_PORT_LEN];
    char original_dst[MAX_ADDR_PORT_LEN];
    char reply_src[MAX_ADDR_PORT_LEN];
    char reply_dst[MAX_ADDR_PORT_LEN];
    bool reply_valid;
};

// static bool hw_acc_flush_line_cb(void *ctx, enum execsh_io type, const char *line)
static void hw_acc_flush_flows_in_file(const char *file_path, struct flow_str_tuple *tuple)
{
    char line[2048] = {};

    FILE *file = fopen(file_path, "r");
    if (file)
    {
        while (fgets(line, sizeof(line), file))
        {
            bool flush = false;

            if (strstr(line, tuple->original_src) != NULL && strstr(line, tuple->original_dst) != NULL)
            {
                LOGD("hw_acc_flush_line_cb: matched: %s -> %s\n", tuple->original_src, tuple->original_dst);
                flush = true;
            }
            else if (tuple->reply_valid && strstr(line, tuple->reply_src) != NULL && strstr(line, tuple->reply_dst) != NULL)
            {
                LOGD("hw_acc_flush_line_cb: matched: %s -> %s\n", tuple->reply_src, tuple->reply_dst);
                flush = true;
            }

            /* Check if line contains both source and destination addresses and ports */
            if (flush)
            {
                /* Flush this flow */
                errno = 0;
                unsigned long flowid = strtoul(line, NULL, 10);
                if (errno == 0)
                {
                    LOGD("hw_acc_flush_line_cb: matched flowid %lu\n", flowid);
                    bcmfc_flush_flow(flowid);
                }
                else
                    LOGE("hw_acc_flush_line_cb: Unable to parse flowid from line: '%s'\n", line);
            }
        }

        fclose(file);
    }
}

/* Print flow IP address and port to string */
static void hw_acc_format_addr_port(char *dst, uint8_t version, const uint8_t *addr, uint16_t port)
{
    if (version == 6)
    {
        /* Example IPv6 flow from /proc/fcache/nflist */
        /* <2001:0ee2:a2b5:8870:0000:0000:0000:1ab0:38602><2001:0ee2:a2b5:8870:0000:0000:0000:0001:5201> */
        snprintf(dst, MAX_ADDR_PORT_LEN,
                 "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%u",
                 addr[0], addr[1], addr[2], addr[3],
                 addr[4], addr[5], addr[6], addr[7],
                 addr[8], addr[9], addr[10], addr[11],
                 addr[12], addr[13], addr[14], addr[15],
                 port);
    }
    else
    {
        /* Example IPv4 flow from /proc/fcache/nflist */
        /* <034.211.126.134:00443> <192.168.200.101:32966> */
        snprintf(dst, MAX_ADDR_PORT_LEN,
                 "%03u.%03u.%03u.%03u:%05u",
                 addr[0], addr[1], addr[2], addr[3],
                 port);
    }
}

bool hw_acc_flush_flow_per_tuple(struct hw_acc_flush_flow_t *flow)
{
    struct flow_str_tuple str_tuple = {0};

    hw_acc_format_addr_port(str_tuple.original_src, flow->ip_version, flow->src_ip, flow->src_port);
    hw_acc_format_addr_port(str_tuple.original_dst, flow->ip_version, flow->dst_ip, flow->dst_port);
    LOGD("hw_acc_flush_flow_per_tuple: flushing flow: %s -> %s\n", str_tuple.original_src, str_tuple.original_dst);

    hw_acc_flush_flows_in_file("/proc/fcache/nflist", &str_tuple);
    hw_acc_flush_flows_in_file("/proc/fcache/brlist", &str_tuple);

    return true;
}

bool hw_acc_flush_flow_per_connection(struct hw_acc_flush_flow_t *flow)
{
    struct hw_acc_flush_flow_t original;
    struct hw_acc_flush_flow_t reply;
    struct flow_str_tuple str_tuple = {0};

    if (hw_acc_lookup_ct_entry(flow, &original, &reply))
    {
        /* Flush using ct entry info */
        hw_acc_format_addr_port(str_tuple.original_src, original.ip_version, original.src_ip, original.src_port);
        hw_acc_format_addr_port(str_tuple.original_dst, original.ip_version, original.dst_ip, original.dst_port);
        hw_acc_format_addr_port(str_tuple.reply_src, reply.ip_version, reply.dst_ip, reply.dst_port);
        hw_acc_format_addr_port(str_tuple.reply_dst, reply.ip_version, reply.src_ip, reply.src_port);
    }
    else
    {
        /* Naive flush (swap reply direction tuple) */
        hw_acc_format_addr_port(str_tuple.original_src, flow->ip_version, flow->src_ip, flow->src_port);
        hw_acc_format_addr_port(str_tuple.original_dst, flow->ip_version, flow->dst_ip, flow->dst_port);
        hw_acc_format_addr_port(str_tuple.reply_src, flow->ip_version, flow->dst_ip, flow->dst_port);
        hw_acc_format_addr_port(str_tuple.reply_dst, flow->ip_version, flow->src_ip, flow->src_port);
    }
    str_tuple.reply_valid = true;

    LOGD("hw_acc_flush_flow_per_connection: flushing flows: original %s -> %s, reply %s -> %s\n",
         str_tuple.original_src, str_tuple.original_dst, str_tuple.reply_src, str_tuple.reply_dst);

    hw_acc_flush_flows_in_file("/proc/fcache/nflist", &str_tuple);
    hw_acc_flush_flows_in_file("/proc/fcache/brlist", &str_tuple);

    return true;
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

bool hw_acc_mode_set(hw_acc_ctrl_flags_t flags)
{
    if (flags & HW_ACC_F_DISABLE_ACCEL)
    {
        hw_acc_disable();
    }
    else
    {
        hw_acc_enable();
    }
    return true;
}
