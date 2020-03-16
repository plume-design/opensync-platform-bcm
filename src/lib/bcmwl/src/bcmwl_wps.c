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

#include <sys/types.h>
#include <string.h>
#include <glob.h>

/* internal */
#include <log.h>
#include <schema_consts.h>
#include <bcmwl.h>
#include <bcmwl_wps.h>
#include <bcmwl_nvram.h>
#include <kconfig.h>

#if defined(CONFIG_TARGET_LAN_BRIDGE_NAME)
#define BCMWL_WPS_LAN_BRIDGE   CONFIG_TARGET_LAN_BRIDGE_NAME
#else
#define BCMWL_WPS_LAN_BRIDGE   SCHEMA_CONSTS_BR_NAME_HOME
#endif

#if defined(CONFIG_BCM_WPS_PROCESS)
#define BCMWL_WPS_PROCESS   CONFIG_BCM_WPS_PROCESS
#else
#define BCMWL_WPS_PROCESS   "wps_monitor"
#endif

#if defined(CONFIG_BCM_WPS_PID)
#define BCMWL_WPS_PID   CONFIG_BCM_WPS_PID
#else
#define BCMWL_WPS_PID   "/tmp/wps_monitor.pid"
#endif

#if defined(CONFIG_BCM_WPS_INTERFACE_LIST)
static const char *bcmwl_wps_iflist[] =
    {
#if defined(CONFIG_BCM_WPS_INTERFACE0_LIST)
        CONFIG_BCM_WPS_INTERFACE0_NAME,
#endif
#if defined(CONFIG_BCM_WPS_INTERFACE1_LIST)
        CONFIG_BCM_WPS_INTERFACE1_NAME,
#endif
#if defined(CONFIG_BCM_WPS_INTERFACE2_LIST)
        CONFIG_BCM_WPS_INTERFACE2_NAME,
#endif
#if defined(CONFIG_BCM_WPS_INTERFACE3_LIST)
        CONFIG_BCM_WPS_INTERFACE3_NAME
#endif
    };
#else
static const char *bcmwl_wps_iflist[] =
    {
        "wl0.2",
        "wl1.2"
    };
#endif


static int bcmwl_wps_configured_on_ifname(const char *ifname)
{
    if (WARN_ON(!ifname))
        return 0;
    if (strcmp(NVG(ifname, "wps_mode") ?: "", "enabled"))
        return 0;
    if (atoi(NVG(ifname, "wps_proc_status") ?: "-1") < 0)
        return 0;
    if ((atoi(NVG(ifname, "radio") ?: "0") |
         atoi(NVG(ifname, "bss_enabled") ?: "0")) != 1)
        return 0;
    if (!strlen(NVG(ifname, "ifname") ?: ""))
        return 0;
    if (!strlen(NVG(ifname, "hwaddr") ?: ""))
        return 0;

    return 1;
}

bool bcmwl_wps_configured(void)
{
    int needed = 0;
    glob_t g;
    size_t i;

    if (WARN_ON(glob("/sys/class/net/*", 0, NULL, &g)))
        return 0;

    for (i = 0; i < g.gl_pathc; i++) {
        if (bcmwl_wps_configured_on_ifname(basename(g.gl_pathv[i]))) {
            needed = 1;
            break;
        }
    }

    globfree(&g);
    return needed;
}

bool bcmwl_wps_enabled(void)
{
    if (!kconfig_enabled(CONFIG_BCM_WPS)) {
        LOGD("WPS disabled");
        return false;
    }
    return true;
}

bool bcmwl_wps_init(void)
{
    uint8_t     i;

    if (!bcmwl_wps_enabled())
        return true;

    LOGI("Initialize WPS");

    assert(strexa("which", BCMWL_WPS_PROCESS));

    /* NVRAM settings that should be permanently stored in eNVRAM */
    if (WARN_ON(!NVS("wps", "mode", "enabled")))
        return false;
    if (WARN_ON(!NVS("wps", "aplockdown", "0")))
        return false;
    if (WARN_ON(!NVS("wps", "autho_sta_mac", "00:00:00:00:00:00")))
        return false;
    if (WARN_ON(!NVS("wps", "config_command", "0")))
        return false;
    if (WARN_ON(!NVS("wps", "config_method", "0x284")))
        return false;
    if (WARN_ON(!NVS("wps", "device_name", "BroadcomAP")))
        return false;
    if (WARN_ON(!NVS("wps", "method", "1")))
        return false;
    if (WARN_ON(!NVS("wps", "mfstring", "Broadcom")))
        return false;
    if (WARN_ON(!NVS("wps", "modelname", "Broadcom")))
        return false;
    if (WARN_ON(!NVS("wps", "modelnum", "123456")))
        return false;
    if (WARN_ON(!NVS("wps", "proc_mac", "")))
        return false;
    if (WARN_ON(!NVS("wps", "restart", "0")))
        return false;
    if (WARN_ON(!NVS("wps", "sta_pin", "00000000")))
        return false;
    if (WARN_ON(!NVS("wps", "status", "0")))
        return false;
    if (WARN_ON(!NVS("wps", "timeout_enable", "0")))
        return false;
    if (WARN_ON(!NVS("wps", "version2", "enabled")))
        return false;
    if (WARN_ON(!NVS("wps", "wer_mode", "deny")))
        return false;
    if (WARN_ON(!NVS("wps", "proc_status", "0")))
        return false;

    /* TODO:
     * These settings should be set via cloud/OVSDB, as they are specific
     * to numbering of VIF's. As a temporary fix they are defined through kconfig */

    for (i = 0; i < sizeof(bcmwl_wps_iflist)/sizeof(char*); i++) {
        LOGI("Set WPS on %s", bcmwl_wps_iflist[i]);
        if (WARN_ON(!NVS(bcmwl_wps_iflist[i], "wps_mode", "enabled")))
            return false;
        if (WARN_ON(!NVS(bcmwl_wps_iflist[i], "wps_reg", "enabled")))
            return false;
        if (WARN_ON(!NVS(bcmwl_wps_iflist[i], "wps_config_state", "1")))
            return false;
    }

    /* TODO */
    if (WARN_ON(!NVS("lan", "wps_oob", "disabled")))
        return false;
    if (WARN_ON(!NVS("lan", "wps_reg", "enabled")))
        return false;
    if (WARN_ON(!NVS("wl", "wps_mode", "enabled")))
        return false;
    if (WARN_ON(!NVS("wps", "ifname", BCMWL_WPS_LAN_BRIDGE)))
        return false;

    return true;
}

bool bcmwl_wps_set_on_state_change_script(const char *wps_script)
{
    if (!bcmwl_wps_enabled())
        return true;

    if (WARN_ON(!NVS("wps", "on_state_change_script", wps_script)))
        return false;

    return true;
}

bool bcmwl_wps_restart(void)
{
    if (!bcmwl_wps_enabled())
        return true;
    if (!bcmwl_wps_configured())
        return true;

    LOGI("Restarting WPS");
    strexa("killall", "-KILL", BCMWL_WPS_PROCESS);
    strexa("rm", BCMWL_WPS_PID);
    bcmwl_system_start_closefd(BCMWL_WPS_PROCESS " &");

    return true;
}

char* bcmwl_wps_process_name(void)
{
    return BCMWL_WPS_PROCESS;
}
