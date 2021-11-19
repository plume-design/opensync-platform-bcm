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
#include "hw_acc.h"
#include "os.h"
#include "log.h"
#include "execsh.h"
#include "kconfig.h"

#define FLOWMGR_CMD_FILE "/proc/driver/flowmgr/cmd"

bool hw_acc_flush_flow_per_mac(const char *mac) {
    char cmd[256];
    int rc;

    if (kconfig_enabled(CONFIG_BCM_FCCTL_HW_ACC))
    {
        rc = execsh_log(LOG_SEVERITY_DEBUG, _S(fcctl flush --mac "$1"), (char*)mac);
        if (rc != 0)
        {
            return false;
        }
        LOGD("fcctl: flushed mac '%s'", mac);
        return true;
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
    int rc;

    if (kconfig_enabled(CONFIG_BCM_FCCTL_HW_ACC))
    {
        rc = execsh_log(LOG_SEVERITY_DEBUG, _S(fcctl flush));
        if (rc != 0)
        {
            return false;
        }
        LOGD("fcctl: flushed all flows\n");
        return true;
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
