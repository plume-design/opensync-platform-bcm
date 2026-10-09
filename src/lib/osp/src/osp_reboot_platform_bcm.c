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
 *  BCM platform reboot-reason hook.
 *
 *  Implements osp_reboot_platform_check() for BCM platforms. It is used by
 *  the generic pstore reboot backend when the reboot reason could not be
 *  determined from pstore (no REBOOT line logged by any process, no kernel
 *  crash dump). On BCM the bootloader records the reset cause in the
 *  bootstate reset_status procfs entry, which lets us tell a hardware
 *  watchdog reset apart from a real power cycle / cold boot.
 * ===========================================================================
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "osp_reboot_platform.h"
#include "util.h"

/**
 * BCM bootstate reset_status proc entry.
 *
 * When the generic backend cannot determine a reboot reason, the reset was
 * caused by something that reset the SoC without giving software a chance to
 * log a reason - most likely an expired hardware watchdog. The reset_status
 * register value 0x20000000 (SW_RESET_STATUS) is what has been empirically
 * observed for this SoC on WDT expiry (as opposed to 0x80000000/POR_RESET_STATUS
 * for real power loss, and 0x40000000/HW_RESET_STATUS for the physical reset
 * button).
 */
#define BCM_RESET_STATUS_PROC "/proc/bootstate/reset_status"
#define BCM_SW_RESET_STATUS 0x20000000

/**
 * Read the BCM bootstate reset_status register value via procfs.
 *
 * Returns true and fills in *status on success (value is treated as hex,
 * with or without a leading "0x"). Returns false if the proc entry is not
 * available (e.g. platform without the bcm_bootstate driver) or cannot be
 * parsed.
 */
static bool bcm_reset_status_get(unsigned long *status)
{
    FILE *fp;
    char buf[32];
    bool retval = false;

    fp = fopen(BCM_RESET_STATUS_PROC, "r");
    if (fp == NULL)
    {
        LOG(DEBUG, "osp_reboot: %s not available: %s", BCM_RESET_STATUS_PROC, strerror(errno));
        return false;
    }

    if (fgets(buf, sizeof(buf), fp) != NULL)
    {
        char *endp = NULL;

        *status = strtoul(buf, &endp, 16);
        if (endp != NULL && endp != buf)
        {
            retval = true;
        }
        else
        {
            LOG(WARN, "osp_reboot: Error parsing %s content: %s", BCM_RESET_STATUS_PROC, buf);
        }
    }
    else
    {
        LOG(WARN, "osp_reboot: Error reading %s", BCM_RESET_STATUS_PROC);
    }

    fclose(fp);

    return retval;
}

bool osp_reboot_platform_check(enum osp_reboot_type *type, char *reason, ssize_t reason_sz)
{
    unsigned long reset_status = 0;

    if (!bcm_reset_status_get(&reset_status))
    {
        return false;
    }

    /*
     * A SW_RESET_STATUS with no reason logged means the SoC was reset by
     * something other than the reset button or a real power cycle, most likely
     * an expired hardware watchdog that fired before any process (including the
     * one feeding it) could log a reason - i.e. a hard-lockup scenario.
     */
    if (reset_status != BCM_SW_RESET_STATUS)
    {
        return true;
    }

    *type = OSP_REBOOT_WATCHDOG;
    if (reason != NULL)
    {
        strscpy(reason, "SoC WDT expired.", reason_sz);
    }

    return true;
}
