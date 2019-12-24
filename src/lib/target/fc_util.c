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
#include <stdio.h>
#include <string.h>

#include "os.h"
#include "log.h"

#include "target.h"

#define MODULE_ID LOG_MODULE_ID_TARGET

static void fc_cache_invalidate(const char *openflow_rule)
{
    char        *flow       = strdupa(openflow_rule);
    char        *ptr        = NULL;
    const char  *k          = NULL;
    const char  *v          = NULL;
    bool        flushed_mac = false;

    /* Openflow rules are of the type
     * "udp6,tp_dst=53,dl_src=a4:e9:75:48:a3:7f,dl_dst=aa:bb:cc:dd:ee:ff"
     * "tcp,tp_dst=80,dl_src=ff:ff:ff:ff:ff:ff" */
    while ((ptr = strsep(&flow, ",")))
        if ((k = strsep(&ptr, "=")) && (v = strsep(&ptr, "")))
            if (!strcmp(k, "dl_src") || !strcmp(k, "dl_dst"))
                if (!WARN_ON(!strexa("fcctl", "flush", "--mac", v)))
                {
                    LOGI("fcctl: flushed mac '%s'", v);
                    flushed_mac = true;
                }

    /* If no mac addresses were found in the openflow rule,
     * flush all fcctl flows */
    if (!flushed_mac)
        if (!WARN_ON(!strexa("fcctl", "flush")))
            LOGD("fcctl: flushed all flows");
}

bool target_om_hook(target_om_hook_t hook, const char *openflow_rule)
{
    switch (hook)
    {
        case TARGET_OM_POST_ADD:
        case TARGET_OM_POST_DEL:
        {
            fc_cache_invalidate(openflow_rule);
            break;
        }

        case TARGET_OM_PRE_ADD:
        case TARGET_OM_PRE_DEL:
            break;

        default:
            break;
    }

    return true;
}
