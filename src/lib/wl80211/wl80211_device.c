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
#include <string.h>

#include "os.h"
#include "os_time.h"
#include "util.h"
#include "log.h"

#include "bcmwl.h"
#include "bcmwl_ioctl.h"
#include "wl80211.h"

#define MODULE_ID LOG_MODULE_ID_WL

/******************************************************************************
 *  PROTECTED definitions
 *****************************************************************************/

/******************************************************************************
 *  PUBLIC definitions
 *****************************************************************************/

bool wl80211_device_temp_results_get(const char *phyname, int32_t *temp)
{
    char *val;

    if (!temp) {
        LOGE("Get temperature (uninitialized)");
        return false;
    }
    *temp = -1;

    if ((val = WL(phyname, "phy_tempsense")) && (val = strsep(&val, " "))) {
        *temp = atoi(val);
        if (*temp > 0)
            return true;
    }

    LOGW("Invalid temperature %s = %d", phyname, *temp);
    return false;
}

bool wl80211_device_txchainmask_get(const char *phyname, uint32_t *txchain)
{
    char *val;

    if (!txchain) {
        LOGE("Get tx chain (uninitialized)");
        return false;
    }
    *txchain = 0;

    if ((val = WL(phyname, "txchain")) && (val = strsep(&val, " "))) {
        *txchain = atoi(val);
        if (*txchain > 0)
            return true;
    }

    LOGW("Invalid txchain %s = %d", phyname, *txchain);
    return false;
}
