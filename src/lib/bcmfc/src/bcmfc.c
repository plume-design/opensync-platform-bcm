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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <stdbool.h>

#include <fcctl_api.h>
#include <fcctl.h>

#include "bcmfc.h"

static_assert(	(BCMFC_FLUSH_ACTION_ALL == FCACHE_FLUSH_ALL) 	&& \
                (BCMFC_FLUSH_ACTION_FLOW == FCACHE_FLUSH_FLOW)	&& \
                (BCMFC_FLUSH_ACTION_DEV == FCACHE_FLUSH_DEV) 	&& \
                (BCMFC_FLUSH_ACTION_MAC == FCACHE_FLUSH_MAC) 	&& \
                (BCMFC_FLUSH_ACTION_DSTMAC == FCACHE_FLUSH_DSTMAC) && \
                (BCMFC_FLUSH_ACTION_SRCMAC == FCACHE_FLUSH_SRCMAC) && \
                (BCMFC_FLUSH_ACTION_HW == FCACHE_FLUSH_HW), "Err: fcctl flush enum mismatch");

int bcmfc_enable(bool enable)
{
    return (enable) ? fcCtlEnable() : fcCtlDisable();
}

int bcmfc_flush(void)
{
    return fcCtlFlush(0);
}

int bcmfc_flush_flow(int flowid)
{
    return fcCtlFlush(flowid);
}

int bcmfc_flush_device(int device)
{
    FcFlushParams_t fc = {0};
    fc.devid = device;
    fc.flags = FCACHE_FLUSH_DEV;

    return fcCtlFlushParams(&fc);
}


int bcmfc_flush_per_mac(uint8_t* mac)
{
    assert(mac);

    FcFlushParams_t fc = {0};
    fc.flags = FCACHE_FLUSH_MAC;
    memcpy(fc.mac, mac, 6);

    return fcCtlFlushParams(&fc);
}

int bcmfc_flush_params(struct bcmfc_flush_t *params)
{
    assert(params);

    FcFlushParams_t fc;
    fc.flags  = (uint32_t)params->action;
    fc.devid  = params->devid;
    fc.flowid = params->flowid;

    if (params->action & BCMFC_FLUSH_ACTION_MAC)
        memcpy(fc.mac, params->mac, 6);

    return fcCtlFlushParams(&fc);
}
