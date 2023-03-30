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

/**
 * libbcmfc - thin wrapper of fcctl_api for flow-cache
 * This wrapper resolves problem with the include files conflicts.
 *
 */
#ifndef BCMFC_H_INCLUDED
#define BCMFC_H_INCLUDED

enum bcmfc_flush_action {
    BCMFC_FLUSH_ACTION_ALL    = (1 << 0),
    BCMFC_FLUSH_ACTION_FLOW   = (1 << 1),
    BCMFC_FLUSH_ACTION_DEV    = (1 << 2),
    BCMFC_FLUSH_ACTION_DSTMAC = (1 << 3),
    BCMFC_FLUSH_ACTION_SRCMAC = (1 << 4),
    BCMFC_FLUSH_ACTION_HW     = (1 << 5),
    BCMFC_FLUSH_ACTION_MAC    =  BCMFC_FLUSH_ACTION_DSTMAC | BCMFC_FLUSH_ACTION_SRCMAC,
};

struct bcmfc_flush_t{
    enum bcmfc_flush_action action;
    uint8_t mac[6];
    int devid;
    int flowid;
};

int bcmfc_enable(bool enable);

int bcmfc_flush(void);
int bcmfc_flush_flow(int fc_flowid);
int bcmfc_flush_device(int device);
int bcmfc_flush_per_mac(uint8_t* mac);
int bcmfc_flush_params(struct bcmfc_flush_t *params);

#endif /* BCMFC_H_INCLUDED */
