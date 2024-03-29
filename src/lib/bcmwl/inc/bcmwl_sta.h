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

#ifndef BCMWL_STA_H_INCLUDED
#define BCMWL_STA_H_INCLUDED

#include <stdint.h>

#include "bcmwl_priv.h"
#include "bcmwl_ioctl.h"


// STA handling
typedef struct
{
    bool is_authorized;
    uint16_t capabilities;
    uint64_t rx_total_bytes;
    uint64_t tx_total_bytes;
    uint64_t rx_total_pkts;
    uint64_t tx_total_pkts;
    uint64_t rx_total_retries;
    uint64_t tx_total_retries;
    bool is_btm_supported;
    uint8_t rrm_caps[DOT11_RRM_CAP_LEN];
    int rssi;
    int nf;
    bool multi_ap;
    uint8_t max_chwidth;
    uint8_t max_streams;
    uint8_t max_mcs;
} bcmwl_sta_info_t;

bool bcmwl_sta_get_sta_info(const char *ifname,
                            const os_macaddr_t *hwaddr,
                            bcmwl_sta_info_t *sta_info);

#endif /* BCMWL_STA_H_INCLUDED */
