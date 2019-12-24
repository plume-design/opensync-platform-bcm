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

#ifndef BCMWL_IOCTL_H_INCLUDED
#define BCMWL_IOCTL_H_INCLUDED

#include <stdint.h>

#include "bcmwl_priv.h"
#include <wlioctl.h>


struct bcmwl_ioctl_num_conv
{
    uint16_t (*dtoh16) (uint16_t);
    uint32_t (*dtoh32) (uint32_t);
    uint64_t (*dtoh64) (uint64_t);
};

bool bcmwl_ioctl_init(void);

const struct bcmwl_ioctl_num_conv* bcmwl_ioctl_lookup_num_conv(const char *ifname);

bool bcmwl_ioctl_prepare_args_with_addr(void *buf,
                                        size_t buf_size,
                                        const char *wl_cmd,
                                        const os_macaddr_t *hwaddr);

bool bcmwl_ioctl_set(const char *ifname,
                     unsigned int ioctl_cmd,
                     const void *buf,
                     size_t buf_size);

bool bcmwl_ioctl_get(const char *ifname,
                     unsigned int ioctl_cmd,
                     void *buf,
                     size_t buf_size);

#endif /* BCMWL_IOCTL_H_INCLUDED */
