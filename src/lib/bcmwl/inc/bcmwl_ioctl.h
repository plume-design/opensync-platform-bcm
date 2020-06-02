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
#include <dhdioctl.h>


struct bcmwl_ioctl_num_conv
{
    uint16_t (*dtoh16) (uint16_t);
    uint32_t (*dtoh32) (uint32_t);
    uint64_t (*dtoh64) (uint64_t);
};

struct bcmwl_ioctl_arg {
    const char *ifname;
    const char *iovar;
    const void *param; /* optional */
    void *buf; /* output buffer */
    int cmd; /* eg. WLC_GET_VAR */
    int bsscfgidx; /* used by bsscfg=1 */
    bool set; /* 0=getter 1=setter */
    bool dongle; /* for dhd iovars */
    bool bsscfg; /* eg. for ssid iovar with -C 3 */
    size_t plen; /* param len */
    size_t len; /* output buffer len */
};

bool bcmwl_ioctl_init(void);

bool bcmwl_ioctl(struct bcmwl_ioctl_arg *arg);

const struct bcmwl_ioctl_num_conv* bcmwl_ioctl_lookup_num_conv(const char *ifname);

#define bcmwl_GIOC(_ifname, _cmd, _param, _buf) \
    bcmwl_ioctl(&(struct bcmwl_ioctl_arg){ \
        .ifname = _ifname, \
        .cmd = _cmd, \
        .param = _param, \
        .plen = sizeof(*_param), \
        .buf = _buf, \
        .len = sizeof(*_buf), \
    })

#define bcmwl_SIOC(_ifname, _cmd, _param) \
    bcmwl_ioctl(&(struct bcmwl_ioctl_arg){ \
        .ifname = _ifname, \
        .cmd = _cmd, \
        .param = _param, \
        .plen = sizeof(*_param), \
        .set = true, \
    })

#define bcmwl_SIOV(_ifname, _iovar, _param) \
    bcmwl_ioctl(&(struct bcmwl_ioctl_arg){ \
        .ifname = _ifname, \
        .iovar = _iovar, \
        .cmd = WLC_SET_VAR, \
        .param = _param, \
        .plen = sizeof(*_param), \
        .set = true, \
    })

#define bcmwl_GIOV(_ifname, _iovar, _param, _buf) \
    bcmwl_ioctl(&(struct bcmwl_ioctl_arg){ \
        .ifname = _ifname, \
        .iovar = _iovar, \
        .cmd = WLC_GET_VAR, \
        .param = _param, \
        .plen = sizeof(*_param), \
        .buf = _buf, \
        .len = sizeof(*_buf), \
    })

#define bcmwl_DHDSIOV(_ifname, _iovar, _param) \
    bcmwl_ioctl(&(struct bcmwl_ioctl_arg){ \
        .ifname = _ifname, \
        .iovar = _iovar, \
        .cmd = DHD_SET_VAR, \
        .param = _param, \
        .plen = sizeof(*_param), \
        .dongle = true, \
        .set = true, \
    })

#define bcmwl_DHDGIOV(_ifname, _iovar, _param, _buf) \
    bcmwl_ioctl(&(struct bcmwl_ioctl_arg){ \
        .ifname = _ifname, \
        .iovar = _iovar, \
        .cmd = DHD_GET_VAR, \
        .param = _param, \
        .plen = sizeof(*_param), \
        .dongle = true, \
        .buf = _buf, \
        .len = sizeof(*_buf), \
    })

#define bcmwl_SIOVBSS(_ifname, _iovar, _idx, _param) \
    bcmwl_ioctl(&(struct bcmwl_ioctl_arg){ \
        .ifname = _ifname, \
        .iovar = _iovar, \
        .cmd = WLC_SET_VAR, \
        .param = _param, \
        .plen = sizeof(*_param), \
        .bsscfg = true, \
        .bsscfgidx = _idx, \
        .set = true, \
    })

#define bcmwl_GIOVBSS(_ifname, _iovar, _idx, _param, _buf) \
    bcmwl_ioctl(&(struct bcmwl_ioctl_arg){ \
        .ifname = _ifname, \
        .iovar = _iovar, \
        .cmd = WLC_GET_VAR, \
        .param = _param, \
        .plen = sizeof(*_param), \
        .bsscfg = true, \
        .bsscfgidx = _idx, \
        .buf = _buf, \
        .len = sizeof(*_buf), \
    })

#define bcmwl_DHDGIOC(_ifname, _cmd, _param, _buf) \
    bcmwl_ioctl(&(struct bcmwl_ioctl_arg){ \
        .ifname = _ifname, \
        .cmd = _cmd, \
        .param = _param, \
        .plen = sizeof(*_param), \
        .buf = _buf, \
        .len = sizeof(*_buf), \
        .dongle = true, \
    })

#define bcmwl_DHDSIOVBSS(_ifname, _iovar, _idx, _param) \
    bcmwl_ioctl(&(struct bcmwl_ioctl_arg){ \
        .ifname = _ifname, \
        .iovar = _iovar, \
        .cmd = DHD_SET_VAR, \
        .param = _param, \
        .plen = sizeof(*_param), \
        .bsscfg = true, \
        .bsscfgidx = _idx, \
        .dongle = true, \
        .set = true, \
    })

#define bcmwl_DHDGIOVBSS(_ifname, _iovar, _idx, _param, _buf) \
    bcmwl_ioctl(&(struct bcmwl_ioctl_arg){ \
        .ifname = _ifname, \
        .iovar = _iovar, \
        .cmd = DHD_GET_VAR, \
        .param = _param, \
        .plen = sizeof(*_param), \
        .bsscfg = true, \
        .bsscfgidx = _idx, \
        .dongle = true, \
        .buf = _buf, \
        .len = sizeof(*_buf), \
    })

#define BCMWL_IOCMAX_GCHANLIST ((WLC_IOCTL_MAXLEN - sizeof(int)) / sizeof(int))
#define BCMWL_IOCMAX_SCHANLIST (BCMWL_IOCMAX_GCHANLIST - (128 / sizeof(int)))
#define BCMWL_IOCMAX_GMACLIST ((WLC_IOCTL_MAXLEN - sizeof(int)) / sizeof(struct ether_addr))
#define BCMWL_IOCMAX_SMACLIST (BCMWL_IOCMAX_GMACLIST - (128 / sizeof(struct ether_addr)))

#endif /* BCMWL_IOCTL_H_INCLUDED */
