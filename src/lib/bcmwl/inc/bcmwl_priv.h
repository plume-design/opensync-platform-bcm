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

#ifndef BCMWL_PRIV_H_INCLUDED
#define BCMWL_PRIV_H_INCLUDED

// Need to define TYPEDEF_BOOL so that bool is not redefined in ethernet.h
#define TYPEDEF_BOOL
#include <stdbool.h>

#if defined(USE_ALTERNATE_BCM_DRIVER_PATHS)
    #include "ethernet.h"
    #include "bcmevent.h"
    #include "wlioctl_defs.h"
#else
    #include "proto/ethernet.h"
    #include "proto/bcmevent.h"
    #include "devctrl_if/wlioctl_defs.h"
#endif

#include <wlioctl.h>

// old driver compatibility
#ifndef WLC_E_IF_BSSCFG_UP
#define WLC_E_IF_BSSCFG_UP	4	/* bsscfg up */
#endif

#ifndef WLC_E_IF_BSSCFG_DOWN
#define WLC_E_IF_BSSCFG_DOWN	5	/* bsscfg down */
#endif


#endif /* BCMWL_PRIV_H_INCLUDED */
