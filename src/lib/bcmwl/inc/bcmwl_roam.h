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

#ifndef BCMWL_ROAM_H_INCLUDED
#define BCMWL_ROAM_H_INCLUDED

#include "bcmwl_event.h"

enum bcmwl_roam_status {
    BCMWL_ROAM_DISABLED,
    BCMWL_ROAM_BUSY,
    BCMWL_ROAM_NEEDED,
    BCMWL_ROAM_MISMATCH,
    BCMWL_ROAM_COMPLETE,
};

#ifdef CONFIG_BCM_USE_NAS
void bcmwl_roam_init(const char *ifname, const char *bssid);
void bcmwl_roam_later(const char *ifname);
void bcmwl_roam_event_handler(const bcm_event_t *ev);
enum bcmwl_roam_status bcmwl_roam_get_status(const char *ifname);
#else
static inline void bcmwl_roam_init(const char *ifname, const char *bssid) { }
static inline void bcmwl_roam_later(const char *ifname) { }
static inline void bcmwl_roam_event_handler(const bcm_event_t *ev) { }
static inline enum bcmwl_roam_status bcmwl_roam_get_status(const char *ifname) { return BCMWL_ROAM_DISABLED; }
#endif

#endif /* BCMWL_ROAM_H_INCLUDED */
