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

#ifndef BCMWL_EVENT_H_INCLUDED
#define BCMWL_EVENT_H_INCLUDED

#include <ev.h>
#include <stdbool.h>
#include <string.h>

#include "bcmwl_priv.h"

#include "os_types.h"


// Events handling
#define BCMWL_EVENT_MASK_BITS_SIZE ((WLC_E_LAST / 8) + 1)

#define BCMWL_EVENT_HANDLED true
#define BCMWL_EVENT_CONTINUE false

typedef bool bcmwl_event_cb_t(const char *ifname, os_macaddr_t *client, void  *event);

typedef struct {
   uint8_t bits[BCMWL_EVENT_MASK_BITS_SIZE];
} bcmwl_event_mask_t;

void    bcmwl_event_init(void);
bool    bcmwl_event_register(struct ev_loop *evloop, const char *ifname, bcmwl_event_cb_t cb);
void    bcmwl_event_unregister(struct ev_loop *evloop, const char *ifname, bcmwl_event_cb_t cb);
bool    bcmwl_event_handler(const char *ifname,
                            os_macaddr_t *hwaddr,
                            void *event);
void    bcmwl_event_setup_extra_cb(bcmwl_event_cb_t cb);
int     bcmwl_event_socket_open(const char *ifname);
int     bcmwl_event_socket_close(int fd);
void    bcmwl_event_discard_probereq(void);
ssize_t bcmwl_event_msg_read(int fd, void *msg, size_t msglen);


bool bcmwl_event_mask_get(const char *ifname, bcmwl_event_mask_t *mask);
bool bcmwl_event_mask_set(const char *ifname,
                          const bcmwl_event_mask_t *mask);
void bcmwl_event_mask_bit_set(bcmwl_event_mask_t *mask, unsigned int bit);
void bcmwl_event_mask_bit_unset(bcmwl_event_mask_t *mask, unsigned int bit);
bool bcmwl_event_mask_bit_isset(bcmwl_event_mask_t *mask, unsigned int bit);
bool bcmwl_event_enable(const char *ifname, unsigned int bit);
void bcmwl_event_enable_all(unsigned int bit);

#endif /* BCMWL_EVENT_H_INCLUDED */
