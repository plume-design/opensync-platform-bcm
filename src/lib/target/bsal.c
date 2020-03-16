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
#include <errno.h>
#include <time.h>
#include <limits.h>
#include <arpa/inet.h>

#if defined(USE_ALTERNATE_BCM_DRIVER_PATHS)
    #include "ethernet.h"
    #include "bcmevent.h"
    #include "802.11.h"
#else
    #include "proto/ethernet.h"
    #include "proto/bcmevent.h"
    #include "proto/802.11.h"
#endif

#include "target.h"
#include "bcmwl_debounce.h"
#include "bcmwl_nvram.h"
#include "bcmwl.h"
#include "target_bsal.h"
#include "bcm_bsal.h"

static struct ev_loop *_ev_loop = NULL;

int
target_bsal_init(bsal_event_cb_t callback,
                 struct ev_loop *loop)
{
    bool res;

    /* TODO: Add multiple ifaces */
    res = bcm_bsal_init(loop, callback);
    if (res) {
        _ev_loop = loop;
    }

    return (res ? 0 : -1);
}

int
target_bsal_cleanup(void)
{
    bool res;

    res = bcm_bsal_finalize(_ev_loop);
    _ev_loop = NULL;

    return (res ? 0 : -1);
}

int
target_bsal_iface_add(const bsal_ifconfig_t *ifcfg)
{
    return bcm_bsal_iface_add(ifcfg) ? 0 : -1;
}

int
target_bsal_iface_update(const bsal_ifconfig_t *ifcfg)
{
    return bcm_bsal_iface_update(ifcfg) ? 0 : -1;
}

int
target_bsal_iface_remove(const bsal_ifconfig_t *ifcfg)
{
    return bcm_bsal_iface_remove(ifcfg) ? 0 : -1;
}

int
target_bsal_client_add(const char *ifname, const uint8_t *mac_addr, const bsal_client_config_t *conf)
{
    return bcm_bsal_add_client(ifname, mac_addr, conf) ? 0 : -1;
}

int
target_bsal_client_update(const char *ifname, const uint8_t *mac_addr, const bsal_client_config_t *conf)
{
    return bcm_bsal_update_client(ifname, mac_addr, conf) ? 0 : -1;
}

int
target_bsal_client_remove(const char *ifname, const uint8_t *mac_addr)
{
    return bcm_bsal_remove_client(ifname, mac_addr) ? 0 : -1;
}

int
target_bsal_client_measure(const char *ifname, const uint8_t *mac_addr, int num_samples)
{
    return bcm_bsal_client_measure(ifname, mac_addr, num_samples) ? 0 : -1;
}

int
target_bsal_client_disconnect(const char *ifname, const uint8_t *mac_addr, bsal_disc_type_t type, uint8_t reason)
{
    return bcm_bsal_client_disconnect(ifname, mac_addr, type, reason) ? 0 : -1;
}

int
target_bsal_client_info(const char *ifname, const uint8_t *mac_addr, bsal_client_info_t *info)
{
    return bcm_bsal_client_info(ifname, mac_addr, info) ? 0 : -1;
}

int
target_bsal_bss_tm_request(const char *ifname, const uint8_t *mac_addr, const bsal_btm_params_t *btm_params)
{
    return bcm_bsal_bss_tm_request(ifname, mac_addr, btm_params) ? 0 : -1;
}

int
target_bsal_rrm_beacon_report_request(const char *ifname, const uint8_t *mac_addr, const bsal_rrm_params_t *rrm_params)
{
    return bcm_bsal_rrm_beacon_report_request(ifname, mac_addr, rrm_params) ? 0 : -1;
}

int
target_bsal_rrm_set_neighbor(const char *ifname, const bsal_neigh_info_t *nr)
{
    return bcm_bsal_rrm_set_neighbor(ifname, nr) ? 0 : -1;
}

int
target_bsal_rrm_remove_neighbor(const char *ifname, const bsal_neigh_info_t *nr)
{
    return bcm_bsal_rrm_remove_neighbor(ifname, nr) ? 0 : -1;
}

int
target_bsal_send_action(const char *ifname, const uint8_t *mac_addr, const uint8_t *data, unsigned int data_len)
{
    return bcm_bsal_send_action(ifname, mac_addr, data, data_len) ? 0 : -1;
}
