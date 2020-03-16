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

#ifndef BCM_BSAL_H_INCLUDED
#define BCM_BSAL_H_INCLUDED

bool bcm_bsal_init(
        struct ev_loop *loop,
        bsal_event_cb_t callback);

bool bcm_bsal_finalize(struct ev_loop *loop);

bool bcm_bsal_iface_add(const bsal_ifconfig_t *ifcfg);
bool bcm_bsal_iface_update(const bsal_ifconfig_t *ifcfg);
bool bcm_bsal_iface_remove(const bsal_ifconfig_t *ifcfg);

bool bcm_bsal_add_client(
        const char *ifname,
        const uint8_t *client_hwaddr,
        const bsal_client_config_t *client_conf);

bool bcm_bsal_update_client(
        const char *ifname,
        const uint8_t *mac_addr,
        const bsal_client_config_t *conf);

bool bcm_bsal_remove_client(
        const char *ifname,
        const uint8_t *mac_addr);


bool bcm_bsal_client_measure(
        const char *ifname,
        const uint8_t *mac_addr,
        int num_samples);

bool bcm_bsal_client_disconnect(
        const char *ifname,
        const uint8_t *mac_addr,
        bsal_disc_type_t type,
        uint8_t reason);

bool bcm_bsal_client_info(
        const char *ifname,
        const uint8_t *mac_addr,
        bsal_client_info_t *info);


bool bcm_bsal_bss_tm_request(
        const char *ifname,
        const uint8_t *mac_addr,
        const bsal_btm_params_t *btm_params);

bool bcm_bsal_rrm_beacon_report_request(
        const char *ifname,
        const uint8_t *mac_addr,
        const bsal_rrm_params_t *rrm_params);


bool bcm_bsal_rrm_set_neighbor(
        const char *ifname,
        const bsal_neigh_info_t *nr);

bool bcm_bsal_rrm_remove_neighbor(
        const char *ifname,
        const bsal_neigh_info_t *nr);

bool bcm_bsal_send_action(
        const char *ifname,
        const uint8_t *mac_addr,
        const uint8_t *data,
        unsigned int data_len);

#endif /* BCM_BSAL_H_INCLUDED */
