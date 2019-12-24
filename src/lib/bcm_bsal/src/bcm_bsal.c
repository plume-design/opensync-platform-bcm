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

/*
 * Band Steering Abstraction Layer - BCM
 */

#define _GNU_SOURCE
#include <errno.h>
#include <time.h>
#include <endian.h>
#include <limits.h>
#include <arpa/inet.h>

#include "proto/ethernet.h"
#include "proto/bcmevent.h"
#include "proto/802.11.h"

#include "target.h"
#include "bcmwl_debounce.h"
#include "bcmwl_nvram.h"
#include "bcmwl.h"
#include "const.h"

bool bcm_bsal_finalize(struct ev_loop *loop, const char *ifnames[]);

/******************************************************************************
 *  PRIVATE definitions
 *****************************************************************************/
#define LOG_PREFIX "BCM-BSAL: "
#define CLIENT_PROBE_REQ_FILTER_PERIOD 2U // seconds
#define CLIENT_STA_INFO_UPDATE_PERIOD 5. // seconds
#define CLIENT_STA_INFO_DATA_VOLUME_THRESHOLD 2000 // bytes
#define PROBE_HMW_MAGIC_VALUE 1 // "Special" HWM value indicating unconditional blocking
#define CLIENT_INACTIVE_TIMEOUT 60U // TODO: use inact_tmout_sec_normal
#define CLIENT_SNR_MAX_DIFF 3

typedef enum
{
    SNR_XING_STATE_NONE = 0,
    SNR_XING_STATE_BELOW_LWM = 1,
    SNR_XING_STATE_BETWEEN_LWM_HWM = 2,
    SNR_XING_STATE_ABOVE_HWM = 3,
} snr_xing_state_t;

typedef enum
{
    PROC_EVENT_NEW_BSAL_EVENT,
    PROC_EVENT_NO_BSAL_EVENT,
    PROC_EVENT_ERROR,
} proc_event_res_t;

typedef struct
{
    int snr;
    time_t time;
    bool ssid_null;
} probe_t;

typedef struct
{
    // Leave ev_timer at the beginning of structure, it's important for casting!
    ev_timer probe_req_filter_timer;

    char ifname[BSAL_IFNAME_LEN];
    os_macaddr_t hwaddr;

    bool connect_send;
    bool is_blacklisted;
    bool is_active;
    time_t is_active_report_time;

    int snr;
    uint8_t snr_lwm;
    uint8_t snr_hwm;

    uint8_t xing_snr_low;
    uint8_t xing_snr_high;

    probe_t max_probe;

    uint64_t tx_bytes;
    uint64_t rx_bytes;
    snr_xing_state_t snr_xing_level;

    bool support_btm;
    bool support_rrm;
    bool support_rrm_beacon_passive_mes;
    bool support_rrm_beacon_active_mes;
    bool support_rrm_beacon_table_mes;

    /* buffer for IEs, TODO fix sta_info in the driver */
    uint8_t assoc_ies[BSAL_MAX_ASSOC_IES_LEN];
    uint16_t assoc_ies_len;

    uint8_t max_chwidth;
    uint8_t max_streams;
    uint8_t max_mcs;

    ds_dlist_node_t node;
} client_t;

static struct ev_loop *_ev_loop = NULL;
static bool _bcm_bsal_initialized = false;
static bsal_event_cb_t _bsal_event_callback = NULL;
static ds_dlist_t _clients = DS_DLIST_INIT(client_t, node);
static ev_timer _client_sta_info_watcher;

os_macaddr_t _hwaddr_mask;

static void probe_add(client_t *client, int snr, time_t time, bool ssid_null)
{
    LOGT("%s: %s: "PRI(os_macaddr_t)" %d %u %d", client->ifname, __func__,
         FMT(os_macaddr_t, client->hwaddr), snr, (unsigned int) time, ssid_null);

    if (client->max_probe.snr > snr)
        return;

    client->max_probe.snr = snr;
    client->max_probe.time = time;
    client->max_probe.ssid_null = ssid_null;
}

static probe_t* probe_get(client_t *client)
{
    return &client->max_probe;
}

static void probe_clean(client_t *client)
{
    memset(&client->max_probe, 0, sizeof(client->max_probe));
}

static void update_hwaddr_mask(os_macaddr_t *hwaddr_client)
{
    unsigned int i;

    for (i = 0; i < sizeof(_hwaddr_mask.addr); i++)
        _hwaddr_mask.addr[i] |= hwaddr_client->addr[i];
}

static void recalc_hwaddr_mask(void)
{
    client_t *client;

    memset(&_hwaddr_mask.addr, 0, sizeof(_hwaddr_mask.addr));
    ds_dlist_foreach(&_clients, client) {
        update_hwaddr_mask(&client->hwaddr);
    }
}

static bool event_pass(os_macaddr_t *hwaddr)
{
    unsigned int i;

    for (i = 0; i < sizeof(_hwaddr_mask.addr); i++)
    {
        if (hwaddr->addr[i] == 0x00)
            continue;
        if (!(_hwaddr_mask.addr[i] & hwaddr->addr[i])) {
            return false;
        }
    }

    return true;
}

static void add_client(client_t *client)
{
    ds_dlist_insert_tail(&_clients, client);

    update_hwaddr_mask(&client->hwaddr);
    LOGD(LOG_PREFIX"%s: add, mask="PRI(os_macaddr_t), client->ifname, FMT(os_macaddr_pt, &_hwaddr_mask));
}

static void remove_client(client_t *client)
{
    ds_dlist_remove(&_clients, client);

    recalc_hwaddr_mask();
    LOGD(LOG_PREFIX"%s: remove, mask="PRI(os_macaddr_t), client->ifname, FMT(os_macaddr_pt, &_hwaddr_mask));
    free(client);
}

static bool is_event_ignored(int etype)
{
    switch (etype)
    {
        case WLC_E_PROBREQ_MSG_RX:
        case WLC_E_DEAUTH_IND:
        case WLC_E_DISASSOC_IND:
        case WLC_E_AUTHORIZED:
        case WLC_E_DEAUTH:
        case WLC_E_AUTH_IND:
        case WLC_E_ASSOC_IND:
        case WLC_E_REASSOC_IND:
            return false;
        default:
            return true;
    }
}

static snr_xing_state_t evaluate_snr_xing(const client_t *client, int snr)
{
    if (snr < client->xing_snr_low)
    {
        return SNR_XING_STATE_BELOW_LWM;
    }
    else if ((snr >= client->xing_snr_low) && (snr <= client->xing_snr_high))
    {
        return SNR_XING_STATE_BETWEEN_LWM_HWM;
    }
    else
    {
        return SNR_XING_STATE_ABOVE_HWM;
    }
}

static int rssi_to_snr(const char *ifname, int rssi)
{
    int noise;

    if (!bcmwl_get_noise(ifname, &noise))
        noise = -95;
    return rssi - noise;
}

static bool tlv_find_element(
        const uint8_t *data,
        size_t data_size,
        uint8_t type,
        uint8_t *len,
        const uint8_t **val)
{
    unsigned int i;

    for (i = 0; i < data_size;)
    {
        const uint8_t element_type = data[i];
        const uint8_t element_len = data[i + 1];

        if (element_type == type)
        {
            if (len)
            {
                *len = element_len;
            }
            if (val)
            {
                *val = data + i + 2;
            }

            return true;
        }

        i += element_len + 2;
    }

    return false;
}

static client_t* get_client(const char *ifname, const os_macaddr_t *hwaddr)
{
    client_t *client;

    ds_dlist_foreach(&_clients, client)
    {
        if (strncmp(client->ifname, ifname, BSAL_IFNAME_LEN))
            continue;
        if (memcmp(&client->hwaddr, hwaddr, sizeof(client->hwaddr)))
            continue;

        return client;
    }

    LOGT(LOG_PREFIX"Client not found! :: hwaddr="PRI(os_macaddr_t), FMT(os_macaddr_pt, hwaddr));
    return NULL;
}

static client_t* event_get_client(const char *ifname, const os_macaddr_t *hwaddr)
{
    client_t *client;

    ds_dlist_foreach(&_clients, client)
    {
        if (!strstr(client->ifname, ifname))
            continue;
        if (memcmp(&client->hwaddr, hwaddr, sizeof(client->hwaddr)))
            continue;

        return client;
    }

    return NULL;
}

static bool iface_prepare_acl(const char *ifname)
{
    LOGD(LOG_PREFIX"%s: Preparing iface ACLs", ifname);

    if (!bcmwl_acl_set_mode(ifname, BCMWL_ACL_MODE_DENY))
    {
        LOGE(LOG_PREFIX"%s: Failed to set ACL mode!", ifname);
        return false;
    }

    if (!bcmwl_acl_del_devs(ifname))
    {
        LOGE(LOG_PREFIX"%s: Failed to clear ACL!", ifname);
        return false;
    }

    if (!bcmwl_acl_set_prob_resp_blocking(ifname, true))
    {
        LOGE(LOG_PREFIX"%s: Failed to set probe responses blocking!", ifname);
        return false;
    }

    return true;
}

static bool iface_enable_events(const char *ifname)
{
    LOGD(LOG_PREFIX"%s: Enabling events on iface", ifname);

    if (WARN_ON(!bcmwl_event_enable(ifname, WLC_E_PROBREQ_MSG_RX)) ||
        WARN_ON(!bcmwl_event_enable(ifname, WLC_E_DEAUTH_IND)) ||
        WARN_ON(!bcmwl_event_enable(ifname, WLC_E_DISASSOC_IND)) ||
        WARN_ON(!bcmwl_event_enable(ifname, WLC_E_AUTHORIZED)) ||
        WARN_ON(!bcmwl_event_enable(ifname, WLC_E_DEAUTH)) ||
        WARN_ON(!bcmwl_event_enable(ifname, WLC_E_AUTH_IND)) ||
        WARN_ON(!bcmwl_event_enable(ifname, WLC_E_ASSOC)) ||
        WARN_ON(!bcmwl_event_enable(ifname, WLC_E_REASSOC_IND)))
    {
        return false;
    }

    return true;
}

static void client_reset(client_t *client)
{
    // Reset only connection-related fields
    client->snr = 0;
    probe_clean(client);
    client->tx_bytes = 0;
    client->rx_bytes = 0;
    client->is_active = 0;
    client->snr_xing_level = SNR_XING_STATE_NONE;
}

static bool client_acl_block(client_t *client)
{
    if (client->is_blacklisted)
        return true;

    LOGD(LOG_PREFIX"%s: Add "PRI(os_macaddr_t)" to blacklist", client->ifname, FMT(os_macaddr_t, client->hwaddr));
    if (!bcmwl_acl_add_dev(client->ifname, &client->hwaddr))
    {
        LOGE(LOG_PREFIX"%s: Failed to add "PRI(os_macaddr_t)" to ACL!", client->ifname, FMT(os_macaddr_t, client->hwaddr));
        return false;
    }

    client->is_blacklisted = true;

    return true;
}

static bool client_acl_unblock(client_t *client)
{
    if (!client->is_blacklisted)
        return true;

    LOGD(LOG_PREFIX"%s: Remove "PRI(os_macaddr_t)" from blacklist!", client->ifname, FMT(os_macaddr_t, client->hwaddr));
    if (!bcmwl_acl_del_dev(client->ifname, &client->hwaddr))
    {
        LOGE(LOG_PREFIX"%s Failed to del "PRI(os_macaddr_t)" from ACL!", client->ifname, FMT(os_macaddr_t, client->hwaddr));
        return false;
    }

    client->is_blacklisted = false;

    return true;
}

static proc_event_res_t process_event_probereq_msg_rx(
        client_t *client,
        const bcm_event_t *event_raw,
        bsal_event_t *event)
{
    bool ssid_null = true;
    const wl_event_rx_frame_data_t *rx_data;
    const struct dot11_management_header *hdr;
    const uint8_t *payload;
    ssize_t payload_size;
    int probe_snr;
    uint8_t ssid_ie_len;
    time_t snr_time;

    rx_data = (const wl_event_rx_frame_data_t*) (event_raw + 1);
    hdr = (const struct dot11_management_header*) (rx_data + 1);
    payload = (const uint8_t*) (hdr + 1);

    snr_time = time(NULL);
    probe_snr = rssi_to_snr(client->ifname, ntohl(rx_data->rssi));

    LOGT(LOG_PREFIX"%s: probreq_msg_rx addr="PRI(os_macaddr_t)" snr=%d",
         client->ifname, FMT(os_macaddr_t, client->hwaddr), probe_snr);

    payload_size = ntohl(event_raw->event.datalen);
    payload_size -= sizeof(wl_event_rx_frame_data_t) + sizeof(struct dot11_management_header);
    payload_size -= 4; // FIXME: FCS at the end?

    if (payload_size <= 0)
    {
        LOGE(LOG_PREFIX"%s: Event is too small to be valid WLC_E_PROBREQ_MSG_RX, datalen=%d",
             client->ifname, ntohl(event_raw->event.datalen));
        return PROC_EVENT_ERROR;
    }

    // Look for SSID IE in TLV
    if (tlv_find_element(payload, payload_size, DOT11_MNG_SSID_ID, &ssid_ie_len, NULL)
        && ssid_ie_len > 0)
    {
        ssid_null = false;
    }

    // Update client state
    probe_add(client, probe_snr, snr_time, ssid_null);
    if (!ev_is_active(&client->probe_req_filter_timer))
    {
        ev_timer_set(&client->probe_req_filter_timer,
                     CLIENT_PROBE_REQ_FILTER_PERIOD, 0);
        ev_timer_start(_ev_loop, &client->probe_req_filter_timer);
    }

    return PROC_EVENT_NO_BSAL_EVENT;
}

static proc_event_res_t process_event_deauth_ind(
        client_t *client,
        const bcm_event_t *event_raw,
        bsal_event_t *event)
{
    bsal_ev_disconnect_t *disconn_ev;

    LOGD(LOG_PREFIX"%s: deauth_ind addr="PRI(os_macaddr_t), client->ifname, FMT(os_macaddr_pt, &client->hwaddr));

    client->connect_send = false;
    event->type = BSAL_EVENT_CLIENT_DISCONNECT;
    strncpy(event->ifname, client->ifname, sizeof(event->ifname));

    disconn_ev = &event->data.disconnect;
    memcpy(&disconn_ev->client_addr, &client->hwaddr.addr, sizeof(disconn_ev->client_addr));
    disconn_ev->reason = ntohl(event_raw->event.reason);

    // FIXME: Is it enough to determine source?
    if (ntohl(event_raw->event.reason) == DOT11_RC_DEAUTH_LEAVING)
    {
        disconn_ev->source = BSAL_DISC_SOURCE_REMOTE;
    }
    else
    {
        disconn_ev->source = BSAL_DISC_SOURCE_LOCAL;
    }

    disconn_ev->type = BSAL_DISC_TYPE_DEAUTH;

    client_reset(client);

    if (client->snr_hwm)
    {
        if (WARN_ON(!client_acl_block(client))) {
            return PROC_EVENT_ERROR;
        }
    }

    return PROC_EVENT_NEW_BSAL_EVENT;
}

static proc_event_res_t process_event_deauth(
        client_t *client,
        const bcm_event_t *event_raw,
        bsal_event_t *event)
{
    bsal_ev_disconnect_t *disconn_ev;

    LOGD(LOG_PREFIX"%s: deauth addr="PRI(os_macaddr_t), client->ifname, FMT(os_macaddr_t, client->hwaddr));

    client->connect_send = false;
    event->type = BSAL_EVENT_CLIENT_DISCONNECT;
    strncpy(event->ifname, client->ifname, sizeof(event->ifname));

    disconn_ev = &event->data.disconnect;
    memcpy(&disconn_ev->client_addr, &client->hwaddr.addr, sizeof(disconn_ev->client_addr));
    disconn_ev->reason = ntohl(event_raw->event.reason);
    disconn_ev->source = BSAL_DISC_SOURCE_LOCAL;
    disconn_ev->type = BSAL_DISC_TYPE_DEAUTH;

    client_reset(client);

    if (client->snr_hwm)
    {
        if (WARN_ON(!client_acl_block(client))) {
            return PROC_EVENT_ERROR;
        }
    }

    return PROC_EVENT_NEW_BSAL_EVENT;
}

static proc_event_res_t process_event_disassoc_ind(
        client_t *client,
        const bcm_event_t *event_raw,
        bsal_event_t *event)
{
    bsal_ev_disconnect_t *disconn_ev;

    LOGD(LOG_PREFIX"%s: disassoc_ind addr="PRI(os_macaddr_t), client->ifname, FMT(os_macaddr_t, client->hwaddr));

    client->connect_send = false;
    event->type = BSAL_EVENT_CLIENT_DISCONNECT;
    strncpy(event->ifname, client->ifname, sizeof(event->ifname));

    disconn_ev = &event->data.disconnect;
    memcpy(&disconn_ev->client_addr, &client->hwaddr.addr, sizeof(disconn_ev->client_addr));
    disconn_ev->reason = ntohl(event_raw->event.reason);

    // FIXME: Is it enough to determine source?
    if (ntohl(event_raw->event.reason) == DOT11_RC_DISASSOC_LEAVING)   {
        disconn_ev->source = BSAL_DISC_SOURCE_REMOTE;
    } else {
        disconn_ev->source = BSAL_DISC_SOURCE_LOCAL;
    }

    disconn_ev->type = BSAL_DISC_TYPE_DISASSOC;

    client_reset(client);

    if (client->snr_hwm)
    {
        if (WARN_ON(!client_acl_block(client))) {
            return PROC_EVENT_ERROR;
        }
    }

    return PROC_EVENT_NEW_BSAL_EVENT;
}

static proc_event_res_t process_event_auth_ind(
        client_t *client,
        const bcm_event_t *event_raw,
        bsal_event_t *event)
{
    const wl_event_msg_t *wl_event = &event_raw->event;
    bsal_ev_auth_fail_t *auth_fail_ev;

    LOGD(LOG_PREFIX"%s: auth_ind addr="PRI(os_macaddr_t), client->ifname, FMT(os_macaddr_t, client->hwaddr));

    if (ntohl(wl_event->status) == 0)
    {
        // Authentication is successful, ignore event
        return PROC_EVENT_NO_BSAL_EVENT;
    }

    event->type = BSAL_EVENT_AUTH_FAIL;
    strncpy(event->ifname, client->ifname, sizeof(event->ifname));

    auth_fail_ev = &event->data.auth_fail;
    memcpy(&auth_fail_ev->client_addr, &client->hwaddr.addr, sizeof(auth_fail_ev->client_addr));
    auth_fail_ev->rssi = 0; // TODO Not needed?
    auth_fail_ev->reason = 1; // TODO BCM driver doesn't report any reason, field is 0
    auth_fail_ev->bs_blocked = 1; // TODO Not needed?
    auth_fail_ev->bs_rejected = 1; // TODO Not needed?

    return PROC_EVENT_NEW_BSAL_EVENT;
}

static proc_event_res_t process_event_authorized(
        client_t *client,
        const bcm_event_t *event_raw,
        bsal_event_t *connect_event)
{
    bsal_ev_connect_t *connect_ev;

    LOGD(LOG_PREFIX"%s: authorized addr="PRI(os_macaddr_t), client->ifname, FMT(os_macaddr_t, client->hwaddr));

    client->connect_send = true;
    connect_event->type = BSAL_EVENT_CLIENT_CONNECT;
    strncpy(connect_event->ifname, client->ifname, sizeof(connect_event->ifname));

    connect_ev = &connect_event->data.connect;
    memcpy(&connect_ev->client_addr, &client->hwaddr.addr, sizeof(connect_ev->client_addr));
    connect_ev->is_BTM_supported = client->support_btm;
    connect_ev->is_RRM_supported = client->support_rrm;
    connect_ev->band_cap_2G = false; // FIXME: Not needed?
    connect_ev->band_cap_5G = false; // FIXME: Not needed?
    // connect_ev->datarate_info // FIXME: Not needed?
    if (connect_ev->is_RRM_supported)
    {
        connect_ev->rrm_caps.bcn_rpt_passive = client->support_rrm_beacon_passive_mes;
        connect_ev->rrm_caps.bcn_rpt_active = client->support_rrm_beacon_active_mes;
        connect_ev->rrm_caps.bcn_rpt_table = client->support_rrm_beacon_table_mes;
        // FIXME: What about remaining fields?
    }

    connect_ev->datarate_info.max_chwidth = client->max_chwidth;
    connect_ev->datarate_info.max_streams = client->max_streams;
    connect_ev->datarate_info.max_MCS = client->max_mcs;

    return PROC_EVENT_NEW_BSAL_EVENT;
}

static proc_event_res_t process_event_assoc_reassoc_ind(
        client_t *client,
        const bcm_event_t *event_raw,
        bsal_event_t *event)
{
    const wl_event_msg_t *wl_event = &event_raw->event;
    bsal_ev_auth_fail_t *auth_fail_ev;
    const uint16_t rrm_cap_mask = DOT11_CAP_RRM;
    const uint8_t btm_cap_mask = 1 << (DOT11_EXT_CAP_BSSTRANS_MGMT - 16);
    const uint8_t rrm_beacon_passive_mes_mask = 1 << DOT11_RRM_CAP_BCN_PASSIVE;
    const uint8_t rrm_beacon_active_mes_mask = 1 << DOT11_RRM_CAP_BCN_ACTIVE;
    const uint8_t rrm_beacon_table_mes_mask = 1 << DOT11_RRM_CAP_BCN_TABLE;
    bool support_rrm = false;
    bool support_btm = false;
    bool support_rrm_beacon_passive_mes = false;
    bool support_rrm_beacon_active_mes = false;
    bool support_rrm_beacon_table_mes = false;
    const uint8_t *payload;
    ssize_t payload_size;
    uint8_t ie_len;
    const uint8_t *ie;
    bcmwl_sta_info_t sta_info;

    LOGD(LOG_PREFIX"%s: assoc_ind/reassoc_ind addr="PRI(os_macaddr_t), client->ifname, FMT(os_macaddr_t, client->hwaddr));

    payload_size = ntohl(event_raw->event.datalen);
    payload_size -= 4; // FIXME FCS at the end?

    if (payload_size <= 0)
    {
        LOGE(LOG_PREFIX"Event is too small to be valid WLC_E_ASSOC_IND! :: datalen=%d",
             ntohl(event_raw->event.datalen));
        return PROC_EVENT_ERROR;
    }

    if (ntohl(wl_event->status) != 0)
    {
        event->type = BSAL_EVENT_AUTH_FAIL;
        strncpy(event->ifname, client->ifname, sizeof(event->ifname));

        auth_fail_ev = &event->data.auth_fail;
        memcpy(&auth_fail_ev->client_addr, &client->hwaddr.addr, sizeof(auth_fail_ev->client_addr));
        auth_fail_ev->rssi = 0; // TODO Not needed?
        auth_fail_ev->reason = ntohl(wl_event->reason);
        auth_fail_ev->bs_blocked = 1; // TODO Not needed?
        auth_fail_ev->bs_rejected = 1; // TODO Not needed?

        return PROC_EVENT_NEW_BSAL_EVENT;
    }

    if (!bcmwl_sta_get_sta_info(client->ifname, &client->hwaddr, &sta_info))
    {
        LOGT(LOG_PREFIX"Failed do obtain STA capabilities! :: ifname=%s hwaddr="PRI(os_macaddr_t),
             client->ifname, FMT(os_macaddr_t, client->hwaddr));
        return PROC_EVENT_NO_BSAL_EVENT;
    }

    client->max_chwidth = sta_info.max_chwidth;
    client->max_streams = sta_info.max_streams;
    client->max_mcs = sta_info.max_mcs;

    payload = (const uint8_t*) (event_raw + 1);

    if (payload_size <= (int) sizeof(client->assoc_ies)) {
        memset(client->assoc_ies, 0, sizeof(client->assoc_ies));
        memcpy(client->assoc_ies, payload, payload_size);
        client->assoc_ies_len = payload_size;
    } else {
        LOGW(LOG_PREFIX"%s: "PRI(os_macaddr_t)" payload_size %d higher than assoc_ies %u", client->ifname,
             FMT(os_macaddr_t, client->hwaddr), payload_size, sizeof(client->assoc_ies));
        client->assoc_ies_len = 0;
        memset(client->assoc_ies, 0, sizeof(client->assoc_ies));
    }

    // Check RRM support
    support_rrm = (sta_info.capabilities & rrm_cap_mask) == rrm_cap_mask;
    if (support_rrm)
    {
        if (tlv_find_element(payload, payload_size, DOT11_MNG_RRM_CAP_ID, &ie_len, &ie))
        {
            if (ie_len >= 1)
            {
                support_rrm_beacon_passive_mes = (ie[0] & rrm_beacon_passive_mes_mask) == rrm_beacon_passive_mes_mask;
                support_rrm_beacon_active_mes = (ie[0] & rrm_beacon_active_mes_mask) == rrm_beacon_active_mes_mask;
                support_rrm_beacon_table_mes = (ie[0] & rrm_beacon_table_mes_mask) == rrm_beacon_table_mes_mask;
            }
        }
    }

    // Check BTM support
    if (tlv_find_element(payload, payload_size, DOT11_MNG_EXT_CAP_ID, &ie_len, &ie))
    {
        if (ie_len >= 3)
        {
            // BSS Transition support bit is in third byte
            support_btm = (ie[2] & btm_cap_mask) == btm_cap_mask;
        }
    }

    client->support_btm = support_btm;
    client->support_rrm = support_rrm;
    client->support_rrm_beacon_passive_mes = support_rrm_beacon_passive_mes;
    client->support_rrm_beacon_active_mes = support_rrm_beacon_active_mes;
    client->support_rrm_beacon_table_mes = support_rrm_beacon_table_mes;

    LOGD(LOG_PREFIX"%s: assoc_ind/reassoc_ind addr="PRI(os_macaddr_t)" btm=%d rrm=%d (%d,%d,%d)",
         client->ifname, FMT(os_macaddr_t, client->hwaddr), support_btm, support_rrm, support_rrm_beacon_passive_mes,
         support_rrm_beacon_active_mes, support_rrm_beacon_table_mes);

    return PROC_EVENT_NO_BSAL_EVENT;
}


static bool process_event_callback(
        const char *ifname,
        os_macaddr_t *client_hwaddr,
        void *data)
{
    const bcm_event_t *bcm_event = (const bcm_event_t*) data;
    proc_event_res_t proc_event_res = PROC_EVENT_NO_BSAL_EVENT;
    bsal_event_t event;
    client_t *client;

    if (is_event_ignored(ntohl(bcm_event->event.event_type))) {
        return true;
    }

    if (!event_pass(client_hwaddr))
    {
        return true;
    }

    if (!(client = event_get_client(ifname, client_hwaddr)))
    {
        return true;
    }

    LOGT(LOG_PREFIX"Processing event! :: ifname=%s client_hwaddr="PRI(os_macaddr_t),
         ifname, FMT(os_macaddr_pt, client_hwaddr));

    memset(&event, 0, sizeof(event));
    strncpy(event.ifname, ifname, sizeof(event.ifname));

    switch (ntohl(bcm_event->event.event_type))
    {
        case WLC_E_PROBREQ_MSG_RX:
            proc_event_res = process_event_probereq_msg_rx(client, bcm_event, &event);
            break;
        case WLC_E_DEAUTH:
            proc_event_res = process_event_deauth(client, bcm_event, &event);
            break;
        case WLC_E_DEAUTH_IND:
            proc_event_res = process_event_deauth_ind(client, bcm_event, &event);
            break;
        case WLC_E_DISASSOC_IND:
            proc_event_res = process_event_disassoc_ind(client, bcm_event, &event);
            break;
        case WLC_E_AUTHORIZED:
            proc_event_res = process_event_authorized(client, bcm_event, &event);
            break;
        case WLC_E_AUTH_IND:
            proc_event_res = process_event_auth_ind(client, bcm_event, &event);
            break;
        case WLC_E_ASSOC_IND:
        case WLC_E_REASSOC_IND:
            proc_event_res = process_event_assoc_reassoc_ind(client, bcm_event, &event);
            break;
        default:
            LOGE(LOG_PREFIX"Event Error: (event: %u) (%s)", ntohl(bcm_event->event.event_type),
                 __PRETTY_FUNCTION__);
            proc_event_res = PROC_EVENT_ERROR;
    }

leave:
    switch (proc_event_res)
    {
        case PROC_EVENT_NEW_BSAL_EVENT:
            _bsal_event_callback(&event);
            break;
        case PROC_EVENT_NO_BSAL_EVENT:
            // Just continue
            break;
        case PROC_EVENT_ERROR:
        default:
            LOGE(LOG_PREFIX"%s: Failed to process BCM event, etype=%d", ifname,
                 ntohl(bcm_event->event.event_type));
            return false;
    }

    return true;
}

static bool client_update_activity_event(
        client_t *client,
        const bcmwl_sta_info_t *sta_info,
        bsal_event_t *event)
{
    bool result = false;
    uint64_t current_volume;
    uint64_t new_volume;
    bool new_is_active;
    bsal_ev_activity_t *activity_ev;
    time_t active_time;

    LOGT(LOG_PREFIX"%s: Updating client activity, addr="PRI(os_macaddr_t),
         client->ifname, FMT(os_macaddr_t, client->hwaddr));

    if ((client->tx_bytes == 0) && (client->rx_bytes == 0))
    {
        // Default start in active state
        new_is_active = true;
        goto update;
    }

    active_time = time(NULL);
    current_volume = client->tx_bytes + client->rx_bytes;
    new_volume = sta_info->tx_total_bytes + sta_info->rx_total_bytes;
    new_is_active = (new_volume - current_volume) > CLIENT_STA_INFO_DATA_VOLUME_THRESHOLD;

    LOGT(LOG_PREFIX"%s: Check preconditions for ACTIVITY event, addr="PRI(os_macaddr_t)
         " data_vol_diff=%"PRIu64" data_vol_threshold=%d old %d new %d", client->ifname, FMT(os_macaddr_t, client->hwaddr),
         (new_volume - current_volume), CLIENT_STA_INFO_DATA_VOLUME_THRESHOLD, client->is_active, new_is_active);

    if (new_is_active)
    {
        /* When activity, start timer again */
        client->is_active_report_time = time(NULL);
    }

    if (client->is_active == new_is_active)
    {
        goto leave;
    }

    if (!new_is_active && ((unsigned int) (active_time - client->is_active_report_time) < CLIENT_INACTIVE_TIMEOUT)) {
        goto leave;
    }

update:
    // Prepare event
    event->type = BSAL_EVENT_CLIENT_ACTIVITY;
    strncpy(event->ifname, client->ifname, BSAL_IFNAME_LEN);

    activity_ev = &event->data.activity;
    memcpy(&activity_ev->client_addr, &client->hwaddr.addr, sizeof(activity_ev->client_addr));
    activity_ev->active = new_is_active;

    client->is_active_report_time = time(NULL);
    result = true;

leave:
    return result;
}

static bool client_update_rssi_event(
        client_t *client,
        int new_snr,
        bsal_event_t *event)
{
    bool result = false;
    bsal_ev_rssi_t *rssi_ev;

    LOGT(LOG_PREFIX"%s: Updating client RSSI, addr="PRI(os_macaddr_t),
         client->ifname, FMT(os_macaddr_t, client->hwaddr));

    LOGT(LOG_PREFIX"%s: Check preconditions for RSSI event, addr="PRI(os_macaddr_t)
         " old_snr=%d new_snr=%d", client->ifname, FMT(os_macaddr_t, client->hwaddr),
         client->snr, new_snr);

    if (abs(client->snr - new_snr) < CLIENT_SNR_MAX_DIFF)
    {
        goto leave;
    }

    // Prepare event
    event->type = BSAL_EVENT_RSSI;
    strncpy(event->ifname, client->ifname, BSAL_IFNAME_LEN);

    rssi_ev = &event->data.rssi;
    memcpy(&rssi_ev->client_addr, &client->hwaddr.addr, sizeof(rssi_ev->client_addr));
    rssi_ev->rssi = new_snr;

    result = true;

leave:
    return result;
}

static bool client_update_rssi_xing_event(
        client_t *client,
        int new_snr,
        bsal_event_t *event)
{
    bool result = false;
    bsal_ev_rssi_xing_t *rssi_xing_ev;
    snr_xing_state_t new_snr_xing_level;

    LOGT(LOG_PREFIX"%s: Updating client RSSI xing, addr="PRI(os_macaddr_t),
         client->ifname, FMT(os_macaddr_t, client->hwaddr));

    LOGT(LOG_PREFIX"%s: Check preconditions for RSSI XING event, addr="PRI(os_macaddr_t)
         " old_snr=%d new_snr=%d low=%d high=%d old_rssi_xing_state=%d",
         client->ifname, FMT(os_macaddr_t, client->hwaddr),
         client->snr, new_snr, client->xing_snr_low, client->xing_snr_high,
         client->snr_xing_level);

    new_snr_xing_level = evaluate_snr_xing(client, new_snr);
    if (client->snr_xing_level == new_snr_xing_level)
    {
        goto leave;
    }

    // Prepare event
    event->type = BSAL_EVENT_RSSI_XING;

    rssi_xing_ev = &event->data.rssi_change;
    memcpy(&rssi_xing_ev->client_addr, &client->hwaddr.addr, sizeof(rssi_xing_ev->client_addr));
    rssi_xing_ev->rssi = new_snr;

    // Old state is SNR_XING_STATE_BELOW_LWM
    if ((client->snr_xing_level == SNR_XING_STATE_BELOW_LWM) &&
        (new_snr_xing_level == SNR_XING_STATE_BETWEEN_LWM_HWM))
    {
        rssi_xing_ev->high_xing = BSAL_RSSI_UNCHANGED;
        rssi_xing_ev->low_xing = BSAL_RSSI_HIGHER;
    }
    else if ((client->snr_xing_level == SNR_XING_STATE_BELOW_LWM) &&
             (new_snr_xing_level == SNR_XING_STATE_ABOVE_HWM))
    {
        rssi_xing_ev->high_xing = BSAL_RSSI_HIGHER;
        rssi_xing_ev->low_xing = BSAL_RSSI_HIGHER;
    }
    // Old state is SNR_XING_STATE_BETWEEN_LWM_HWM
    else if ((client->snr_xing_level == SNR_XING_STATE_BETWEEN_LWM_HWM) &&
             (new_snr_xing_level == SNR_XING_STATE_BELOW_LWM))
    {
        rssi_xing_ev->high_xing = BSAL_RSSI_UNCHANGED;
        rssi_xing_ev->low_xing = BSAL_RSSI_LOWER;
    }
    else if ((client->snr_xing_level == SNR_XING_STATE_BETWEEN_LWM_HWM) &&
             (new_snr_xing_level == SNR_XING_STATE_ABOVE_HWM))
    {
        rssi_xing_ev->high_xing = BSAL_RSSI_HIGHER;
        rssi_xing_ev->low_xing = BSAL_RSSI_UNCHANGED;
    }
    // Old state is SNR_XING_STATE_ABOVE_HWM
    else if ((client->snr_xing_level == SNR_XING_STATE_ABOVE_HWM) &&
             (new_snr_xing_level == SNR_XING_STATE_BETWEEN_LWM_HWM))
    {
        rssi_xing_ev->high_xing = BSAL_RSSI_LOWER;
        rssi_xing_ev->low_xing = BSAL_RSSI_UNCHANGED;
    }
    else if ((client->snr_xing_level == SNR_XING_STATE_ABOVE_HWM) &&
             (new_snr_xing_level == SNR_XING_STATE_BELOW_LWM))
    {
        rssi_xing_ev->high_xing = BSAL_RSSI_LOWER;
        rssi_xing_ev->low_xing = BSAL_RSSI_LOWER;
    }
    else if ((client->snr_xing_level == SNR_XING_STATE_NONE) &&
             (new_snr_xing_level == SNR_XING_STATE_ABOVE_HWM))
    {
        rssi_xing_ev->high_xing = BSAL_RSSI_UNCHANGED;
        rssi_xing_ev->low_xing = BSAL_RSSI_UNCHANGED;
    }
    else if ((client->snr_xing_level == SNR_XING_STATE_NONE) &&
             (new_snr_xing_level == SNR_XING_STATE_BELOW_LWM))
    {
        rssi_xing_ev->high_xing = BSAL_RSSI_UNCHANGED;
        rssi_xing_ev->low_xing = BSAL_RSSI_UNCHANGED;
    }
    else
    {
        LOGW(LOG_PREFIX"%s: Unexpected RSSI xing observed for client, addr="
             PRI(os_macaddr_t)" low=%d high=%d old_snr=%d new_snr=%d",
             client->ifname, FMT(os_macaddr_t, client->hwaddr), client->xing_snr_low,
             client->xing_snr_high, client->snr, new_snr);
        goto leave;
    }

    rssi_xing_ev->inact_xing = BSAL_RSSI_UNCHANGED; // FIXME Is it correct?

    result = true;

leave:
    return result;
}

static void client_sta_info_update_callback(
        struct ev_loop *loop,
        ev_timer *watcher,
        int revents)
{
    client_t *client;

    LOGT(LOG_PREFIX"Handling clients sta_info update callback");

    ds_dlist_foreach(&_clients, client)
    {
        const char *mac = strfmta(PRI(os_macaddr_t), FMT(os_macaddr_t, client->hwaddr));
        bool activity_changed;
        bcmwl_sta_info_t sta_info;
        bsal_event_t event;
        int snr;

        if (!client->connect_send) {
            continue;
        }

        if (!bcmwl_sta_get_sta_info(client->ifname, &client->hwaddr, &sta_info))
        {
            LOGT(LOG_PREFIX"%s: Failed to get STA state, addr=%s", client->ifname, mac);
            continue;
        }

        memset(&event, 0, sizeof(event));
        strncpy(event.ifname, client->ifname, sizeof(event.ifname));
        snr = sta_info.rssi - sta_info.nf;

        if ((activity_changed = client_update_activity_event(client, &sta_info, &event)))
        {
            LOGD(LOG_PREFIX"%s: Send ACTIVITY event, addr=%s %s", client->ifname, mac,
                 event.data.activity.active ? "ACTIVE" : "INACTIVE");
            _bsal_event_callback(&event);
        }

        if (client_update_rssi_event(client, snr, &event))
        {
            LOGD(LOG_PREFIX"%s: Send RSSI event, addr=%s snr=%d",
                 client->ifname, mac, event.data.rssi.rssi);
            _bsal_event_callback(&event);
        }

        if (client_update_rssi_xing_event(client, snr, &event))
        {
            LOGI(LOG_PREFIX"%s: Send RSSI XING event, addr=%s snr=%d",
                 client->ifname, mac, event.data.rssi_change.rssi);
            _bsal_event_callback(&event);
        }

        // Update client fields
        client->tx_bytes = sta_info.tx_total_bytes;
        client->rx_bytes = sta_info.rx_total_bytes;
        client->snr = snr;
        client->snr_xing_level = evaluate_snr_xing(client, client->snr);
        if (activity_changed)
        {
            client->is_active = !client->is_active;
        }
    }

leave:
    return;
}

static void probe_req_filter_timer_callback(
        struct ev_loop *loop,
        ev_timer *watcher,
        int revents)
{
    bsal_event_t event;
    bsal_ev_probe_req_t *prob_req_ev;
    client_t *client;
    probe_t *probe;

    client = (client_t *) watcher;
    probe = probe_get(client);

    if (!probe) {
        LOGD("%s: no probe for " PRI(os_macaddr_t), client->ifname, FMT(os_macaddr_t, client->hwaddr));
        return;
    }

    memset(&event, 0, sizeof(event));

    event.type = BSAL_EVENT_PROBE_REQ;
    strncpy(event.ifname, client->ifname, sizeof(event.ifname));

    prob_req_ev = &event.data.probe_req;
    memcpy(&prob_req_ev->client_addr, &client->hwaddr.addr, sizeof(prob_req_ev->client_addr));
    prob_req_ev->rssi = probe->snr;
    prob_req_ev->ssid_null = probe->ssid_null;
    prob_req_ev->blocked = client->is_blacklisted;

    LOGD(LOG_PREFIX"%s: deliver probreq_msg_rx addr="PRI(os_macaddr_t)" snr=%d",
         client->ifname, FMT(os_macaddr_t, client->hwaddr), probe->snr);

    if (client->snr_hwm != 0 && client->snr_hwm != PROBE_HMW_MAGIC_VALUE)
    {
        LOGD("%s "PRI(os_macaddr_t)" hwm mode check, snr %d hwm %d", client->ifname,
             FMT(os_macaddr_t, client->hwaddr), probe->snr, client->snr_hwm);

        if (probe->snr <= client->snr_hwm) {
            client_acl_unblock(client);
        } else {
            client_acl_block(client);
        }
    }

    probe_clean(client);
    _bsal_event_callback(&event);
}


/******************************************************************************
 *  PUBLIC definitions
 *****************************************************************************/

bool bcm_bsal_init(
        struct ev_loop *loop,
        const char *ifnames[],
        bsal_event_cb_t callback)
{
    struct target_radio_ops bcm_ops;
    const char **ifname;

    if (_bcm_bsal_initialized)
    {
        LOGE(LOG_PREFIX"Already initialized");
        goto error;
    }

    memset(&bcm_ops, 0, sizeof(bcm_ops));

    if (!bcmwl_init(&bcm_ops))
    {
        LOGE(LOG_PREFIX"Failed to initialize bcmwl");
        goto error;
    }

    for (ifname = ifnames; *ifname; ifname++)
    {
        if (!bcmwl_event_register(loop, *ifname, process_event_callback))
        {
            LOGE(LOG_PREFIX"Failed to register to events on interface! :: ifname=%s", *ifname);
            goto error;
        }
    }

    assert(ds_dlist_is_empty(&_clients));
    ds_dlist_init(&_clients, client_t, node);

    ev_timer_init(&_client_sta_info_watcher, client_sta_info_update_callback,
                  CLIENT_STA_INFO_UPDATE_PERIOD, CLIENT_STA_INFO_UPDATE_PERIOD);
    ev_timer_start(loop, &_client_sta_info_watcher);

    _ev_loop = loop;
    _bcm_bsal_initialized = true;
    _bsal_event_callback = callback;

    return true;

error:
    bcm_bsal_finalize(loop, ifnames);
    return false;
}

bool bcm_bsal_finalize(
        struct ev_loop *loop,
        const char *ifnames[])
{
    const char **ifname;

    if (_bcm_bsal_initialized)
    {
        for (ifname = ifnames; *ifname; ifname++)
            bcmwl_event_unregister(loop, *ifname, process_event_callback);

        _bsal_event_callback = NULL;
        _bcm_bsal_initialized = false;
    }

    return true;
}

bool bcm_bsal_iface_add(const bsal_ifconfig_t *ifcfg)
{
    if (!ifcfg)
        return false;

    if (!iface_enable_events(ifcfg->ifname))
    {
        LOGE(LOG_PREFIX"%s: Failed set BCM events!", ifcfg->ifname);
        return false;
    }

    if (!iface_prepare_acl(ifcfg->ifname))
    {
        LOGE(LOG_PREFIX"%s: Failed prepare ACL!", ifcfg->ifname);
        return false;
    }

    return true;
}

bool bcm_bsal_iface_update(const bsal_ifconfig_t *ifcfg)
{
    (void)ifcfg;
    return true;
}

bool bcm_bsal_iface_remove(const bsal_ifconfig_t *ifcfg)
{
    /* TODO: disable events/acls */
    (void)ifcfg;
    return true;
}

bool bcm_bsal_add_client(
        const char *ifname,
        const uint8_t *client_hwaddr,
        const bsal_client_config_t *client_conf)
{
    client_t *client = NULL;
    os_macaddr_t hwaddr;
    const char *mac;

    memcpy(&hwaddr.addr, client_hwaddr, sizeof(hwaddr.addr));
    mac = strfmta(PRI(os_macaddr_t), FMT(os_macaddr_t, hwaddr));

    LOGD(LOG_PREFIX"%s: %s hwaddr=%s probe_lwm=%d probe_hwm=%d auth_lwm=%d auth_hwm=%d xing_low=%d xing_high=%d",
         ifname, __func__, mac,
         client_conf->rssi_probe_lwm, client_conf->rssi_probe_hwm,
         client_conf->rssi_auth_lwm, client_conf->rssi_auth_hwm,
         client_conf->rssi_low_xing, client_conf->rssi_high_xing);

    client = get_client(ifname, &hwaddr);
    if (client) {
        LOGE(LOG_PREFIX"%s: %s already added", ifname, mac);
        return false;
    }

    client = calloc(1, sizeof(*client));
    if (!client) {
        LOGE(LOG_PREFIX"%s: Failed to allocate memory for client, addr=%s", ifname, mac);
        return false;
    }

    client_reset(client);
    strncpy(client->ifname, ifname, BSAL_IFNAME_LEN);
    memcpy(&client->hwaddr, &hwaddr, sizeof(client->hwaddr));
    client->snr_lwm = client_conf->rssi_probe_lwm;
    client->snr_hwm = client_conf->rssi_probe_hwm;
    client->xing_snr_low = client_conf->rssi_low_xing;
    client->xing_snr_high = client_conf->rssi_high_xing;

    add_client(client);

    // Blacklist device (if device is not connected to us) or hwm == 1
    if (client_conf->rssi_probe_hwm)
    {
        if (!bcmwl_sta_is_connected(ifname, mac) ||
            client_conf->rssi_probe_hwm == PROBE_HMW_MAGIC_VALUE)
        {
            if (WARN_ON(!client_acl_block(client))) {
                goto leave;
            }
        }
    }
    else
    {
        if (WARN_ON(!client_acl_unblock(client))) {
            goto leave;
        }
    }

    ev_timer_init(&client->probe_req_filter_timer,
                  probe_req_filter_timer_callback,
                  CLIENT_PROBE_REQ_FILTER_PERIOD, 0.);

    return true;

leave:
    if (client) {
        remove_client(client);
    }

    return false;
}

bool bcm_bsal_update_client(
        const char  *ifname,
        const uint8_t *mac_addr,
        const bsal_client_config_t *conf)
{
    bool result = false;
    client_t *client;
    os_macaddr_t hwaddr;
    const char *mac;

    memcpy(&hwaddr.addr, mac_addr, sizeof(hwaddr.addr));
    mac = strfmta(PRI(os_macaddr_t), FMT(os_macaddr_t, hwaddr));

    LOGD(LOG_PREFIX"%s: %s addr=%s probe_lwm=%d probe_hwm=%d auth_lwm=%d auth_hwm=%d xing_low=%d xing_high=%d",
         ifname, __func__, mac,
         conf->rssi_probe_lwm, conf->rssi_probe_hwm,
         conf->rssi_auth_lwm, conf->rssi_auth_hwm,
         conf->rssi_low_xing, conf->rssi_high_xing);

    client = get_client(ifname, &hwaddr);
    if (!client) {
        LOGE(LOG_PREFIX"%s: Failed to update client -- client not found, addr=%s", ifname, mac);
        goto leave;
    }

    // Blacklist device (if device is not connected to us) or hwm == 1
    if (conf->rssi_probe_hwm)
    {
        if (!bcmwl_sta_is_connected(ifname, mac) ||
            conf->rssi_probe_hwm == PROBE_HMW_MAGIC_VALUE)
        {
            if (WARN_ON(!client_acl_block(client))) {
                goto leave;
            }
        }
    }
    else
    {
        if (WARN_ON(!client_acl_unblock(client))) {
            goto leave;
        }
    }

    client->snr_lwm = conf->rssi_probe_lwm;
    client->snr_hwm = conf->rssi_probe_hwm;
    client->xing_snr_low = conf->rssi_low_xing;
    client->xing_snr_high = conf->rssi_high_xing;

    result = true;

leave:
    return result;
}

bool bcm_bsal_remove_client(
        const char *ifname,
        const uint8_t *mac_addr)
{
    client_t *client = NULL;
    bool result = false;
    os_macaddr_t hwaddr;

    memcpy(&hwaddr.addr, mac_addr, sizeof(hwaddr.addr));

    LOGD(LOG_PREFIX"%s: %s addr="PRI(os_macaddr_t),
         ifname, __func__, FMT(os_macaddr_t, hwaddr));

    if (WARN_ON(!(client = get_client(ifname, &hwaddr))))    {
        goto leave;
    }

    ev_timer_stop(_ev_loop, &client->probe_req_filter_timer);

    if (WARN_ON(!client_acl_unblock(client))) {
        goto leave;
    }

    remove_client(client);
    result = true;

leave:
    return result;
}

bool bcm_bsal_client_measure(
        const char *ifname,
        const uint8_t *mac_addr,
        int num_samples)
{
    bool result = false;
    os_macaddr_t hwaddr;
    int rssi;
    bsal_event_t event;
    bsal_ev_rssi_t *rssi_ev;

    memcpy(&hwaddr.addr, mac_addr, sizeof(hwaddr.addr));

    LOGD(LOG_PREFIX"%s: Measuring client's connection RSSI, addr="PRI(os_macaddr_t),
         ifname, FMT(os_macaddr_t, hwaddr));

    if (!bcmwl_sta_get_rssi(ifname, &hwaddr, &rssi))
    {
        LOGE(LOG_PREFIX"%s: Failed to read RSSI value, addr="PRI(os_macaddr_t),
             ifname, FMT(os_macaddr_t, hwaddr));
        goto leave;
    }

    event.type = BSAL_EVENT_RSSI;
    strncpy(event.ifname, ifname, sizeof(event.ifname));

    rssi_ev = &event.data.rssi;
    memcpy(&rssi_ev->client_addr, mac_addr, sizeof(rssi_ev->client_addr));
    rssi_ev->rssi = rssi_to_snr(ifname, rssi);

    _bsal_event_callback(&event);

    result = true;

leave:
    return result;
}

bool bcm_bsal_client_disconnect(
        const char *ifname,
        const uint8_t *mac_addr,
        bsal_disc_type_t type,
        uint8_t reason)
{
    bool result = false;
    os_macaddr_t hwaddr;

    memcpy(&hwaddr.addr, mac_addr, sizeof(hwaddr.addr));

    LOGD(LOG_PREFIX"%s: Disconnecting client, addr="PRI(os_macaddr_t),
         ifname, FMT(os_macaddr_t, hwaddr));

    if (type != BSAL_DISC_TYPE_DEAUTH)
    {
        LOGI(LOG_PREFIX"disassoc requested, force BSAL_DISC_TYPE_DEAUTH");
    }

    if (!bcmwl_sta_deauth(ifname, &hwaddr, reason))
    {
        LOGE(LOG_PREFIX"%s: Failed to deauthenticate client, addr="PRI(os_macaddr_t),
             ifname, FMT(os_macaddr_t, hwaddr));
        goto leave;
    }

    result = true;

leave:
    return result;
}

bool bcm_bsal_client_info(
        const char *ifname,
        const uint8_t *mac_addr,
        bsal_client_info_t *info)
{
    bcmwl_sta_info_t sta_info;
    os_macaddr_t hwaddr;
    client_t *client;

    memset(info, 0, sizeof(*info));
    memcpy(&hwaddr.addr, mac_addr, sizeof(hwaddr.addr));

    if (!bcmwl_sta_get_sta_info(ifname, &hwaddr, &sta_info)) {
        LOGT(LOG_PREFIX"%s: Failed to get sta_info: hwaddr="PRI(os_macaddr_t),
             ifname, FMT(os_macaddr_t, hwaddr));
        return true;
    }

    info->connected = sta_info.is_authorized;
    info->is_BTM_supported = sta_info.is_btm_supported;

    /* TODO check how we can get RRM caps from driver */

    client = get_client(ifname, &hwaddr);
    if (!client) {
        return true;
    }

    info->datarate_info.max_chwidth = sta_info.max_chwidth;
    info->datarate_info.max_streams = sta_info.max_streams;
    info->datarate_info.max_MCS = sta_info.max_mcs;

    if (sta_info.is_authorized) {
        client->connect_send = true;
    }

    if (client->assoc_ies_len <= sizeof(info->assoc_ies)) {
        memcpy(info->assoc_ies, client->assoc_ies, client->assoc_ies_len);
        info->assoc_ies_len = client->assoc_ies_len;
    } else {
        LOGW(LOG_PREFIX"%s: "PRI(os_macaddr_t)" client ies_len %d higher than info storage %u", client->ifname,
             FMT(os_macaddr_t, client->hwaddr), client->assoc_ies_len, sizeof(info->assoc_ies));
    }

    return true;
}

bool bcm_bsal_bss_tm_request(
        const char *ifname,
        const uint8_t *mac_addr,
        const bsal_btm_params_t *btm_params)
{
    const char *fixed_params_fmt = "0a0701" // Category, Action Code, Dialog Token
                                   "%02x" // Options
                                   "0000" // Disassociation Timer
                                   "%02x"; // Validity Interval

    const char *mac_fmt = "%02x%02x%02x%02x%02x%02x";

    const char *neigh_report_body_fmt = "%08x" // BSSSID Information
                                        "%02x" // Operating Class
                                        "%02x" // Channel Number
                                        "%02x"; // PHY Type

    bool result = false;
    size_t offset = 0;
    char buffer[256] = { '\0' };
    os_macaddr_t hwaddr;
    uint8_t options;
    int i;

    memcpy(&hwaddr.addr, mac_addr, sizeof(hwaddr.addr));

    LOGD(LOG_PREFIX"%s: Issuing 11v request for client, addr="PRI(os_macaddr_t),
         ifname, FMT(os_macaddr_t, hwaddr));

    // Fixed parameters
    options = btm_params->pref ? DOT11_BSSTRANS_REQMODE_PREF_LIST_INCL : 0;
    options |= btm_params->abridged ? DOT11_BSSTRANS_REQMODE_ABRIDGED : 0;
    options |= btm_params->disassoc_imminent ? DOT11_BSSTRANS_REQMODE_DISASSOC_IMMINENT : 0;

    offset += snprintf(buffer + offset, sizeof(buffer) - offset,
                       fixed_params_fmt, options, btm_params->valid_int);

    // Neighbors
    for (i = 0; i < btm_params->num_neigh; i++)
    {
        const bsal_neigh_info_t *neighbor = &btm_params->neigh[i];

        offset += snprintf(buffer + offset, sizeof(buffer) - offset, "340d");

        offset += snprintf(buffer + offset, sizeof(buffer) - offset, mac_fmt,
                           neighbor->bssid[0], neighbor->bssid[1], neighbor->bssid[2],
                           neighbor->bssid[3], neighbor->bssid[4], neighbor->bssid[5]);

        offset += snprintf(buffer + offset, sizeof(buffer) - offset, neigh_report_body_fmt,
                           htole32(neighbor->bssid_info),
                           neighbor->op_class,
                           neighbor->channel,
                           neighbor->phy_type);
    }

    if (!bcmwl_misc_send_action_frame(ifname, &hwaddr, buffer))
    {
        LOGE(LOG_PREFIX"%s: Failed to send WNM action frame, addr="PRI(os_macaddr_t),
             ifname, FMT(os_macaddr_t, hwaddr));
        goto leave;
    }

    result = true;

leave:
    return result;
}

bool bcm_bsal_rrm_beacon_report_request(
        const char *ifname,
        const uint8_t *mac_addr,
        const bsal_rrm_params_t *rrm_params)
{
    const char *req_fmt = "05000100002619020005"
                          "%02x" // Operating Class
                          "%02x" // Measurement Channel
                          "%02x00" // Measurement Interval
                          "%02x00" // Measurement Duration
                          "%02x" // Measurement Mode
                          "ffffffffffff00000102"
                          "%02x" // Reporting Condition
                          "000201"
                          "%02x"; // Reporting Detail
    bool result = false;
    char buffer[128] = { '\0' };
    os_macaddr_t hwaddr;

    memcpy(&hwaddr.addr, mac_addr, sizeof(hwaddr.addr));

    LOGD(LOG_PREFIX"%s: Issuing 11k request for client, addr="PRI(os_macaddr_t),
         ifname, FMT(os_macaddr_t, hwaddr));

    snprintf(buffer, sizeof(buffer), req_fmt,
             rrm_params->op_class,
             rrm_params->channel,
             rrm_params->rand_ivl,
             rrm_params->meas_dur,
             rrm_params->meas_mode,
             rrm_params->rep_cond,
             rrm_params->rpt_detail);

    if (!bcmwl_misc_send_action_frame(ifname, &hwaddr, buffer))
    {
        LOGE(LOG_PREFIX"%s: Failed to send RRM action frame, addr="PRI(os_macaddr_t),
             ifname, FMT(os_macaddr_t, hwaddr));
        goto leave;
    }

    result = true;

leave:
    return result;
}


/* This is from 802.11 spec Table 9-152—Preference field values */
#define NEIGH_BTM_PREFERENCE "255"

bool bcm_bsal_rrm_set_neighbor(
        const char *ifname,
        const bsal_neigh_info_t *nr)
{
    return bcmwl_misc_set_neighbor(ifname,
                                   strfmta("%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                                           nr->bssid[0], nr->bssid[1], nr->bssid[2],
                                           nr->bssid[3], nr->bssid[4], nr->bssid[5]),
                                   strfmta("%u", nr->bssid_info),
                                   strfmta("%u", nr->op_class),
                                   strfmta("%u", nr->channel),
                                   strfmta("%u", nr->phy_type),
                                   /* This should be optional - should be added if present in
                                    * nr->opt_subelems[], but BCM require value for that. Set this
                                    * always the same - most preferred.
                                    * This is mainly used when handling BTM query request.
                                    * For unsolicited BSS TM request we build own action frame,
                                    * so not using driver Neighbor Report list.
                                    */
                                   NEIGH_BTM_PREFERENCE);
}

bool bcm_bsal_rrm_remove_neighbor(
        const char *ifname,
        const bsal_neigh_info_t *nr)
{
    return bcmwl_misc_remove_neighbor(ifname,
                                      strfmta("%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                                              nr->bssid[0], nr->bssid[1], nr->bssid[2],
                                              nr->bssid[3], nr->bssid[4], nr->bssid[5]));
}
