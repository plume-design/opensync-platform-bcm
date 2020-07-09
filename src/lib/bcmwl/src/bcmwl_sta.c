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
#include <stdio.h>
#include <string.h>
#include <stddef.h>

#include "log.h"
#include "target.h"
#include "util.h"
#include "bcmwl.h"
#include "bcmwl_ioctl.h"
#include "bcmwl_nvram.h"
#include "bcmwl_debounce.h"
#include "bcmwl_hostap.h"
#include "bcmwl_sta.h"

#define FIELD_FITS(_ptr, _field, _len) \
        ((_len) >= (offsetof(typeof(*_ptr), _field) + sizeof(_ptr->_field)))

/**
 * Public
 */

bool bcmwl_sta_deauth(
        const char *ifname,
        const os_macaddr_t *mac,
        int reason)
{
    FILE *fp = NULL;
    char cmd[512];
    int return_code;

    snprintf(cmd, sizeof(cmd), "wl -i %s deauthenticate "PRI(os_macaddr_t)" %d",
             ifname, FMT(os_macaddr_t, *mac), reason);

    fp = popen(cmd, "r");
    if (!fp)
    {
        LOGE("Failed to call \"wl\"! :: cmd=%s", cmd);
        goto error;
    }

    return_code = pclose(fp);
    fp = NULL;

    if (return_code == -1)
    {
        LOGE("pclose() failed! :: errno=%s cmd=%s", strerror(errno), cmd);
        goto error;
    }

    if (!WIFEXITED(return_code))
    {
        LOGE("\"wl\" failed! :: exit_code=%d cmd=%s", return_code, cmd);
        goto error;
    }

    return true;

error:
    if (fp)
    {
        pclose(fp);
    }
    return false;
}

bool bcmwl_sta_is_associated(const char *ifname, const char *mac)
{
    const char *list = WL(ifname, "assoclist");
    return WARN_ON(!list) ? false : strcasestr(list, mac);
}

bool bcmwl_sta_is_authorized(const char *ifname, const char *mac)
{
    const char *list = WL(ifname, "autho_sta_list");
    return WARN_ON(!list) ? false : strcasestr(list, mac);
}

bool bcmwl_sta_is_connected(const char *ifname, const char *mac)
{
    const char *wsec = WL(ifname, "wsec");
    if (WARN_ON(!wsec))
        return false;
    if (atoi(wsec) == 0)
        return bcmwl_sta_is_associated(ifname, mac);
    else
        return bcmwl_sta_is_authorized(ifname, mac);
}

bool bcmwl_sta_get_rssi(
        const char *ifname,
        const os_macaddr_t *hwaddr,
        int *rssi)
{
    int tmp_rssi;
    char *output;

    if (!(output = strexa("wl", "-i", ifname, "rssi",
                          strfmta(PRI(os_macaddr_t), FMT(os_macaddr_pt, hwaddr)))))
    {
        LOGE("Failed to read STA RSSI! :: ifname=%s hwaddr="PRI(os_macaddr_t),
             ifname, FMT(os_macaddr_pt, hwaddr));
        return false;
    }

    if (sscanf(output, "%d", &tmp_rssi) != 1)
    {
        LOGE("Failed to parse \"wl\" output! :: ifname%s hwaddr="PRI(os_macaddr_t)" output=%s",
             ifname, FMT(os_macaddr_pt, hwaddr), output);
        return false;
    }

    *rssi = tmp_rssi;

    return true;
}

static int get_ht_mcs_max(const uint8_t *mcsset)
{
    int i;

    if (!mcsset)
        return 0;

    for (i = (MCSSET_LEN * 8 - 1); i >= 0; i--)
    {
        if (i < 32 && (mcsset[i/8] & (1<<(i%8))))
            return i;
    }
    return 0;
}

static int get_vht_nss_max(
        const uint16_t *mcsset,
        const struct bcmwl_ioctl_num_conv *conv)
{
    int max_vht_nss = 0;
    int i;

    if (!mcsset)
        return 0;

    for (i = 0; i < VHT_CAP_MCS_MAP_NSS_MAX; i++)
    {
        if (conv->dtoh16(mcsset[i]))
            max_vht_nss = i + 1;
    }
    return max_vht_nss;
}

static int get_vht_mcs_max(
        const uint16_t *mcsset,
        const struct bcmwl_ioctl_num_conv *conv)
{
    int max_vht_mcs = 0;
    int i, j;

    if (!mcsset)
        return 0;

    for (i = 0; i < VHT_CAP_MCS_MAP_NSS_MAX; i++)
    {
        if (conv->dtoh16(mcsset[i]))
        {
            /* mcs 0-9: standard, mcs 10-11: nonstandard */
            for (j = 0; j <= 11; j++)
            {
                if (conv->dtoh16(mcsset[i]) & (1<<j))
                    max_vht_mcs = j;
            }
        }
    }
    return max_vht_mcs;
}

static int get_he_nss_max(
        const uint16_t *mcsset,
        const struct bcmwl_ioctl_num_conv *conv)
{
    uint16_t rxmcs;
    int max = 0;
    int i;
    int j;

    if (!mcsset)
        return 0;

    /* 80, 160, 80+80, interleaved tx/rx */
    for (i = 0; i < 3; i++)
    {
        rxmcs = conv->dtoh16(mcsset[(i*2) + 1]);
        for (j = 0; j < 8; j++, rxmcs >>= 2)
            if ((rxmcs & 3) != 3)
                if (j > max)
                    max = j;
    }

    return max + 1;
}

static int get_he_mcs_max(
        const uint16_t *mcsset,
        const struct bcmwl_ioctl_num_conv *conv)
{
    uint16_t rxmcs;
    int max = 0;
    int i;
    int j;

    if (!mcsset)
        return 0;

    /* 80, 160, 80+80, interleaved tx/rx */
    for (i = 0; i < 3; i++)
    {
        rxmcs = conv->dtoh16(mcsset[(i*2) + 1]);
        for (j = 0; j < 8; j++, rxmcs >>= 2)
        {
            switch (rxmcs & 3)
            {
                case 0: if (max < 7) max = 7; break;
                case 1: if (max < 9) max = 9; break;
                case 2: if (max < 11) max = 11; break;
                case 3: break;
            }
        }
    }

    return max;
}

static void sta_get_max_mcs_nss_capab(
        const char *ifname,
        const os_macaddr_t *hwaddr,
        const uint8 *mcs,
        const uint16 *vht_mcs,
        const uint16 *he_mcs,
        const struct bcmwl_ioctl_num_conv *conv,
        bcmwl_sta_info_t *sta_info)
{
    int ht_mcs_max = 0;
    int vht_nss_max = 0;
    int vht_mcs_max = 0;
    int he_nss_max = 0;
    int he_mcs_max = 0;
    int mcs_max = 0;
    int nss_max = 0;

    ht_mcs_max = get_ht_mcs_max(mcs);
    vht_nss_max = get_vht_nss_max(vht_mcs, conv);
    vht_mcs_max = get_vht_mcs_max(vht_mcs, conv);
    he_nss_max = get_he_nss_max(he_mcs, conv);
    he_mcs_max = get_he_mcs_max(he_mcs, conv);

    LOGT("%s: "PRI(os_macaddr_t)": ht_mcs_max=%d, vht_mcs_max=%d, "
              "vht_nss_max=%d he_mcs_max=%d he_nss_max=%d",
              ifname, FMT(os_macaddr_pt, hwaddr),
              ht_mcs_max, vht_mcs_max, vht_nss_max,
              he_mcs_max, he_nss_max);

    /* Max mcs x nss: */
    mcs_max = ht_mcs_max % 8;
    nss_max = ht_mcs_max / 8 + 1;
    if (vht_mcs_max > mcs_max)
        mcs_max = vht_mcs_max;
    if (vht_nss_max > nss_max)
        nss_max = vht_nss_max;
    if (he_mcs_max > mcs_max)
        mcs_max = he_mcs_max;
    if (he_nss_max > nss_max)
        nss_max = he_nss_max;

    sta_info->max_mcs = mcs_max;
    sta_info->max_streams = nss_max;
}

static void bcmwl_sta_get_sta_info_v4(
        const char *ifname,
        const os_macaddr_t *hwaddr,
        bcmwl_sta_info_t *sta_info,
        const struct bcmwl_ioctl_num_conv *conv,
        const void *buf)
{
#if WL_STA_VER >= 4
    const sta_info_t *v4 = buf;
    uint32_t flags;
    uint16_t ht_capabilities;
    uint16_t vht_flags;
    size_t i;

    if (conv->dtoh16(v4->ver) < 4)
        return;

    flags = conv->dtoh32(v4->flags);
    ht_capabilities = conv->dtoh16(v4->ht_capabilities);
    vht_flags = conv->dtoh16(v4->vht_flags);

    sta_info->is_authorized = (conv->dtoh32(v4->flags) & WL_STA_AUTHO);
    sta_info->capabilities = conv->dtoh16(v4->cap);
    sta_info->tx_total_bytes = conv->dtoh64(v4->tx_tot_bytes);
    sta_info->rx_total_bytes = conv->dtoh64(v4->rx_tot_bytes);

    sta_info->nf = v4->nf[0];
    sta_info->rssi = v4->rssi[0];
    for (i = 0; i < ARRAY_SIZE(v4->rssi); i++)
    {
        /* Ideally should rely on rx chainmask but that's expensive to get
         * here. 0 means undefined and is unlikely to be seen in real world
         * anyway.
         */
        if (v4->rssi[i] != 0 && sta_info->rssi < v4->rssi[i]) {
            sta_info->rssi = v4->rssi[i];
            sta_info->nf = v4->nf[i];
        }
    }

    /* Max bandwidth: */
    sta_info->max_chwidth = 0;         // 20 MHz
    if (ht_capabilities & WL_STA_CAP_40MHZ)
        sta_info->max_chwidth = 1;     // 40 MHz
    if (flags & WL_STA_VHT_CAP)
    {
        sta_info->max_chwidth = 2;     // 80 MHz
        if (vht_flags & WL_STA_SGI160)
        {   /* There's no 160Mhz capab flag advertised in sta_info on bcm, so
             * this won't report 160Mhz if SGI is not supported. */
            sta_info->max_chwidth = 3; // 160 MHz
        }
    }
#endif
}

static void bcmwl_sta_get_sta_info_v5(
        const char *ifname,
        const os_macaddr_t *hwaddr,
        bcmwl_sta_info_t *sta_info,
        const struct bcmwl_ioctl_num_conv *conv,
        const void *buf)
{
#if WL_STA_VER >= 5
    const sta_info_t *v5 = buf;
    const uint32 flags = conv->dtoh32(v5->flags);
    const bool ht = flags & WL_STA_N_CAP;
    const bool vht = flags & WL_STA_VHT_CAP;
    const uint8 *mcs = ht ? v5->rateset_adv.mcs : NULL;
    const uint16 *vht_mcs = vht ? v5->rateset_adv.vht_mcs : NULL;
    const uint16 *he_mcs = NULL;
    uint16_t sta_len;

    if (conv->dtoh16(v5->ver) < 5)
        return;

    sta_len = conv->dtoh16(v5->len);
    if (WARN_ON(!FIELD_FITS(v5, rateset_adv, sta_len)))
        return;

    sta_get_max_mcs_nss_capab(ifname, hwaddr, mcs, vht_mcs, he_mcs, conv, sta_info);
#endif
}

static void bcmwl_sta_get_sta_info_v6(
        const char *ifname,
        const os_macaddr_t *hwaddr,
        bcmwl_sta_info_t *sta_info,
        const struct bcmwl_ioctl_num_conv *conv,
        const void *buf)
{
#if WL_STA_VER >= 6
    const sta_info_t *v6 = buf;
    const uint32 flags = conv->dtoh32(v6->flags);
    const bool ht = flags & WL_STA_N_CAP;
    const bool vht = flags & WL_STA_VHT_CAP;
    const bool he = flags & WL_STA_HE_CAP;
    const uint8 *mcs = ht ? v6->rateset_adv.mcs : NULL;
    const uint16 *vht_mcs = vht ? v6->rateset_adv.vht_mcs : NULL;
    const uint16 *he_mcs = he ? v6->rateset_adv.he_mcs : NULL;

    if (conv->dtoh16(v6->ver) < 6)
        return;

    sta_get_max_mcs_nss_capab(ifname, hwaddr, mcs, vht_mcs, he_mcs, conv, sta_info);
#endif
}

static void bcmwl_sta_get_sta_info_v7(
        const char *ifname,
        const os_macaddr_t *hwaddr,
        bcmwl_sta_info_t *sta_info,
        const struct bcmwl_ioctl_num_conv *conv,
        const void *buf)
{
#if WL_STA_VER >= 7
    const sta_info_t *v7 = buf;

    if (conv->dtoh16(v7->ver) < 7)
        return;

    sta_info->is_btm_supported = (conv->dtoh32(v7->wnm_cap) & WL_WNM_BSSTRANS);
#endif
}

static void bcmwl_sta_get_sta_info_v8(
        const char *ifname,
        const os_macaddr_t *hwaddr,
        bcmwl_sta_info_t *sta_info,
        const struct bcmwl_ioctl_num_conv *conv,
        const void *buf)
{
#if WL_STA_VER >= 8
    const sta_info_t *v8 = buf;

    if (conv->dtoh16(v8->ver) < 8)
        return;

    memcpy(sta_info->rrm_caps, v8->rrm_capabilities, DOT11_RRM_CAP_LEN);
#endif
}

bool bcmwl_sta_get_sta_info(
        const char *ifname,
        const os_macaddr_t *hwaddr,
        bcmwl_sta_info_t *sta_info)
{
    const struct bcmwl_ioctl_num_conv *conv;
    char buf[WLC_IOCTL_MAXLEN];
    bool found;

    if (WARN_ON(!(conv = bcmwl_ioctl_lookup_num_conv(ifname))))
        return false;

    found = bcmwl_GIOV(ifname, "sta_info", &hwaddr->addr, &buf);
    LOGT("%s: "PRI(os_macaddr_t)": sta info %s",
         ifname, FMT(os_macaddr_pt, hwaddr), found ? "found" : "not found");
    if (!found)
        return false;

    bcmwl_sta_get_sta_info_v4(ifname, hwaddr, sta_info, conv, buf);
    bcmwl_sta_get_sta_info_v5(ifname, hwaddr, sta_info, conv, buf);
    bcmwl_sta_get_sta_info_v6(ifname, hwaddr, sta_info, conv, buf);
    bcmwl_sta_get_sta_info_v7(ifname, hwaddr, sta_info, conv, buf);
    bcmwl_sta_get_sta_info_v8(ifname, hwaddr, sta_info, conv, buf);

    LOGT("%s: "PRI(os_macaddr_t)": Client capabilities: mcs_max=%d, "
              "nss_max=%d, bw_max=%d",
              ifname, FMT(os_macaddr_pt, hwaddr),
              sta_info->max_mcs, sta_info->max_streams, sta_info->max_chwidth);

    return true;
}

char* bcmwl_sta_get_authorized_macs(const char *ifname)
{
    char *result;

    if (!(result = strexread("wl", (const char* []) {"wl", "-i", ifname, "autho_sta_list", NULL})))
    {
        LOGE("Failed get list of authorized STA! :: ifname=%s", ifname);
    }

    return strchomp(result, " \t\r\n");
}

void bcmwl_sta_get_schema(
        const char *ifname,
        const char *mac,
        struct schema_Wifi_Associated_Clients *c)
{
    const char *keyid;

    if (!(keyid = NVG(ifname, strfmta("sta_%s_keyid", mac))) || !strlen(keyid))
        keyid = "";

    LOGT("%s: prepping %s schema, keyid=%s", ifname, mac, keyid);
    memset(c, 0, sizeof(*c));
    schema_Wifi_Associated_Clients_mark_all_present(c);
    c->_partial_update = true;
    SCHEMA_SET_STR(c->key_id, keyid);
    SCHEMA_SET_STR(c->state, "active");
    SCHEMA_SET_STR(c->mac, mac);
    bcmwl_hostap_sta_get(ifname, mac, c);
}

void bcmwl_sta_resync(const char *ifname)
{
    struct schema_Wifi_Associated_Clients *clients = NULL;
    char *macs;
    char *mac;
    char *p;
    int i;
    int n;

    if (!bcmwl_ops.op_clients)
        return;
    if (strncmp(ifname, "wl", 2) != 0)
        return;
    if (bcmwl_vap_is_sta(ifname))
        return;
    if (WARN_ON(!(macs = WL(ifname, "autho_sta_list"))))
        return;

    n = 0;
    p = strdupa(macs);
    while ((mac = strsep(&p, "\r\n")))
        if (strlen(mac))
            n++;

    LOGI("%s: syncing %d clients: %s", ifname, n, macs);

    if (WARN_ON(!(clients = calloc(n > 0 ? n : 1, sizeof(*clients)))))
        return;

    i = 0;
    while ((mac = strsep(&macs, " \t\r\n")))
        if (bcmwl_misc_is_valid_mac(mac))
            bcmwl_sta_get_schema(ifname, mac, &clients[i++]);

    bcmwl_ops.op_clients(clients, n, ifname);
    free(clients);
}

int bcmwl_sta_get_tx_avg_rate_v6(const wl_iov_pktq_log_t *resp,
                                 int i,
                                 const struct bcmwl_ioctl_num_conv *conv,
                                 float *mbps,
                                 float *psr,
                                 float *tried)
{
#ifdef PKTQ_LOG_V06_HEADINGS_SIZE
    const pktq_log_counters_v06_t *c;
    float phyrate = 0;
    float acked = 0;
    float retry = 0;
    int n;

    if (resp->version != 6)
        return -1;
    if ((resp->params.addr_type[i] & 0x7F) != 'A' &&
        (resp->params.addr_type[i] & 0x7F) != 'N')
        return -1;

    n = resp->pktq_log.v06.num_prec[i];
    c = resp->pktq_log.v06.counters[i].pktq;

    for (; n; n--, c++) {
        phyrate += conv->dtoh64(c->txrate_main);
        acked += conv->dtoh32(c->acked);
        retry += conv->dtoh32(c->retry);
    }

    *mbps *= *tried;
    *psr *= *tried;
    *tried += acked + retry;
    if (*tried) {
        *mbps += phyrate * 0.1;
        *mbps /= *tried;
        *psr += acked;
        *psr /= *tried;
    }

    return 0;
#else
    /* if it reports v6 but headers didn't say it is
     * supported then somethimg is clearly wrong with the
     * headers at build time and it needs to be addressed.
     */
    WARN_ON(resp->version == 6);
    return -1;
#endif
}

int bcmwl_sta_get_tx_avg_rate_v5(const wl_iov_pktq_log_t *resp,
                                 int i,
                                 const struct bcmwl_ioctl_num_conv *conv,
                                 float *mbps,
                                 float *psr,
                                 float *tried)
{
    const pktq_log_counters_v05_t *c;
    float phyrate = 0;
    float acked = 0;
    float retry = 0;
    int n;

    if (resp->version != 5)
        return -1;
    if ((resp->params.addr_type[i] & 0x7F) != 'A' &&
        (resp->params.addr_type[i] & 0x7F) != 'N')
        return -1;

    n = resp->pktq_log.v05.num_prec[i];
    c = resp->pktq_log.v05.counters[i];

    for (; n; n--, c++) {
        phyrate += conv->dtoh32(c->txrate_main);
        acked += conv->dtoh32(c->acked);
        retry += conv->dtoh32(c->retry);
    }

    *mbps *= *tried;
    *psr *= *tried;
    *tried += acked + retry;
    if (*tried) {
        *mbps += phyrate * 0.5;
        *mbps /= *tried;
        *psr += acked;
        *psr /= *tried;
    }

    return 0;
}

int bcmwl_sta_get_tx_avg_rate_v4(const wl_iov_pktq_log_t *resp,
                                 int i,
                                 const struct bcmwl_ioctl_num_conv *conv,
                                 float *mbps,
                                 float *psr,
                                 float *tried)
{
    const pktq_log_counters_v04_t *c;
    float phyrate = 0;
    float acked = 0;
    float retry = 0;
    int n;

    if (resp->version != 4)
        return -1;
    if ((resp->params.addr_type[i] & 0x7F) != 'A' &&
        (resp->params.addr_type[i] & 0x7F) != 'N')
        return -1;

    n = resp->pktq_log.v04.num_prec[i];
    c = resp->pktq_log.v04.counters[i];

    for (; n; n--, c++) {
        phyrate += conv->dtoh32(c->txrate_main);
        acked += conv->dtoh32(c->acked);
        retry += conv->dtoh32(c->retry);
    }

    *mbps *= *tried;
    *psr *= *tried;
    *tried += acked + retry;
    if (*tried) {
        *mbps += phyrate * 0.5;
        *mbps /= *tried;
        *psr += acked;
        *psr /= *tried;
    }

    return 0;
}

int bcmwl_sta_get_tx_avg_rate(const char *ifname,
                              const char *mac,
                              float *mbps,
                              float *psr,
                              float *tried)
{
    const struct bcmwl_ioctl_num_conv *conv;
    wl_iov_mac_full_params_t req;
    wl_iov_pktq_log_t resp;
    unsigned int i;

    if (WARN_ON(!(conv = bcmwl_ioctl_lookup_num_conv(ifname))))
        return -1;

    req.params.addr_type[0] = 'A';
    req.params.addr_type[1] = 'N';
    req.extra_params.addr_info[0] = 1 << 31; /* log auto bit, ie. all tids */
    req.extra_params.addr_info[1] = 1 << 31; /* log auto bit, ie. all tids */
    sscanf(mac, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
           &req.params.ea[0].octet[0], &req.params.ea[0].octet[1],
           &req.params.ea[0].octet[2], &req.params.ea[0].octet[3],
           &req.params.ea[0].octet[4], &req.params.ea[0].octet[5]);
    memcpy(&req.params.ea[1], &req.params.ea[0], sizeof(req.params.ea[0]));
    req.params.num_addrs = 2;
    req.params.num_addrs |= 4 << 8; /* v4 stats */
    req.params.num_addrs = conv->dtoh32(req.params.num_addrs);

    if (WARN_ON(!bcmwl_GIOV(ifname, "pktq_stats", &req, &resp)))
        return -1;

    resp.version = conv->dtoh32(resp.version);
    resp.params.num_addrs = conv->dtoh32(resp.params.num_addrs);

    *mbps = 0;
    *psr = 0;
    *tried = 0;

    for (i = 0; i < resp.params.num_addrs; i++) {
        if (bcmwl_sta_get_tx_avg_rate_v6(&resp, i, conv, mbps, psr, tried) == 0)
            continue;
        if (bcmwl_sta_get_tx_avg_rate_v5(&resp, i, conv, mbps, psr, tried) == 0)
            continue;
        if (bcmwl_sta_get_tx_avg_rate_v4(&resp, i, conv, mbps, psr, tried) == 0)
            continue;

        WARN_ON(1);
    }

    return 0;
}

int bcmwl_sta_get_rx_avg_rate(const char *ifname,
                              void (*iter)(const char *ifname,
                                           const char *mac_octet,
                                           float mbps,
                                           float psr,
                                           float tried,
                                           void *arg),
                              void *arg)
{
#ifdef SCB_RX_REPORT_DATA_STRUCT_VERSION
    const struct bcmwl_ioctl_num_conv *conv;
    iov_rx_report_counters_t *c;
    iov_rx_report_record_t *r;
    union {
        iov_rx_report_struct_t cmd;
        char buf[WLC_IOCTL_MAXLEN];
    } resp;
    int flags = 0;
    float mbps;
    float psr;
    float phyrate;
    float mpdu;
    float retried;
    size_t tid;
    int i;

    if (WARN_ON(!(conv = bcmwl_ioctl_lookup_num_conv(ifname))))
        return -1;

    /* possibly unsupported, so allow it to fail */
    if (!bcmwl_GIOV(ifname, "rx_report", &flags, &resp))
        return -1;

    resp.cmd.structure_version = conv->dtoh16(resp.cmd.structure_version);
    resp.cmd.structure_count = conv->dtoh16(resp.cmd.structure_count);

    /* ABI mismatch, headers might be incorrect */
    if (WARN_ON(resp.cmd.structure_version != SCB_RX_REPORT_DATA_STRUCT_VERSION))
        return -1;

    for (i = 0; i < resp.cmd.structure_count; i++) {
        r = &resp.cmd.structure_record[i];

        phyrate = 0;
        mpdu = 0;
        mbps = 0;
        psr = 0;
        retried = 0;

        for (tid = 0; tid < ARRAY_SIZE(r->station_counters); tid++) {
            c = &r->station_counters[tid];

            if (!(r->station_flags & (1 << tid)))
                continue;

            phyrate += conv->dtoh64(c->rxphyrate);
            mpdu += conv->dtoh32(c->rxmpdu);
            retried += conv->dtoh32(c->rxretried);
        }

        if (mpdu > 0) {
            mbps = phyrate;
            mbps /= 1000;
            mbps /= mpdu;
            psr = mpdu / (mpdu + retried);
        }

        iter(ifname, (const char *)r->station_address.octet, mbps, psr, mpdu + retried, arg);
    }

    return 0;
#else
    return -1;
#endif
}
