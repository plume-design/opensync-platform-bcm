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

#include "log.h"
#include "target.h"
#include "util.h"
#include "bcmwl.h"
#include "bcmwl_ioctl.h"
#include "bcmwl_nvram.h"
#include "bcmwl_debounce.h"

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

static void sta_get_max_mcs_nss_capab(
        const char *ifname,
        const os_macaddr_t *hwaddr,
        const wl_rateset_args_v2_t *rateset_adv,
        const struct bcmwl_ioctl_num_conv *conv,
        bcmwl_sta_info_t *sta_info)
{
    int ht_mcs_max = 0;
    int vht_nss_max = 0;
    int vht_mcs_max = 0;
    int mcs_max = 0;
    int nss_max = 0;

    ht_mcs_max = get_ht_mcs_max(rateset_adv->mcs);
    vht_nss_max = get_vht_nss_max(rateset_adv->vht_mcs, conv);
    vht_mcs_max = get_vht_mcs_max(rateset_adv->vht_mcs, conv);

    LOGT("%s: "PRI(os_macaddr_t)": ht_mcs_max=%d, vht_mcs_max=%d, "
              "vht_nss_max=%d",
              ifname, FMT(os_macaddr_pt, hwaddr),
              ht_mcs_max, vht_mcs_max, vht_nss_max);

    /* Max mcs x nss: */
    mcs_max = ht_mcs_max % 8;
    nss_max = ht_mcs_max / 8 + 1;
    if (vht_mcs_max > mcs_max)
        mcs_max = vht_mcs_max;
    if (vht_nss_max > nss_max)
        nss_max = vht_nss_max;

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
    uint16_t sta_len;

    if (conv->dtoh16(v5->ver) < 5)
        return;

    sta_len = conv->dtoh16(v5->len);
    if (sta_len < sizeof(sta_info_t)) {
        LOG(DEBUG, "%s: Driver did not return extended sta info.", __func__);
        return;
    }

    sta_get_max_mcs_nss_capab(ifname, hwaddr, &v5->rateset_adv, conv, sta_info);
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

    if (WARN_ON(!bcmwl_ioctl_prepare_args_with_addr(&buf, sizeof(buf), "sta_info", hwaddr)))
        return false;

    found = bcmwl_ioctl_get(ifname, WLC_GET_VAR, &buf, sizeof(buf));
    LOGT("%s: "PRI(os_macaddr_t)": sta info %s",
         ifname, FMT(os_macaddr_pt, hwaddr), found ? "found" : "not found");
    if (!found)
        return false;

    bcmwl_sta_get_sta_info_v4(ifname, hwaddr, sta_info, conv, buf);
    bcmwl_sta_get_sta_info_v5(ifname, hwaddr, sta_info, conv, buf);
    bcmwl_sta_get_sta_info_v7(ifname, hwaddr, sta_info, conv, buf);

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
