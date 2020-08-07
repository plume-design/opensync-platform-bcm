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
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdbool.h>
#include <ev.h>

#include "log.h"
#include "os_nif.h"
#include "ds.h"
#include "ds_tree.h"
#include "const.h"
#include "util.h"
#include "kconfig.h"

#include "bcmwl.h"
#include "bcmwl_ioctl.h"
#include "wl80211.h"
#include "wl80211_client.h"

#define MODULE_ID LOG_MODULE_ID_WL

#define WL80211_DATA_RATE_LEN       (128)


#define WL_MCS_REPORT_VERSION    1  /* Suported wl rate_histo_report version */
#define WL_MCS_REPORT_TYPE       1  /* Suported wl rate_histo_report version */


#define STR_BEGINS_WITH(buf, token)  \
            (strncmp(buf, token, strlen(token)) == 0)


typedef struct {
    radio_entry_t                  *radio_cfg;
    char                           *ifname;
    char                            ssid[WL80211_DATA_RATE_LEN + 1];
    ds_dlist_t                     *list;  /* wl80211_client_record_t */
} wl80211_client_ctx_t;



static void wl80211_client_mcs_stats_get(
        const char *ifname,
        wl80211_client_record_t *client);
static int wl80211_client_mcs_stats_parse(
        FILE *f,
        wl80211_client_record_t *client);


static bool mcs_wl_to_dpp(
        struct __dpp_client_stats_rxtx *dpp,
        const wl80211_client_mcs_stats_t *wl,
        uint64_t bytes_total,
        int32_t rssi)
{
    memset(dpp, 0, sizeof(*dpp));

    if (wl->freq == 20)
        dpp->bw = CLIENT_RADIO_WIDTH_20MHZ;
    else if (wl->freq == 40)
        dpp->bw = CLIENT_RADIO_WIDTH_40MHZ;
    else if (wl->freq == 80)
        dpp->bw = CLIENT_RADIO_WIDTH_80MHZ;
    else if (wl->freq == 160)
        dpp->bw = CLIENT_RADIO_WIDTH_160MHZ;
    else
    {
        LOG(ERROR, "Invalid/unsupported client radio width: %u. Skipping.", wl->freq);
        return false;
    }

    if (wl->rate) /* Legacy format */
    {
        dpp->nss = 0;

        if (wl->rate == 6)
            dpp->mcs = 0;
        else if (wl->rate == 9)
            dpp->mcs = 1;
        else if (wl->rate == 12)
            dpp->mcs = 2;
        else if (wl->rate == 18)
            dpp->mcs = 3;
        else if (wl->rate == 24)
            dpp->mcs = 4;
        else if (wl->rate == 36)
            dpp->mcs = 5;
        else if (wl->rate == 48)
            dpp->mcs = 6;
        else if (wl->rate == 54)
            dpp->mcs = 7;
        else if (wl->rate == 1)
            dpp->mcs = 8;
        else if (wl->rate == 2)
            dpp->mcs = 9;
        else if (wl->rate == 5)
             dpp->mcs = 10;
        else if (wl->rate == 11)
            dpp->mcs = 11;
        else
        {
            LOG(ERROR, "Invalid/unsupported client rate: %u. Skipping.", wl->rate);
            return false;
        }
    }
    else
    {
        dpp->mcs = wl->mcs;
        dpp->nss = wl->nss;
    }

    if (wl->pkts_total == 0)
    {
        dpp->bytes = 0;
    }
    else
    {
        /* WAR: BCM does not provide bytes per rate, hence we're forced
         * to best-effort "estimate" this count from packet per rate counters: */
        double pkts_ratio = (double)wl->pkts / (double)wl->pkts_total;
        double bytes = pkts_ratio * (double)bytes_total;

        dpp->bytes = (uint64_t) (bytes + 0.5);

        /* According to comments in BCM wl driver's ioctl interface,
         * the pkts/counts per rate in rate_histo_report output are
         * "count of mpdus per rate", so copy this count of "pkts"
         * to dpp mpdu count here: */
        dpp->mpdu = wl->pkts;

        /* Unfortunately BCM driver reports no additional data -- it's a
         * known limitation, mpdu count is all we have, no msdu or ppdu info
         * available: */
        dpp->msdu = 0;
        dpp->ppdu = 0;
    }

    if (rssi > 0)
        dpp->rssi = rssi;

    return true;
}


/******************************************************************************
 *  PROTECTED definitions
 *****************************************************************************/

static bool wl80211_client_stats_calculate(
        radio_entry_t              *radio_cfg,
        wl80211_client_record_t    *data_new,
        wl80211_client_record_t    *data_old,
        dpp_client_record_t        *client_result)
{
    wl80211_client_stats_t         *old_stats;
    wl80211_client_stats_t         *new_stats;
    wl80211_client_mcs_stats_t     *mcs_wl = 0;
    radio_type_t                    radio_type = radio_cfg->type;


    new_stats = &data_new->stats;
    old_stats = &data_old->stats;

    /* Some drivers reset stats at reconnect and we do not notice that. Until
       they add connection cookie or some other way of reconnect indication
       we shall assume that if all stats are overlapped it is reconnect
     */
    if (    (new_stats->tx.ucast_bytes < old_stats->tx.ucast_bytes)
         && (new_stats->tx.mcast_bytes < old_stats->tx.mcast_bytes)
         && (new_stats->rx.ucast_bytes < old_stats->rx.ucast_bytes)
         && (new_stats->rx.mcast_bytes < old_stats->rx.mcast_bytes)
         && (new_stats->tx.ucast_pkts  < old_stats->tx.ucast_pkts)
         && (new_stats->tx.mcast_pkts  < old_stats->tx.mcast_pkts)
         && (new_stats->rx.ucast_pkts  < old_stats->rx.mcast_pkts)
         && (new_stats->rx.mcast_pkts  < old_stats->rx.mcast_pkts)
        )
    {
        memset(old_stats, 0, sizeof(wl80211_client_stats_t));
    }

    /* Workaround for 'tx mcast/bcast bytes' and 'tx mcast/bcast pkts'
     * counters not restarting from zero at reconnect - discard first sample
     * by forcing stats delta 0. */
    if (old_stats->tx.mcast_bytes == 0) {
        old_stats->tx.mcast_bytes = new_stats->tx.mcast_bytes;
    }
    if (old_stats->tx.mcast_pkts == 0) {
        old_stats->tx.mcast_pkts = new_stats->tx.mcast_pkts;
    }


    client_result->stats.bytes_tx =
        STATS_DELTA(new_stats->tx.ucast_bytes, old_stats->tx.ucast_bytes);

    LOG(TRACE,
        "Calculated %s client delta stats for "MAC_ADDRESS_FORMAT" "
        "bytes_tx=%"PRIu64" (new_ucast=%"PRIu64", old_ucast=%"PRIu64", "
                            "new_mcast=%"PRIu64", old_mcast=%"PRIu64")",
        radio_get_name_from_type(radio_type),
        MAC_ADDRESS_PRINT(data_new->info.mac),
        client_result->stats.bytes_tx,
        new_stats->tx.ucast_bytes,
        old_stats->tx.ucast_bytes,
        new_stats->tx.mcast_bytes,
        old_stats->tx.mcast_bytes);


    client_result->stats.bytes_rx =
        STATS_DELTA(new_stats->rx.ucast_bytes, old_stats->rx.ucast_bytes);

    LOG(TRACE,
        "Calculated %s client delta stats for "MAC_ADDRESS_FORMAT" "
        "bytes_rx=%"PRIu64" (new_ucast=%"PRIu64", old_ucast=%"PRIu64", "
                            "new_mcast=%"PRIu64", old_mcast=%"PRIu64")",
        radio_get_name_from_type(radio_type),
        MAC_ADDRESS_PRINT(data_new->info.mac),
        client_result->stats.bytes_rx,
        new_stats->rx.ucast_bytes,
        old_stats->rx.ucast_bytes,
        new_stats->rx.mcast_bytes,
        old_stats->rx.mcast_bytes);


    client_result->stats.frames_tx =
        (uint64_t)STATS_DELTA(new_stats->tx.ucast_pkts, old_stats->tx.ucast_pkts);

    LOG(TRACE,
        "Calculated %s client delta stats for "MAC_ADDRESS_FORMAT" "
        "frames_tx=%"PRIu64" (new_ucast=%"PRIu32", old_ucast=%"PRIu32", "
                            "new_mcast=%"PRIu32", old_mcast=%"PRIu32")",
        radio_get_name_from_type(radio_type),
        MAC_ADDRESS_PRINT(data_new->info.mac),
        client_result->stats.frames_tx,
        new_stats->tx.ucast_pkts,
        old_stats->tx.ucast_pkts,
        new_stats->tx.mcast_pkts,
        old_stats->tx.mcast_pkts);


    client_result->stats.frames_rx =
        (uint64_t)STATS_DELTA(new_stats->rx.ucast_pkts, old_stats->rx.ucast_pkts);

    LOG(TRACE,
        "Calculated %s client delta stats for "MAC_ADDRESS_FORMAT" "
        "frames_rx=%"PRIu64" (new_ucast=%"PRIu32", old_ucast=%"PRIu32", "
                            "new_mcast=%"PRIu32", old_mcast=%"PRIu32")",
        radio_get_name_from_type(radio_type),
        MAC_ADDRESS_PRINT(data_new->info.mac),
        client_result->stats.frames_rx,
        new_stats->rx.ucast_pkts,
        old_stats->rx.ucast_pkts,
        new_stats->rx.mcast_pkts,
        old_stats->rx.mcast_pkts);


    client_result->stats.retries_rx =
        STATS_DELTA(
                new_stats->rx.retries,
                old_stats->rx.retries);
    client_result->stats.retries_tx =
        STATS_DELTA(
                new_stats->tx.retries,
                old_stats->tx.retries);
    client_result->stats.errors_rx =
        STATS_DELTA(
                new_stats->rx.errors,
                old_stats->rx.errors);
    client_result->stats.errors_tx =
        STATS_DELTA(
                new_stats->tx.errors,
                old_stats->tx.errors);

    /* RSSI is value above the noise floor */
    if (new_stats->rx.snr)
    {
        client_result->stats.rssi = new_stats->rx.snr;
        LOG(TRACE,
            "Calculated %s client delta stats for "
            MAC_ADDRESS_FORMAT" rssi=%d",
            radio_get_name_from_type(radio_type),
            MAC_ADDRESS_PRINT(data_new->info.mac),
            client_result->stats.rssi);
    }

    if (new_stats->tx.last_rate)
    {
        client_result->stats.rate_tx = new_stats->tx.last_rate;
        client_result->stats.rate_tx /= 1000;

        if (new_stats->tx.rate_capacity)
            client_result->stats.rate_tx = new_stats->tx.rate_capacity;

        if (new_stats->tx.rate_perceived)
            client_result->stats.rate_tx_perceived = new_stats->tx.rate_perceived;

        LOG(TRACE,
            "Calculated %s client delta stats for "
            MAC_ADDRESS_FORMAT" rate_tx=%0.2f/%0.2f",
            radio_get_name_from_type(radio_type),
            MAC_ADDRESS_PRINT(data_new->info.mac),
            client_result->stats.rate_tx,
            client_result->stats.rate_tx_perceived);
    }

    if (new_stats->rx.last_rate)
    {
        client_result->stats.rate_rx = new_stats->rx.last_rate;
        client_result->stats.rate_rx /= 1000;

        if (new_stats->rx.rate_capacity)
            client_result->stats.rate_rx = new_stats->rx.rate_capacity;

        if (new_stats->rx.rate_perceived)
            client_result->stats.rate_rx_perceived = new_stats->rx.rate_perceived;

        LOG(TRACE,
            "Calculated %s client delta stats for "
            MAC_ADDRESS_FORMAT" rate_rx=%0.2f/%0.2f",
            radio_get_name_from_type(radio_type),
            MAC_ADDRESS_PRINT(data_new->info.mac),
            client_result->stats.rate_rx,
            client_result->stats.rate_rx_perceived);
    }


    /* ----- ----- -----
     * Rate histogram (aka mcs) stats: */

    /* mcs RX: */
    ds_dlist_foreach(&new_stats->rate_histo_rx, mcs_wl)
    {
        dpp_client_stats_rx_t *mcs_dpp_rx = dpp_client_stats_rx_record_alloc();
        if (!mcs_wl_to_dpp(mcs_dpp_rx, mcs_wl, client_result->stats.bytes_rx, client_result->stats.rssi))
        {
            dpp_client_stats_rx_record_free(mcs_dpp_rx);
            continue;
        }
        ds_dlist_insert_tail(&client_result->stats_rx, mcs_dpp_rx);
    }

    /* mcs TX: */
    ds_dlist_foreach(&new_stats->rate_histo_tx, mcs_wl)
    {
        dpp_client_stats_tx_t *mcs_dpp_tx = dpp_client_stats_tx_record_alloc();
        if (!mcs_wl_to_dpp(mcs_dpp_tx, mcs_wl, client_result->stats.bytes_tx, 0))
        {
            dpp_client_stats_tx_record_free(mcs_dpp_tx);
            continue;
        }
        ds_dlist_insert_tail(&client_result->stats_tx, mcs_dpp_tx);
    }


    return true;
}

static void wl80211_client_tx_rate_stats_get(const char *ifname,
                                             wl80211_client_record_t *client)
{
    const uint8_t *mac = client->info.mac;
    const char *macstr = strfmta(MAC_ADDRESS_FORMAT, MAC_ADDRESS_PRINT(mac));
    struct bcmwl_sta_rate rate;

    if (WARN_ON(bcmwl_sta_get_tx_avg_rate(ifname, macstr, &rate) < 0))
        return;

    client->stats.tx.rate_capacity = rate.mbps_capacity;
    client->stats.tx.rate_perceived = rate.mbps_perceived;

    LOG(DEBUG, "PHY stats: %s: "MAC_ADDRESS_FORMAT": tx mbps=%.0f/%.0f psr=%1.2f snr=%"PRId32,
        ifname, MAC_ADDRESS_PRINT(mac),
        rate.mbps_capacity, rate.mbps_perceived,
        rate.psr, client->stats.rx.snr);
}

static int wl80211_client_sta_info_parse(
        FILE                       *file_desc,
        wl80211_client_ctx_t       *client_ctx)
{
    wl80211_client_record_t        *client;
    wl80211_client_stats_t         *client_entry;
    char                            buf[WL80211_CMD_BUFF_SIZE];
    char                           *k;
    char                           *v;
    size_t                          i;
    int                             err;

    /* WL80211 assoclist output example :
       [VER 5] STA 00:0F:55:B1:32:8A:
            aid:1
            rateset [ 1 2 5.5 6 9 11 12 18 24 36 48 54 ]
            idle 3 seconds
            in network 8187 seconds
            state: AUTHENTICATED ASSOCIATED AUTHORIZED
            flags 0x1e03a: WME N_CAP AMPDU AMSDU
            HT caps 0x17e: 40MHz GF SGI20 SGI40 STBC-Rx
            tx total pkts: 11811
            tx total bytes: 2188745
            tx ucast pkts: 4544
            tx ucast bytes: 1243136
            tx mcast/bcast pkts: 7267
            tx mcast/bcast bytes: 945609
            tx failures: 0
            rx data pkts: 4946
            rx data bytes: 645350
            rx ucast pkts: 4943
            rx ucast bytes: 644954
            rx mcast/bcast pkts: 3
            rx mcast/bcast bytes: 396
            rate of last tx pkt: 72222 kbps - 19500 kbps
            rate of last rx pkt: 52000 kbps
            rx decrypt succeeds: 4507
            rx decrypt failures: 1
            tx data pkts retried: 0
            per antenna rssi of last rx data frame: -89 -53 -43 -50
            per antenna average rssi of rx data frames: -89 -55 -44 -51
            per antenna noise floor: -102 -94 -92 -94
            tx total pkts sent: 4544
            tx pkts retries: 1493
            tx pkts retry exhausted: 0
            tx FW total pkts sent: 27
            tx FW pkts retries: 0
            tx FW pkts retry exhausted: 0
            rx total pkts retried: 45
        MCS SET : [ 0 1 2 3 4 5 6 7 32 ]
     */
    memset(buf, 0, sizeof(buf));
    if (fgets(buf, sizeof(buf) - 1, file_desc) == NULL)
        return 1;

    k = strstr(buf, "STA ");
    if (!k)
        return 2;

    k = strstr(k, " ");
    k++;

    if (strlen(k) < 1)
        return 3;

    client = wl80211_client_record_alloc();
    if (!client)
        return 4;
    client_entry = &client->stats;

    /* Populate client information data */
    client->info.type = client_ctx->radio_cfg->type;

    k[strlen(k) - 1] = 0;
    err = sscanf(k, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
            &client->info.mac[0], &client->info.mac[1], &client->info.mac[2],
            &client->info.mac[3], &client->info.mac[4], &client->info.mac[5]);
    if (err != 6) {
        LOGE("Parsing %s client MAC "MAC_ADDRESS_FORMAT,
            radio_get_name_from_type(client->info.type),
            MAC_ADDRESS_PRINT(client->info.mac));
        wl80211_client_record_free(client);
        return 5;
    }
    LOG(TRACE,
        "Parsed %s client MAC "MAC_ADDRESS_FORMAT,
        radio_get_name_from_type(client->info.type),
        MAC_ADDRESS_PRINT(client->info.mac));

    STRSCPY(client->info.ifname, client_ctx->ifname);
    LOG(TRACE,
        "Parsed %s client IFNAME %s",
        radio_get_name_from_type(client->info.type),
        client->info.ifname);

    STRSCPY(client->info.essid, client_ctx->ssid);
    LOG(TRACE,
        "Parsed %s client ESSID %s",
        radio_get_name_from_type(client->info.type),
        client->info.essid);

#define DUMPU32(name, var) LOG(TRACE, "Parsed %s: " name "=%u", radio_get_name_from_type(client->info.type), var)
#define DUMPU64(name, var) LOG(TRACE, "Parsed %s: " name "=%"PRIu64, radio_get_name_from_type(client->info.type), var)
#define GETU32(name, var) if (strcmp(k, name) == 0) { sscanf(v, "%u", var); DUMPU32(name, *(var)); }
#define GETU64(name, var) if (strcmp(k, name) == 0) { sscanf(v, "%"PRIu64, var); DUMPU64(name, *(var)); }

    client_entry->nss = 1;
    /* Populate client stats data */
    while (fgets(buf, sizeof(buf) - 1, file_desc))
    {
        buf[sizeof(buf) - 1] = 0;

        k = strtok(buf, ":");
        v = strtok(NULL, "");

        if (!k)
            continue;

        while (k[0] == ' ' || k[0] == '\t')
            k++;

        if (strcmp(k, "MCS SET ") == 0) {
            if (!v)
                continue;

            strtok(v, " ");
            while ((v = strtok(NULL, " ")))
                if (atoi(v) != 32)
                    client_entry->nss = MAX((int)client_entry->nss, (atoi(v) / 8) + 1);
        } else if (strstr(k, "rateset") == k) {
            client_entry->is11b = 1;
            strtok(k, " ");
            while ((v = strtok(NULL, " ")))
            {
                switch (atoi(v)) {
                    case 6:
                    case 9:
                    case 12:
                    case 18:
                    case 24:
                    case 36:
                    case 48:
                    case 54:
                        client_entry->is11b = 0;
                        break;
                }
            }
        } else if (strstr(k, "idle ") == k) {
            strtok(k, " ");
            v = strtok(NULL, " ");
            if (v)
                client_entry->idle = atoi(v);
        } else if (strstr(k, "HT caps ") == k) {
            if (!v)
                continue;

            client_entry->is11n = 1;
            strtok(v, " ");
            do {
                if (strstr(v, "MHz"))
                    client_entry->bw = atoi(v);
            } while ((v = strtok(NULL, " ")));
        } else if (strstr(k, "per antenna rssi of last rx data frame")) {
            if (!v)
                continue;

            v = strtok(v, " ");
            for (i = 0; i < ARRAY_SIZE(client_entry->rx.last_rssi); i++) {
                if (!v)
                    break;

                client_entry->rx.last_rssi[i] = atoi(v);
                if (client_entry->rx.last_rssi[i] > 0) {
                    LOG(WARN, "Invalid RSSI read from driver: %d. Assume zero.",
                               client_entry->rx.last_rssi[i]);
                    client_entry->rx.last_rssi[i] = 0;
                }

                v = strtok(NULL, " ");
            }
        } else if (strstr(k, "per antenna noise floor")) {
            if (!v)
                continue;

            v = strtok(v, " ");
            for (i = 0; i < ARRAY_SIZE(client_entry->rx.noise); i++) {
                if (!v)
                    break;

                client_entry->rx.noise[i] = atoi(v);
                if (client_entry->rx.noise[i] > 0) {
                    LOG(WARN, "Invalid noise floor read from driver: %d. Assume zero.",
                              client_entry->rx.noise[i]);
                    client_entry->rx.noise[i] = 0;
                }

                v = strtok(NULL, " ");
            }
        }

        GETU32("tx ucast pkts", &client_entry->tx.ucast_pkts);
        GETU64("tx ucast bytes", &client_entry->tx.ucast_bytes);
        GETU32("tx mcast/bcast pkts", &client_entry->tx.mcast_pkts);
        GETU64("tx mcast/bcast bytes", &client_entry->tx.mcast_bytes);
        GETU32("tx failures", &client_entry->tx.errors);
        GETU32("tx pkts retries", &client_entry->tx.retries);
        GETU32("rate of last tx pkt", &client_entry->tx.last_rate);
        GETU32("rx ucast pkts", &client_entry->rx.ucast_pkts);
        GETU64("rx ucast bytes", &client_entry->rx.ucast_bytes);
        GETU32("rx mcast/bcast pkts", &client_entry->rx.mcast_pkts);
        GETU64("rx mcast/bcast bytes", &client_entry->rx.mcast_bytes);
        GETU32("rx total pkts retried", &client_entry->rx.retries);
        GETU32("rx decrypt failures", &client_entry->rx.errors);
        GETU32("rate of last rx pkt", &client_entry->rx.last_rate);
    }
#undef GETU32
#undef GETU64
#undef DUMPU32
#undef DUMPU64

    client_entry->rx.snr = client_entry->rx.last_rssi[0] - client_entry->rx.noise[0];
    for (i = 1; i < ARRAY_SIZE(client_entry->rx.last_rssi); i++) {
        client_entry->rx.snr =
            MAX(client_entry->rx.snr,
                client_entry->rx.last_rssi[i] - client_entry->rx.noise[i]);
    }

    LOG(TRACE,
        "Parsed %s client RSSI %d",
        radio_get_name_from_type(client->info.type),
        client_entry->rx.snr);


    /* Now, let's get mcs (rate histogram) stats for this client: */
    wl80211_client_mcs_stats_get(client_ctx->ifname, client);
    wl80211_client_tx_rate_stats_get(client_ctx->ifname, client);


    ds_dlist_insert_tail(client_ctx->list, client);

    return 0;
}

enum mcs_supported_e
{
    MCS_UNKNOWN = 0,
    MCS_NOT_SUPPORTED,
    MCS_SUPPORTED
};

#define MCS_MAX_PHY 4

static bool wl80211_mcs_stats_supported(const char *ifname)
{
    static enum mcs_supported_e g_mcs_supported[MCS_MAX_PHY];
    int ri, vi;
    if (!bcmwl_parse_vap(ifname, &ri, &vi)) return false;
    if (ri >= MCS_MAX_PHY) return false;
    if (g_mcs_supported[ri] == MCS_UNKNOWN) {
        // using rate_histo_report without mac parameter to get the output:
        //   wl: Unsupported
        // otherwise with mac parameter it prints:
        //   set: error parsing value "00:11:22:33:44:55" as an integer for set of "rate_histo_report"
        //   var     unrecognized name, type -h for help
        // first option is more predictable and easier to parse
        // note, the error is printed on stderr, hence 2>&1
        char buf[WL80211_CMD_BUFF_SIZE] = {0};
        wl80211_cmd_exec(buf, sizeof(buf), "wl -i wl%d rate_histo_report 2>&1", ri);
        if (strstr(buf, "Unsupported")) {
            g_mcs_supported[ri] = MCS_NOT_SUPPORTED;
            LOGI("wl%d rate_histo_report: not supported", ri);
        } else {
            g_mcs_supported[ri] = MCS_SUPPORTED;
            LOGI("wl%d rate_histo_report: supported", ri);
        }
    }
    return g_mcs_supported[ri] == MCS_SUPPORTED;
}


static void wl80211_client_mcs_stats_get(
        const char *ifname,
        wl80211_client_record_t *client)
{
    uint8_t *macaddr = client->info.mac;
    char cmd[WL80211_CMD_BUFF_SIZE];
    FILE *f = 0;

    if (!kconfig_enabled(CONFIG_BCM_USE_RATE_HISTO)) {
        return;
    }

    if (!wl80211_mcs_stats_supported(ifname)) {
        return;
    }

    /* Compose and run shell cmd: "wl -i <interface> rate_histo_report:" */
    memset(cmd, 0, sizeof(cmd));
    snprintf(cmd, sizeof(cmd)-1, WL80211_CLIENT_MCS_GET, ifname,
             macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4],
             macaddr[5]);

    f = popen(cmd, "r");
    if (!f)
    {
        LOG(ERR, "Error executing %s: %s", cmd, strerror(errno));
        return;
    }

    LOG(INFO, "Getting MCS stats for client: %s:"MAC_ADDRESS_FORMAT"",
               ifname, MAC_ADDRESS_PRINT(macaddr));

    if (wl80211_client_mcs_stats_parse(f, client))
        LOG(ERR, "Error parsing client mcs stats.");
    pclose(f);
}


static const char* mcs_parse_legacy_line_token(
        const char *token,
        uint32_t   *rate,
        uint64_t   *pkts)
{
    uint32_t mbps = 0;
    uint64_t num_pkts = 0;
    int ret;

    *rate = 0;
    *pkts = 0;

    if (!token)
        return NULL;

    ret = sscanf(token, " %uMbps: %"PRIu64"", &mbps, &num_pkts);
    if (ret == 2)
    {
        *rate = mbps;
        *pkts = num_pkts;

        token = strchr(token, ')');
        if (!token)
            return NULL;
        token++;
        if (*token == '\0')
            return NULL;
        else
            return token;
    }
    else
    {
        return NULL;
    }
}


static uint32_t mcs_to_mbps(const int mcs, const int bw, const int nss)
{
    /* The following table is precomputed from:
     *
     * bpsk -> 1bit
     * qpsk -> 2bit
     * 16-qam -> 4bit
     * 64-qam -> 6bit
     * 256-qam -> 8bit
     *
     * 20mhz -> 52 tones
     * 40mhz -> 108 tones
     * 80mhz -> 234 tones
     * 160mhz -> 486 tones
     *
     * Once divided by 4 will get an long GI phyrate.
     */
    static const unsigned short bps[10][4] = {
        /* 20mhz 40mhz 80mhz  160mhz */
        {  26,   54,   117,   234   }, /* BPSK 1/2 */
        {  52,   108,  234,   468   }, /* QPSK 1/2 */
        {  78,   162,  351,   702   }, /* QPSK 3/4 */
        {  104,  216,  468,   936   }, /* 16-QAM 1/2 */
        {  156,  324,  702,   1404  }, /* 16-QAM 3/4 */
        {  208,  432,  936,   1248  }, /* 16-QAM 2/3 */
        {  234,  486,  1053,  2106  }, /* 64-QAM 3/4 */
        {  260,  540,  1170,  2340  }, /* 64-QAM 5/6 */
        {  312,  648,  1404,  2808  }, /* 256-QAM 3/4 */
        {  346,  720,  1560,  3120  }, /* 256-QAM 5/6 */
    };
    const int i = mcs < 10 ? mcs : 9;
    const int j = bw == 20 ? 0 :
                  bw == 40 ? 1 :
                  bw == 80 ? 2 :
                  bw == 160 ? 3 : 0;
    return (bps[i][j] * nss) / 4; /* hopefully compiler makes a bitshift */
}


static int wl80211_client_mcs_stats_parse(FILE *f, wl80211_client_record_t *client)
{

    wl80211_client_stats_t         *client_entry = &client->stats;

    char                            line_buf[256];
    int                             line_num = 0;
    bool                            is_tx_entry = false;
    int ret;

    unsigned version = 0;
    unsigned report_type = 0;
    uint64_t rx_total = 0;
    uint64_t tx_total = 0;
    uint32_t duration = 0;
    uint64_t non_legacy = 0;
    uint64_t tx_phyrate = 0;
    uint64_t rx_phyrate = 0;
    uint32_t tx_mpdus = 0;
    uint32_t rx_mpdus = 0;
    uint64_t mbps;


    line_num = 0;
    while (fgets(line_buf, sizeof(line_buf), f))
    {
        line_buf[strlen(line_buf)-1] = '\0';
        line_num++;

        if (line_num == 1)  /* Version */
        {
            ret = sscanf(line_buf, "Version: %u", &version);
            if (ret != 1 || version != WL_MCS_REPORT_VERSION)
            {
                LOG(ERROR, "ERROR: Error parsing rate_histo_report. "
                            "Unsupported version: %u", version);
                return -1;
            }
            continue;
        }
        else if (line_num == 2)  /* Report type */
        {
            ret = sscanf(line_buf, "Report type: %u", &report_type);
            if (ret != 1 || report_type != WL_MCS_REPORT_TYPE)
            {
                LOG(ERROR, "Error parsing rate_histo_report. "
                           "Unsupported report type: %u", report_type);
                return -1;
            }
            continue;
        }

        /* Rx total, duration: */
        ret = sscanf(line_buf, "Rx total:%"PRIu64", recent rate type: %*s duration: "
                               "%us", &rx_total, &duration);
        if (ret == 2)
        {
            is_tx_entry = false;
            continue;
        }
        /* Tx total, duration: */
        ret = sscanf(line_buf, "Tx total:%"PRIu64", recent rate type: %*s duration: "
                               "%us", &tx_total, &duration);
        if (ret == 2)
        {
            is_tx_entry = true;  /* Mark begin of TX entries section */
            continue;
        }


        ret = sscanf(line_buf, " total Legacy/non: %*u/%"PRIu64"", &non_legacy);
        if (ret == 1)
        {
            if (is_tx_entry)
                LOG(DEBUG, "Parsed TX non_legacy=%"PRIu64"", non_legacy);
            else
                LOG(DEBUG, "Parsed RX non_legacy=%"PRIu64"", non_legacy);

            continue;
        }


        /*  Lines such as:
         *   "1Mbps: 0(0%)     2Mbps: 0(0%)     5Mbps: 0(0%)     6Mbps: 10(1%) \
         *      9Mbps: 0(0%)     11Mbps: 0(0%)"
         */
        if (STR_BEGINS_WITH(line_buf, "1Mbps: ") || STR_BEGINS_WITH(line_buf, "12Mbps: "))
        {
            uint32_t rate;
            uint64_t pkts;
            const char *token;

            if (non_legacy > 0)
            {
                /* If at least one rate is in non-legacy format, then all the rates
                 * (legacy and non-legacy) are present in rate histogram
                 * lines and we will parse them there (next case). */
                continue;
            }

            token = line_buf;
            do
            {
                token = mcs_parse_legacy_line_token(token, &rate, &pkts);
                if (rate) /* rate token parsed */
                {
                    if (pkts == 0)
                        continue; /* skip if packet count 0 */

                    if (kconfig_enabled(CONFIG_BCM_USE_RATE_HISTO_TO_EXPECTED_TPUT)) {
                        mbps = rate;
                        mbps *= pkts;

                        if (is_tx_entry) {
                            tx_phyrate += mbps;
                            tx_mpdus += pkts;
                        } else {
                            rx_phyrate += mbps;
                            rx_mpdus += pkts;
                        }

                        /* histograms have been converted to
                         * expected throughput. there's no need to
                         * allocate and send out histograms anymore
                         * so skip them.
                         */
                        continue;
                    }

                    wl80211_client_mcs_stats_t *rate_histo = wl80211_client_mcs_stats_alloc();
                    rate_histo->freq = 20;
                    rate_histo->pkts = pkts;
                    if (is_tx_entry)
                        rate_histo->pkts_total = tx_total;
                    else
                        rate_histo->pkts_total = rx_total;
                    rate_histo->rate = rate;
                    rate_histo->duration = duration;

                    /* New legacy rate parsed. Insert it into a corresponding list: */
                    if (is_tx_entry)
                        ds_dlist_insert_tail(&client_entry->rate_histo_tx, rate_histo);
                    else
                        ds_dlist_insert_tail(&client_entry->rate_histo_rx, rate_histo);

                    LOG(DEBUG, "MCS stats: %s (%s): "MAC_ADDRESS_FORMAT
                               " Parsed new rate entry: %s: "
                               "rate=%u, pkts=%"PRIu64" "
                               "(total=%"PRIu64"), duration=%u",
                               client->info.ifname, client->info.essid,
                               MAC_ADDRESS_PRINT(client->info.mac),
                               (is_tx_entry ? "TX" : "RX"), rate, pkts,
                               rate_histo->pkts_total,
                               duration);
                }
            } while (token);

            continue;
        }


        /*
         * Rate histogram lines. Lines such as:
         *   "@ 20MHz 6Mbps: 10(1%)        |"
         *   "@ 80MHz  7x2: 57666(35%)     |=======" */
        if (line_buf[0] == '@')
        {
            wl80211_client_mcs_stats_t *rate_histo = 0;
            uint32_t freq = 0;
            uint32_t mcs = 0;
            uint32_t nss = 0;
            uint64_t pkts = 0;
            uint32_t rate = 0;

            /* mcs/ncs format: */
            ret = sscanf(line_buf, "@ %uMHz %ux%u: %"PRIu64"", &freq, &mcs, &nss, &pkts);
            if (ret != 4)
            {
                /* legacy format: */
                ret = sscanf(line_buf, "@ %uMHz %uMbps: %"PRIu64"", &freq, &rate, &pkts);
                if (ret != 3) /* parse error */
                {
                    LOG(ERROR, "ERROR parsing RX/TX rate histogram line: %s", line_buf);
                    continue;
                }
            }

            if (kconfig_enabled(CONFIG_BCM_USE_RATE_HISTO_TO_EXPECTED_TPUT)) {
                mbps = rate ?: mcs_to_mbps(mcs, freq, nss);
                mbps *= pkts;

                if (is_tx_entry) {
                    tx_phyrate += mbps;
                    tx_mpdus += pkts;
                } else {
                    rx_phyrate += mbps;
                    rx_mpdus += pkts;
                }

                /* histograms have been converted to
                 * expected throughput. there's no need to
                 * allocate and send out histograms anymore
                 * so skip them.
                 */
                continue;
            }

            rate_histo = wl80211_client_mcs_stats_alloc();

            rate_histo->freq = freq;
            rate_histo->mcs = mcs;
            rate_histo->nss = nss;
            rate_histo->pkts = pkts;

            if (is_tx_entry)
                rate_histo->pkts_total = tx_total;
            else
                rate_histo->pkts_total = rx_total;

            rate_histo->rate = rate;
            rate_histo->duration = duration;

            /* New rate histogram / mcs entry parsed. Insert it into a corresponding list: */
            if (is_tx_entry)
                ds_dlist_insert_tail(&client_entry->rate_histo_tx, rate_histo);
            else
                ds_dlist_insert_tail(&client_entry->rate_histo_rx, rate_histo);

            LOG(DEBUG, "MCS stats: %s (%s): "MAC_ADDRESS_FORMAT
                       " Parsed new delta histogram entry: %s: "
                       "freq=%u, mcs=%u, nss=%u, rate=%u, pkts=%"PRIu64" "
                       "(total=%"PRIu64"), duration=%u",
                       client->info.ifname, client->info.essid,
                       MAC_ADDRESS_PRINT(client->info.mac),
                       (is_tx_entry ? "TX" : "RX"), freq, mcs, nss, rate, pkts,
                       rate_histo->pkts_total,
                       duration);
        }
    }

    if (kconfig_enabled(CONFIG_BCM_USE_RATE_HISTO_TO_EXPECTED_TPUT)) {
        if (tx_mpdus) {
            tx_phyrate /= tx_mpdus;
            client->stats.tx.rate_capacity = tx_phyrate;
            client->stats.tx.rate_perceived = tx_phyrate;
        }

        if (rx_mpdus) {
            rx_phyrate /= rx_mpdus;
            client->stats.rx.rate_capacity = rx_phyrate;
            client->stats.rx.rate_perceived = rx_phyrate;
        }

        LOG(DEBUG, "MCS expected tput: %s (%s): "MAC_ADDRESS_FORMAT
                   " Computed phy rates: tx=%" PRIu64 " (pkts=%u) rx=%" PRIu64 " (pkts=%u)",
                   client->info.ifname, client->info.essid,
                   MAC_ADDRESS_PRINT(client->info.mac),
                   tx_phyrate, tx_mpdus,
                   rx_phyrate, rx_mpdus);
    }

    return 0;
}


static void wl80211_client_assoclist_cb(
        const char                 *macaddr,
        wl80211_client_ctx_t       *client_ctx)
{
    char                            cmd[WL80211_CMD_BUFF_SIZE];
    FILE                           *file_desc;


    /* Get client stats for interface */
    memset(cmd, 0, sizeof(cmd));
    snprintf(cmd, sizeof(cmd) - 1,
            WL80211_CLIENT_STATS_GET,
            client_ctx->ifname,
            macaddr[0], macaddr[1], macaddr[2],
            macaddr[3], macaddr[4], macaddr[5]);

    LOG(TRACE,
        "Initiating %s command '%s'",
        radio_get_name_from_type(client_ctx->radio_cfg->type),
        cmd);

    file_desc = popen(cmd, "r");
    if (!file_desc)
        return;

    wl80211_client_sta_info_parse(file_desc, client_ctx);

    pclose(file_desc);
}

static void wl80211_client_assoclist_parse(
        FILE                       *file_desc,
        void (*cb)(const char *macaddr, wl80211_client_ctx_t *ctx),
        wl80211_client_ctx_t       *client_ctx)
{
    char                            buf[WL80211_CMD_BUFF_SIZE];
    char                            macaddr[6];
    int                             err;

    /* WL80211 assoclist output example :

       assoclist E8:DE:27:19:1B:98
       assoclist 08:DE:27:19:1B:98
       assoclist E8:DE:27:19:1B:38
     */
    memset(buf, 0, sizeof(buf));
    memset(macaddr, 0, sizeof(macaddr));

    if (!file_desc)
        return;

    while (fgets(buf, sizeof(buf) - 1, file_desc))
    {
        err = sscanf(buf, "assoclist %2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
                &macaddr[0], &macaddr[1], &macaddr[2],
                &macaddr[3], &macaddr[4], &macaddr[5]);
        if (err != 6)
            continue;


        /* Callback that shall get stats for client with specified macaddr: */
        cb(macaddr, client_ctx);
    }
}

static void wl80211_client_rxavgrate_cb(
        const char                  *ifname,
        const char                  *mac_octet,
        const struct bcmwl_sta_rate *rate,
        void                        *arg)
{
    wl80211_client_ctx_t *ctx = arg;
    wl80211_client_record_t *client;

    ds_dlist_foreach(ctx->list, client) {
        if (strcmp(client->info.ifname, ifname))
            continue;
        if (memcmp(client->info.mac, mac_octet, sizeof(client->info.mac)))
            continue;

        client->stats.rx.rate_capacity = rate->mbps_capacity;
        client->stats.rx.rate_perceived = rate->mbps_perceived;

        LOGD("PHY stats: %s: "MAC_ADDRESS_FORMAT": tx mbps=%.0f/%.0f psr=%1.2f",
             ifname, MAC_ADDRESS_PRINT(client->info.mac),
             rate->mbps_capacity, rate->mbps_perceived,
             rate->psr);
        return;
    }
}


/******************************************************************************
 *  PUBLIC definitions
 *****************************************************************************/

bool wl80211_client_list_get(
        radio_entry_t              *radio_cfg,
        char                       *ifname,
        ds_dlist_t                 *client_data)
{
    wl80211_client_ctx_t            client_ctx;
    char                            cmd[WL80211_CMD_BUFF_SIZE];
    char                            buf[WL80211_CMD_BUFF_SIZE] = {0};
    char                            wl_ssid[256];
    FILE                           *file_desc;

    memset(&client_ctx, 0, sizeof(client_ctx));
    client_ctx.radio_cfg = radio_cfg;
    client_ctx.ifname    = ifname;
    client_ctx.list      = client_data;


    LOG(TRACE,
        "Initiating %s command '"WL80211_CLIENT_SSID_GET"'",
        radio_get_name_from_type(radio_cfg->type),
        ifname);

    /* Don't even try `wl assoc` if the bss is down. This
     * avoids needless kernel log warnings from more recent
     * driver builds like these:
     *
     *   Apr  1 11:47:06 kernel: [ 1424.149337] dhd_prot_ioctl: status ret value is -17
     *
     */
    if (strcmp(WL(ifname, "bss") ?: "", "up"))
        return true;

    wl80211_cmd_exec(
            buf,
            sizeof(buf),
            WL80211_CLIENT_SSID_GET,
            ifname);

    /* get SSID */
    // get first line only
    strtok(buf, "\n");
    // check if empty string
    if (*buf == 0) {
        /* Skip interfaces with no network association */
        return true;
    }
    if (sizeof(wl_ssid) < strlen(buf)+1)
    {
        LOG(ERROR, "wl reported SSID too long: '%s'", buf);
        return false;
    }
    STRSCPY(wl_ssid, buf);

    LOG(TRACE,
        "Parsed %s %s SSID '%s' (len: %zu)",
        radio_get_name_from_type(radio_cfg->type),
        ifname,
        wl_ssid,
        strlen(wl_ssid));


    /* SSID string wl tool is reporting may contain \xXX escaped
     * characters, so we may need to unescape those to get the
     * real SSID bytes.
     */
    str_unescape_hex(wl_ssid);

    STRSCPY(client_ctx.ssid, wl_ssid);

    LOG(TRACE,
        "Parsed %s %s SSID '%s' (len: %zu)",
        radio_get_name_from_type(radio_cfg->type),
        ifname,
        client_ctx.ssid,
        strlen(client_ctx.ssid));



    /* Get client on interface */
    memset(cmd, 0, sizeof(cmd));
    snprintf(cmd, sizeof(cmd) - 1,
            WL80211_CLIENT_LIST_GET,
            ifname);

    LOG(TRACE,
        "Initiating %s command '%s'",
        radio_get_name_from_type(radio_cfg->type),
        cmd);

    file_desc = popen(cmd, "r");
    if (!file_desc) {
        return false;
    }

    wl80211_client_assoclist_parse(
            file_desc,
            wl80211_client_assoclist_cb,
            &client_ctx);

    pclose(file_desc);

    bcmwl_sta_get_rx_avg_rate(
            ifname,
            wl80211_client_rxavgrate_cb,
            &client_ctx);

    return true;
}

bool wl80211_client_stats_convert(
        radio_entry_t              *radio_cfg,
        wl80211_client_record_t    *data_new,
        wl80211_client_record_t    *data_old,
        dpp_client_record_t        *client_result)
{
    bool                           status;

    /* Update delta stats for clients/peers */
    status =
        wl80211_client_stats_calculate (
                radio_cfg,
                data_new,
                data_old,
                client_result);
    if (true != status) {
        return false;
    }

    return true;
}
