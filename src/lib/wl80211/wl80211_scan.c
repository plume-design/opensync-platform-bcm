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

#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <ev.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/types.h>
#include <inttypes.h>

#include "os.h"
#include "os_time.h"
#include "util.h"
#include "log.h"

#include "wl80211.h"
#include "wl80211_scan.h"

#define MODULE_ID LOG_MODULE_ID_WL

// Delay and retry logic is only used when "wl escanresults" is not available.
// Also, it might be better to run "wl scan" and wait for WLC_E_SCAN_COMPLETE
// event, instead of doing retries.
#define WL80211_SCAN_RETRY_COUNT    (3)
#define WL80211_SCAN_RETRY_TIMEOUT  (150 * 1000.0)

typedef struct {
    mac_address_str_t               bssid;
    radio_essid_t                   ssid;
    char                            role[16 + 1];
    int                             rssi;
    int                             chan_capture;
    int                             chan_control;
    int                             chan_center;
    int                             noise;
    int                             bw;
    uint64_t                        lastseen;
    ds_dlist_node_t                 node;
} wl80211_scan_record_t;

static ds_dlist_t                   g_wl80211_scan_list =
                                        DS_DLIST_INIT(
                                                wl80211_scan_record_t,
                                                node);


static inline wl80211_scan_record_t* wl80211_scan_record_alloc()
{
    wl80211_scan_record_t *record = NULL;

    record = malloc(sizeof(wl80211_scan_record_t));
    if (record)
    {
        memset(record, 0, sizeof(wl80211_scan_record_t));
    }

    return record;
}

static inline void wl80211_scan_record_free(wl80211_scan_record_t *record)
{
    if (NULL != record)
    {
        free(record);
    }
}


/******************************************************************************
 *  PROTECTED definitions
 *****************************************************************************/

static radio_chanwidth_t wl80211_scan_chanwidth_get(const wl80211_scan_record_t *record)
{
    switch (record->bw) {
        case 20:
            return RADIO_CHAN_WIDTH_20MHZ;
        case 40:
            if (record->chan_control > record->chan_center)
                return RADIO_CHAN_WIDTH_40MHZ_BELOW;
            else if (record->chan_control < record->chan_center)
                return RADIO_CHAN_WIDTH_40MHZ_ABOVE;
            else
                return RADIO_CHAN_WIDTH_40MHZ;
        case 80:
            return RADIO_CHAN_WIDTH_80MHZ;
        case 160:
            return RADIO_CHAN_WIDTH_160MHZ;
    }

    return RADIO_CHAN_WIDTH_NONE;
}

static bool wl80211_scan_results_convert(
        radio_entry_t              *radio_cfg,
        dpp_neighbor_report_data_t *scan_results)
{
    dpp_neighbor_record_list_t     *neighbor;
    dpp_neighbor_record_t          *entry;
    radio_bssid_t                   bssid;

    wl80211_scan_record_t          *record = NULL;
    ds_dlist_iter_t                 record_iter;

    for (   record = ds_dlist_ifirst(&record_iter, &g_wl80211_scan_list);
            record != NULL;
            record = ds_dlist_inext(&record_iter))
    {
        neighbor = dpp_neighbor_record_alloc();
        if (!neighbor)
            return false;
        entry = &neighbor->entry;

        entry->type         = radio_cfg->type;
        entry->lastseen     = record->lastseen;
        entry->sig          = record->rssi - record->noise;

        LOG(TRACE, "RSSI on node: %s, rssi: %d noise %d snr: %d",
            record->bssid, record->rssi, record->noise, entry->sig);

        /* Prevent sending negative values */
        if (entry->sig < 0) {
            entry->sig = 0;
            LOG(TRACE, "Found negative signal/noise ratio, forcing value to 0");
        }
        entry->chan         = record->chan_control;
        entry->chanwidth    = wl80211_scan_chanwidth_get(record);
        STRSCPY(entry->ssid, record->ssid);
        STRSCPY(bssid, record->bssid);
        STRSCPY(entry->bssid, str_tolower(bssid));

        ds_dlist_insert_tail(&scan_results->list, neighbor);

        ds_dlist_iremove(&record_iter);
        wl80211_scan_record_free(record);
        record = NULL;
    }

    return true;
}

static bool wl80211_scan_results_parse(
        radio_type_t                radio_type,
        FILE                       *file_desc)
{
    wl80211_scan_record_t          *entry = NULL;
    char                            buf[WL80211_CMD_BUFF_SIZE];
    char                            wl_ssid[256];
    char                           *rssi;
    char                           *noise;
    char                           *chan;
    char                           *bw;
    char                           *k;
    char                           *v;


    /*
    SSID: "BELL894"
          Mode: Managed   RSSI: -25 dBm   SNR: 0 dB       noise: -68 dBm  Flags: RSSI on-channel  Channel: 11
          BSSID: 88:A6:C6:82:14:36        Capability: ESS WEP ShortPre ShortSlot
          Supported Rates: [ 1(b) 2(b) 5.5(b) 6 9 11(b) 12 18 24 36 48 54 ]
          RSN (WPA2):
              multicast cipher: AES-CCMP
              unicast ciphers(1): AES-CCMP
              AKM Suites(1): WPA2-PSK
              Capabilities(0x0000): No Pre-Auth, Pairwise, 1 PTK Replay Ctr1 GTK Replay Ctr
          HT Capable:
              Chanspec: 2.4GHz channel 9 40MHz (0x1909)
              Primary channel: 11
              HT Capabilities: 40Mhz SGI20 SGI40
              Supported HT MCS : 0-23 96
              WPS: V2.0 Configured
    SSID: "plume-test-auto"
         Mode: Managed   RSSI: -44 dBm   SNR: 0 dB       noise: -68 dBm  Flags: RSSI on-channel  Channel: 11
         BSSID: E2:B4:F7:00:26:51        Capability: ESS WEP ShortPre ShortSlot
         Supported Rates: [ 1(b) 2(b) 5.5(b) 6 9 11(b) 12 18 24 36 48 54 ]
         RSN (WPA2):
             multicast cipher: AES-CCMP
             unicast ciphers(1): AES-CCMP
             AKM Suites(1): WPA2-PSK
             Capabilities(0x0000): No Pre-Auth, Pairwise, 1 PTK Replay Ctr1 GTK Replay Ctr
         HT Capable:
             Chanspec: 2.4GHz channel 9 40MHz (0x1909)
             Primary channel: 11
             HT Capabilities: 40Mhz SGI20 SGI40
             Supported HT MCS : 0-15 96
    */

    if (!file_desc)
        return false;

    memset(buf, 0, sizeof(buf));
    while (fgets(buf, sizeof(buf) - 1, file_desc))
    {
        buf[sizeof(buf) - 1] = 0;

        k = strtok(buf, ":");
        v = strtok(NULL, "");  // rest of the line

        if (!k || !v)
            continue;

        while (k[0] == ' ' || k[0] == '\t')
            k++;

        if (strcmp(k, "SSID") == 0) {
            if (entry) {
                if (strlen(entry->bssid) > 0) {
                    LOG(TRACE,
                        "Parsed %s chanwidth %d",
                        radio_get_name_from_type(radio_type),
                        wl80211_scan_chanwidth_get(entry));
                    ds_dlist_insert_tail(&g_wl80211_scan_list, entry);
                }
            }

            entry = wl80211_scan_record_alloc();
            if (!entry)
                return false;

            memset(wl_ssid, 0, sizeof(wl_ssid));
            v = strtok(v, "\"");

            if (!v)
                continue;
            v = strtok(NULL, "\"");
            if (v)
            {
                STRSCPY(wl_ssid, v);

                // remove empty "\n" strings
                if ((strlen(v) == 1) && (wl_ssid[0] == 0x0A))
                {
                    LOG(TRACE, "EMPTY SSID...");
                    wl_ssid[0] = 0;
                }
                else
                {
                    LOG(TRACE, "Parsed %s SSID %s (len: %zu)",
                        radio_get_name_from_type(radio_type),
                        wl_ssid, strlen(v));
                }
            }
            else
            {
                LOG(TRACE,
                    "Parsed %s hidden SSID ",
                    radio_get_name_from_type(radio_type));
            }

            /* SSID string may contain \xXX escaped characters, so we may
             * need to unescape those to get the real SSID bytes.
             */
            str_unescape_hex(wl_ssid);

            STRSCPY(entry->ssid, wl_ssid);

            LOG(TRACE,
                "Parsed %s SSID '%s' (len: %zu)",
                radio_get_name_from_type(radio_type),
                entry->ssid, strlen(entry->ssid));

        } else if (strcmp(k, "Mode") == 0) {
            char buf_mode[256];
            STRSCPY(buf_mode, v);

            LOG(TRACE, "\n\n %s \n\n", buf_mode);

            rssi = strstr(buf_mode, "RSSI:");
            noise = strstr(buf_mode, "noise:");
            chan = strstr(buf_mode, "Channel:");
            v = strtok(v, " ");
            if (v)
                STRSCPY(entry->role, v);

            if (rssi) {
                strtok(rssi, ":");
                rssi = strtok(NULL, " ");
                if (rssi) {
                    entry->rssi = atoi(rssi);
                }

                if (rssi == 0)
                {
                    LOG(TRACE, "\n NULL RSSI DETECTED? \n");
                }
            }

            if (noise) {
                strtok(noise, ":");
                noise = strtok(NULL, " ");
                if (noise)
                    entry->noise = atoi(noise);
            }

            if (chan) {
                strtok(chan, ":");
                chan = strtok(NULL, " ");
                if (chan) {
                    entry->chan_capture = atoi(chan);
                }
            }
        } else if (strcmp(k, "BSSID") == 0) {
            v = strtok(v, " ");
            if (v) {
                STRSCPY(entry->bssid, v);

                LOG(TRACE,
                    "Parsed %s BSSID %s",
                    radio_get_name_from_type(radio_type),
                    entry->bssid);

                entry->lastseen = time(NULL);
                LOG(TRACE,
                    "Parsed %s lastseen %"PRIu64,
                    radio_get_name_from_type(radio_type),
                    entry->lastseen);
            }
        } else if (strcmp(k, "Chanspec") == 0) {
            chan = strstr(v, "channel");

            if (chan) {
                strtok(chan, " ");
                chan = strtok(NULL, " ");
                if (chan)
                    entry->chan_center = atoi(chan);
                bw = strtok(NULL, " ");
                if (bw && strstr(bw, "MHz"))
                    entry->bw = atoi(bw);
            }
        } else if (strcmp(k, "Primary channel") == 0) {
            entry->chan_control = atoi(v);

            LOG(TRACE,
                "Parsed %s chan %u",
                radio_get_name_from_type(radio_type),
                entry->chan_control);
        }
    }

    if (entry) {
        if (strlen(entry->bssid) > 0) {
            LOG(TRACE,
                "Parsed %s chanwidth %d",
                radio_get_name_from_type(radio_type),
                wl80211_scan_chanwidth_get(entry));
            ds_dlist_insert_tail(&g_wl80211_scan_list, entry);
        }
    }

    return true;
}


/******************************************************************************
 *  PUBLIC definitions
 *****************************************************************************/

bool wl80211_scan_channel(
        radio_entry_t              *radio_cfg,
        uint32_t                   *chan_list,
        uint32_t                    chan_num,
        radio_scan_type_t           scan_type,
        int32_t                     dwell_time,
        wl80211_scan_cb_t          *scan_cb,
        void                       *scan_ctx)
{
    int                             rc;
    char                           *scan_cmd;
    bool                            scan_status = false;
    bool                            scan_retry = false;
    int                             scan_retry_cnt = 0;
    char                            cmd[WL80211_CMD_BUFF_SIZE] = {};
    FILE                           *file_desc;

    if (wl80211_have_wl_escanresults()) {
        scan_cmd = WL80211_SCAN_CMD_ESCAN;
    } else {
        scan_cmd = WL80211_SCAN_CMD_SCAN;
    }


    if (scan_type == RADIO_SCAN_TYPE_OFFCHAN) {
        snprintf(cmd, sizeof(cmd) - 1,
                WL80211_SCAN_OFFCHAN_RESULTS_GET,
                radio_cfg->if_name,
                scan_cmd,
                chan_list[0],
                dwell_time);
    } else if (scan_type == RADIO_SCAN_TYPE_ONCHAN) {
        snprintf(cmd, sizeof(cmd) - 1,
                WL80211_SCAN_ONCHAN_RESULTS_GET,
                radio_cfg->if_name,
                scan_cmd,
                chan_list[0]);
    } else if (scan_type == RADIO_SCAN_TYPE_FULL) {
#define SCAN_CHAN_STR_SIZE      4
#define SCAN_CHANLIST_STR_SIZE  128
        char     chan[SCAN_CHAN_STR_SIZE];
        char     chanlist[SCAN_CHANLIST_STR_SIZE];
        uint32_t chan_index;

        memset (chanlist, 0, sizeof(chanlist));
        for (chan_index = 0; chan_index < chan_num; chan_index++) {
            sprintf(chan, "%d,", chan_list[chan_index]);
            strcat(chanlist, chan);
        }
#undef SCAN_CHAN_STR_SIZE
#undef SCAN_CHANLIST_STR_SIZE

        snprintf(cmd, sizeof(cmd) - 1,
                WL80211_SCAN_FULL_RESULTS_GET,
                radio_cfg->if_name,
                scan_cmd,
                chanlist,
                dwell_time);
    } else {
        return false;
    }

    LOG(TRACE,
        "Initiating %s command '%s'",
        radio_get_name_from_type(radio_cfg->type),
        cmd);

    // In case that "wl escanresults" command is not available we need to use
    // a combination of "wl scan" and "wl scanresults" commands.
    if (wl80211_have_wl_escanresults() == false)
    {
        // Run scan command
        file_desc = popen(cmd, "r");
        if (!file_desc) {
            return false;
        }
        pclose(file_desc);

        // Create scanresults command
        snprintf(cmd, sizeof(cmd) - 1,
                 WL80211_SCAN_ALL_RESULTS_GET,
                 radio_cfg->if_name);

        scan_retry = true;
    }


    do
    {
        if (scan_retry) {
            usleep(WL80211_SCAN_RETRY_TIMEOUT);
            scan_retry_cnt++;
        }

        file_desc = popen(cmd, "r");
        if (!file_desc) {
            return false;
        }

        scan_status =
            wl80211_scan_results_parse(
                    radio_cfg->type,
                    file_desc);

        rc = pclose(file_desc);
        if (WIFEXITED(rc) &&
            (WEXITSTATUS(rc) == 0 || scan_retry_cnt >= WL80211_SCAN_RETRY_COUNT))
        {
            scan_retry = false;
        }

    } while (scan_retry);

    if (scan_cb)
    {
        scan_cb(scan_ctx, scan_status);
    }

    return scan_status;
}

bool wl80211_scan_results_get(
        radio_entry_t              *radio_cfg,
        uint32_t                   *chan_list,
        uint32_t                    chan_num,
        radio_scan_type_t           scan_type,
        dpp_neighbor_report_data_t *scan_results)
{
    /* TODO: Consider channel filtering! */
    return wl80211_scan_results_convert(radio_cfg, scan_results);
}
