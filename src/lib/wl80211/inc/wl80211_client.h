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

#ifndef WL80211_CLIENT_H_INCLUDED
#define WL80211_CLIENT_H_INCLUDED

#include "ds_dlist.h"
#include "schema.h"

#include "dppline.h"

#define WL80211_CLIENT_LIST_GET          "wl -i %s assoclist"
#define WL80211_CLIENT_STATS_GET         "wl -i %s sta_info %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx"
#define WL80211_CLIENT_SSID_GET          "wl -i %s assoc | grep 'SSID: \"' | cut -d'\"' -f2"
#define WL80211_CLIENT_MCS_GET           "wl -i %s rate_histo_report %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx"


typedef struct {
    uint32_t freq;      /* Bandwidth, in MHz [20, 40, 80, 160] */
    uint32_t mcs;
    uint32_t nss;
    uint32_t rate;      /* rate ? rate='Legacy rate' [6, 9, 12, 18 ...] and mcs/nss undefined/zero */
    uint64_t pkts;
    uint64_t pkts_total;

    uint32_t duration;  /* This sample duration, in seconds */

    ds_dlist_node_t     ds_node;
} wl80211_client_mcs_stats_t;



typedef struct {
    uint32_t                        ucast_pkts;
    uint64_t                        ucast_bytes;
    uint32_t                        mcast_pkts;
    uint64_t                        mcast_bytes;
    uint32_t                        last_rate;
    uint32_t                        rate_capacity;
    uint32_t                        rate_perceived;
    uint32_t                        errors;
    uint32_t                        retries;
    int32_t                         last_rssi[4];
    int32_t                         noise[4];
    int32_t                         snr;
} wl80211_client_info_stats_t;

typedef struct {
    uint32_t                        is11b;
    uint32_t                        is11n;
    uint32_t                        bw;
    uint32_t                        nss;
    uint32_t                        idle;
    wl80211_client_info_stats_t     tx;
    wl80211_client_info_stats_t     rx;

    /* Rate histogram (aka mcs stats): */
    ds_dlist_t                      rate_histo_rx;   /* wl80211_client_mcs_stats_t */
    ds_dlist_t                      rate_histo_tx;   /* wl80211_client_mcs_stats_t */
} wl80211_client_stats_t;

typedef struct
{
    DPP_TARGET_CLIENT_RECORD_COMMON_STRUCT;
    /* Target specific client data */
    wl80211_client_stats_t          stats;
} wl80211_client_record_t;


static inline wl80211_client_mcs_stats_t* wl80211_client_mcs_stats_alloc()
{
    wl80211_client_mcs_stats_t *mcs = 0;

    mcs = calloc(1, sizeof(*mcs));
    return mcs;
}

static inline wl80211_client_record_t* wl80211_client_record_alloc()
{
    wl80211_client_record_t *record = NULL;

    record = malloc(sizeof(wl80211_client_record_t));
    if (!record)
        return NULL;

    memset(record, 0, sizeof(wl80211_client_record_t));
    ds_dlist_init(&record->stats.rate_histo_rx, wl80211_client_mcs_stats_t, ds_node);
    ds_dlist_init(&record->stats.rate_histo_tx, wl80211_client_mcs_stats_t, ds_node);

    return record;
}

static inline void wl80211_client_record_free(wl80211_client_record_t *record)
{
    wl80211_client_mcs_stats_t *mcs = 0;

    if (!record)
        return;

    while ((mcs = ds_dlist_remove_head(&record->stats.rate_histo_rx)))
    {
        free(mcs);
    }
    while ((mcs = ds_dlist_remove_head(&record->stats.rate_histo_tx)))
    {
        free(mcs);
    }

    free(record);
}

bool wl80211_client_list_get(
        radio_entry_t              *radio_cfg,
        char                       *ifname,
        ds_dlist_t                 *client_data);

bool wl80211_client_stats_convert(
        radio_entry_t              *radio_cfg,
        wl80211_client_record_t    *data_new,
        wl80211_client_record_t    *data_old,
        dpp_client_record_t        *client_result);

#endif /* WL80211_CLIENT_H_INCLUDED */
