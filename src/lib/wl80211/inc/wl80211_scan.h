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

#ifndef WL80211_SCAN_H_INCLUDED
#define WL80211_SCAN_H_INCLUDED

#include "ds_dlist.h"

#include "dppline.h"

#define WL80211_SCAN_CMD_SCAN              "scan"
#define WL80211_SCAN_CMD_ESCAN             "escanresults"
#define WL80211_SCAN_OFFCHAN_RESULTS_GET   "wl -i %s %s -c %d -t passive -h 0 -p %d"
#define WL80211_SCAN_ONCHAN_RESULTS_GET    "wl -i %s %s -c %d -t passive -h 0 -p 100"
#define WL80211_SCAN_FULL_RESULTS_GET      "wl -i %s %s -c %s -t passive -h 0 -p %d"
#define WL80211_SCAN_ALL_RESULTS_GET       "wl -i %s scanresults"


typedef bool wl80211_scan_cb_t(
        void                       *scan_ctx,
        int                         status);

bool wl80211_scan_channel(
        radio_entry_t              *radio_cfg,
        uint32_t                   *chan_list,
        uint32_t                    chan_num,
        radio_scan_type_t           scan_type,
        int32_t                     dwell_time,
        wl80211_scan_cb_t          *scan_cb,
        void                       *scan_ctx);

bool wl80211_scan_results_get(
        radio_entry_t              *radio_cfg,
        uint32_t                   *chan_list,
        uint32_t                    chan_num,
        radio_scan_type_t           scan_type,
        dpp_neighbor_report_data_t *scan_results);

#endif /* WL80211_SCAN_H_INCLUDED */
