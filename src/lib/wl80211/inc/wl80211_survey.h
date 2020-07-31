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

#ifndef WL80211_SURVEY_H_INCLUDED
#define WL80211_SURVEY_H_INCLUDED

#include "ds_dlist.h"

#include "dppline.h"

#include "wl80211_scan.h"
#include "bcmwl_cim.h"

#define WL80211_SURVEY_CHANNEL_GET  "wl -i %s chanim_stats"
#define WL80211_SURVEY_INTERVAL_SET "wl -i %s chanim_sample_period %d"

typedef struct
{
    DPP_TARGET_SURVEY_RECORD_COMMON_STRUCT;

    /* Target specific survey data */
    struct bcmwl_cim stats;
} wl80211_survey_record_t;

static inline
wl80211_survey_record_t* wl80211_survey_record_alloc()
{
    wl80211_survey_record_t *record = NULL;

    record = malloc(sizeof(wl80211_survey_record_t));
    if (record) {
        memset(record, 0, sizeof(wl80211_survey_record_t));
    }

    return record;
}

static inline
void wl80211_survey_record_free(wl80211_survey_record_t *record)
{
    if (NULL != record) {
        free(record);
    }
}

bool wl80211_survey_results_get(
        radio_entry_t              *radio_cfg,
        uint32_t                   *chan_list,
        uint32_t                    chan_num,
        radio_scan_type_t           scan_type,
        ds_dlist_t                 *survey_list);

bool wl80211_survey_results_convert(
        radio_entry_t              *radio_cfg,
        radio_scan_type_t           scan_type,
        wl80211_survey_record_t    *data_new,
        wl80211_survey_record_t    *data_old,
        dpp_survey_record_t        *survey_record);

bool wl80211_survey_set_interval(
        radio_entry_t              *radio_cfg,
        uint32_t                    interval);

#endif /* WL80211_SURVEY_H_INCLUDED */
