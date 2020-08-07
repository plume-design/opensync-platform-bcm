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

#include "log.h"
#include "kconfig.h"

#include "bcmwl.h"
#include "bcmwl_cim.h"
#include "wl80211.h"
#include "wl80211_survey.h"
#include "os.h"

#define MODULE_ID LOG_MODULE_ID_WL

#define SURVEY_5G_FLT_NOISE     (-70)
#define SURVEY_5G_FLT_GLITCH    (5000)


/******************************************************************************
 *  PROTECTED definitions
 *****************************************************************************/

/******************************************************************************
 *  PUBLIC definitions
 *****************************************************************************/

bool wl80211_survey_results_get(
        radio_entry_t              *radio_cfg,
        uint32_t                   *chan_list,
        uint32_t                    chan_num,
        radio_scan_type_t           scan_type,
        ds_dlist_t                 *survey_list)
{
    wl80211_survey_record_t *survey_record;
    struct bcmwl_cim arr[64] = {0};
    size_t len = ARRAY_SIZE(arr);
    size_t i;
    size_t j;

    if (WARN_ON(!survey_list)) return false;
    if (WARN_ON(!chan_list)) return false;
    if (WARN_ON(!bcmwl_cim_get(radio_cfg->if_name, arr, len))) return false;

    for (i = 0; i < len; i++) {
        if (!arr[i].channel) continue;

        if (kconfig_enabled(BCM_BOGUS_SURVEY_WORKAROUND) &&
            radio_cfg->type == RADIO_TYPE_5G) {
            /* On some BCM platforms with very old BCM SDK survey output on
             * 5G radio reports bogus information in case there are no clients
             * connected. We try to detect this situation and filter out survey
             * records.
             */
            if (arr[i].nf > SURVEY_5G_FLT_NOISE) continue;
            if (arr[i].glitch > SURVEY_5G_FLT_GLITCH) continue;
        }

        for (j = 0; j < chan_num; j++)
            if (chan_list[j] == (uint32_t)arr[i].channel)
                break;

        if (j == chan_num) continue; /* not requested so don't collect */

        survey_record = wl80211_survey_record_alloc();
        if (WARN_ON(!survey_record)) continue;

        memcpy(&survey_record->stats, &arr[i], sizeof(survey_record->stats));
        survey_record->info.chan = arr[i].channel;
        survey_record->info.timestamp_ms = get_timestamp();

        ds_dlist_insert_tail(survey_list, survey_record);
    }

    return true;
}

bool wl80211_survey_results_convert(
        radio_entry_t              *radio_cfg,
        radio_scan_type_t           scan_type,
        wl80211_survey_record_t    *data_new,
        wl80211_survey_record_t    *data_old,
        dpp_survey_record_t        *survey_record)
{
    if (!data_new) return false;
    if (!data_old) return false;
    if (!survey_record) return false;

    survey_record->chan_noise = data_new->stats.nf;
    survey_record->chan_busy = data_new->stats.percent.busy;
    survey_record->chan_tx = data_new->stats.percent.tx;
    survey_record->chan_rx = data_new->stats.percent.rx;
    survey_record->chan_self = data_new->stats.percent.rx_self;

    /* The old chanim_stats (without support for usec reports) doesn't
     * report time spent on off-chan. It doesn't even report time
     * spent on-chan, but for all intents and purposes it's good
     * enough. The off-chan dwell time is configurable from the cloud
     * but in practice it shouldn't greater than 50msec.
     */
    if (scan_type == RADIO_SCAN_TYPE_ONCHAN)
        survey_record->duration_ms = data_new->stats.percent.timestamp - data_old->stats.percent.timestamp;
    else
        survey_record->duration_ms = 50;

    if (data_new->stats.usec.total != data_old->stats.usec.total) {
        LOGT("%s: channel %d: using usec to derive percentage", radio_cfg->if_name, data_new->info.chan);
        survey_record->chan_busy = (data_new->stats.usec.busy - data_old->stats.usec.busy) * 100;
        survey_record->chan_busy /= (data_new->stats.usec.total - data_old->stats.usec.total);
        survey_record->chan_tx = (data_new->stats.usec.tx - data_old->stats.usec.tx) * 100;
        survey_record->chan_tx /= (data_new->stats.usec.total - data_old->stats.usec.total);
        survey_record->chan_rx = (data_new->stats.usec.rx - data_old->stats.usec.rx) * 100;
        survey_record->chan_rx /= (data_new->stats.usec.total - data_old->stats.usec.total);
        survey_record->chan_self = (data_new->stats.usec.rx_self - data_old->stats.usec.rx_self) * 100;
        survey_record->chan_self /= (data_new->stats.usec.total - data_old->stats.usec.total);
        survey_record->duration_ms = (data_new->stats.usec.total - data_old->stats.usec.total) / 1000;
    }

    return true;
}

bool wl80211_survey_set_interval(
        radio_entry_t              *radio_cfg,
        uint32_t                    interval)
{
    /* Changing chanim_sample_period is dangerous because it
     * affects desensing according to Broadcom. This means
     * we'll be getting skewed survey reports, but we won't
     * be affecting rf performance and interference
     * mitigation.
     */
    LOGI("%s: not changing chanim_sample_period to %u",
         radio_cfg->if_name, interval);
    return true;
}
