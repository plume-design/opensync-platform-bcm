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

#include "wl80211.h"
#include "wl80211_survey.h"
#include "bcmwl.h"
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
    const char                     *tok;
    char                           *ptr;
    char                           *buf = NULL;
    bool                            result;
    int                             count = 0;
    char                          **lines = NULL;
    radio_type_t                    radio_type;
    uint32_t                        chan;
    uint32_t                        chan_index;
    wl80211_survey_record_t        *survey_record = NULL;
    char                            chan_str[32];
    int                             i;
    bcmwl_chanspec_t               *csinfo;

    radio_type = radio_cfg->type;


    /* Clear-up the output list just in case: */
    while ((survey_record = ds_dlist_remove_head(survey_list)))
    {
        memset(survey_record, 0, sizeof(*survey_record));
        wl80211_survey_record_free(survey_record);
    }


    str_join_int(chan_str, sizeof(chan_str), (int*)chan_list, chan_num, ",");
    TRACE("r:%s c:%d i:%s t:%s [%s]",
            radio_get_name_from_type(radio_type),
            radio_cfg->chan,
            radio_cfg->if_name,
            radio_get_scan_name_from_type(scan_type),
            chan_str);

    #define GET(_name, _fmt, _expr) do { \
        tok = strsep(&ptr, " \t"); \
        if (!tok) { \
            LOG(ERR, \
                "Processing %s %s survey for chan %u " \
                " (Failed to get params '%s')", \
                radio_get_name_from_type(radio_type), \
                radio_get_scan_name_from_type(scan_type), \
                chan, \
                strerror(errno)); \
            free(survey_record); \
            goto error; \
        } \
        survey_record->stats._name = _expr; \
        LOG(TRACE, \
            "Parsed %s %s %u survey %s " _fmt, \
            radio_get_name_from_type(radio_type), \
            radio_get_scan_name_from_type(scan_type), \
            chan, \
            #_name, survey_record->stats._name); \
        } while (0)

/* sample output of chanim_stats
version: 2
chanspec tx   inbss   obss   nocat   nopkt   doze     txop     goodtx  badtx   glitch   badplcp  knoise  idle  timestamp
0x1006  10      1       31      27      11      0       3       2       6       4448    34      -81     14      447786260
*/
    result = os_cmd_exec(&buf, WL80211_SURVEY_CHANNEL_GET, radio_cfg->if_name);
    if (!result) goto error;

    lines = str_split_lines(buf, &count);
    if (!lines) goto error;

    for (chan_index = 0; chan_index < chan_num; chan_index++)
    {
        chan = chan_list[chan_index];

        // find matching line
        for (i = 0; i < count; i++) {
            ptr = lines[i];
            if (strncmp(ptr, "0x", 2)) continue;
            int cs = 0;
            sscanf(ptr, "%i", &cs);
            if (!cs) continue;
            csinfo = bcmwl_chanspec_get(radio_cfg->if_name, cs);
            if (csinfo && (uint32_t)csinfo->channel == chan) goto found;
        }
        continue; // not found
found:
        survey_record =
            wl80211_survey_record_alloc();
        if (NULL == survey_record) {
            LOGE("Processing %s %s survey report "
                 "(Failed to allocate memory)",
                 radio_get_name_from_type(radio_type),
                 radio_get_scan_name_from_type(scan_type));
            goto error;
        }

        GET(chanspec,   "%x",  strtol(tok,  NULL,  16));
        GET(tx,         "%d",  atoi(tok));
        GET(inbss,      "%d",  atoi(tok));
        GET(obss,       "%d",  atoi(tok));
        GET(nocat,      "%d",  atoi(tok));
        GET(nopkt,      "%d",  atoi(tok));
        GET(doze,       "%d",  atoi(tok));
        GET(txop,       "%d",  atoi(tok));
        GET(goodtx,     "%d",  atoi(tok));
        GET(badtx,      "%d",  atoi(tok));
        GET(glitch,     "%d",  atoi(tok));
        GET(badplcp,    "%d",  atoi(tok));
        GET(noise,      "%d",  atoi(tok));
        GET(idle,       "%d",  atoi(tok));
        GET(timestamp,  "%u",  atoi(tok));

#ifdef BCM_BOGUS_SURVEY_WORKAROUND
        if (radio_type == RADIO_TYPE_5G &&
                (survey_record->stats.noise  > SURVEY_5G_FLT_NOISE ||
                 survey_record->stats.glitch > SURVEY_5G_FLT_GLITCH)) {
            /* On some BCM platforms with very old BCM SDK survey output on
             * 5G radio reports bogus information in case there are no clients
             * connected. We try to detect this situation and filter out survey
             * records. */
            LOGD("Dropping corrupted 5G survey record! :: knoise=%d glitch=%d",
                 survey_record->stats.noise,
                 survey_record->stats.glitch);
            wl80211_survey_record_free(survey_record);
            continue;
        }
#endif
        survey_record->info.chan            = chan;
        survey_record->info.timestamp_ms    = get_timestamp();

        ds_dlist_insert_tail(survey_list, survey_record);
    }
    #undef GET
    if (buf) free(buf);
    if (lines) free(lines);

    return true;

error:
    LOG(ERROR, "survey get r:%s c:%d i:%s t:%s [%s]",
            radio_get_name_from_type(radio_type),
            radio_cfg->chan,
            radio_cfg->if_name,
            radio_get_scan_name_from_type(scan_type),
            chan_str);
    if (buf) free(buf);
    if (lines) free(lines);
    return false;
}

bool wl80211_survey_results_convert(
        radio_entry_t              *radio_cfg,
        radio_scan_type_t           scan_type,
        wl80211_survey_record_t    *data_new,
        wl80211_survey_record_t    *data_old,
        dpp_survey_record_t        *survey_record)
{

    if (    (NULL == data_new)
         || (NULL == data_old)
         || (NULL == survey_record)
       ) {
        return false;
    }

    // FIXME: chanim_stats reports percentages from last sample period that it
    // is doing internally. We should compute the delta ourselves somehow or
    // accumulate percentages overtime in a temp buffer. Let's hope BCM
    // delivers this in microseconds - until then let's report _something_.

    // FIXME: These conversions must be really confronted and compared to
    // Atheros radio side-by-side.
    survey_record->chan_busy    = 100 - data_new->stats.txop;
    survey_record->chan_tx      = data_new->stats.tx;
    survey_record->chan_rx      = (data_new->stats.inbss +
            data_new->stats.obss +
            data_new->stats.nocat +
            data_new->stats.nopkt);
    survey_record->chan_self    = data_new->stats.inbss;
    survey_record->chan_busy_ext = 0;  // FIXME

    if (scan_type == RADIO_SCAN_TYPE_ONCHAN) {
        survey_record->duration_ms   = 10000;
    } else {
        survey_record->duration_ms   = 50;
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
