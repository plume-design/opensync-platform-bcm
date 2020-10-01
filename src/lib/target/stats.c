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
#include <string.h>
#include <sys/types.h>
#include <dirent.h>

#include "os.h"
#include "os_nif.h"
#include "log.h"

#include "wl80211_client.h"
#include "wl80211_survey.h"
#include "wl80211_device.h"

#include "target.h"
#include "bcmwl.h"

#define MODULE_ID LOG_MODULE_ID_TARGET

/******************************************************************************
 *  PRIVATE definitions
 *****************************************************************************/

/******************************************************************************
 *  INTERFACE definitions
 *****************************************************************************/
bool target_is_radio_interface_ready(char *phy_name)
{
    return atoi(WL(phy_name, "isup") ?: "0") == 1;
}

bool target_is_interface_ready(char *if_name)
{
    bool                            rc;

    rc = os_nif_is_interface_ready(if_name);
    if (true != rc) {
        return false;
    }

    return true;
}

/******************************************************************************
 *  RADIO definitions
 *****************************************************************************/
bool target_radio_tx_stats_enable(
        radio_entry_t              *radio_cfg,
        bool                        enable)
{
    return true;
}

bool target_radio_fast_scan_enable(
        radio_entry_t              *radio_cfg,
        ifname_t                    if_name)
{
    return true;
}

/******************************************************************************
 *  CLIENT definitions
 *****************************************************************************/
target_client_record_t* target_client_record_alloc()
{
    return wl80211_client_record_alloc();
}

void target_client_record_free(target_client_record_t *result)
{
    wl80211_client_record_free(result);
}

bool target_stats_clients_get(
        radio_entry_t              *radio_cfg,
        radio_essid_t              *essid,
        target_stats_clients_cb_t  *client_cb,
        ds_dlist_t                 *client_list,
        void                       *client_ctx)
{
    struct dirent *d;
    DIR *dir;
    int ri;
    int r;
    int v;

    if (WARN_ON(essid)) /* per-essid collection not supported now */
        return false;
    if (WARN_ON(!bcmwl_parse_vap(radio_cfg->phy_name, &r, &v)))
        return false;
    if (WARN_ON(!(dir = opendir("/sys/class/net"))))
        return false;
    while ((d = readdir(dir))) {
        if (!bcmwl_parse_vap(d->d_name, &ri, &v))
            continue;
        if (ri != r)
            continue;
        if (!os_nif_is_interface_ready(d->d_name))
            continue;

        LOGD("Fetching VIF %s clients", d->d_name);
        if (!wl80211_client_list_get(radio_cfg, d->d_name, client_list))
            break; /* leaves non-NULL `d` as error indication */
    }

    if (d)
        LOGE("%s: %s: failed to get client list", radio_cfg->phy_name, d->d_name);

    (*client_cb)(client_list, client_ctx, true);
    closedir(dir);
    return d == NULL ? true : false;
}

bool target_stats_clients_convert(
        radio_entry_t              *radio_cfg,
        target_client_record_t     *data_new,
        target_client_record_t     *data_old,
        dpp_client_record_t        *client_result)
{
    bool                            rc;

    rc = wl80211_client_stats_convert(
                radio_cfg,
                data_new,
                data_old,
                client_result);

    if (true != rc) {
        return false;
    }

    return true;
}

/******************************************************************************
 *  SURVEY definitions
 *****************************************************************************/
target_survey_record_t* target_survey_record_alloc()
{
    return wl80211_survey_record_alloc();
}

void target_survey_record_free(target_survey_record_t *result)
{
    wl80211_survey_record_free(result);
}

bool target_stats_survey_get(
        radio_entry_t              *radio_cfg,
        uint32_t                   *chan_list,
        uint32_t                    chan_num,
        radio_scan_type_t           scan_type,
        target_stats_survey_cb_t   *survey_cb,
        ds_dlist_t                 *survey_list,
        void                       *survey_ctx)
{
    bool                            rc;

    rc =
        wl80211_survey_results_get (
                radio_cfg,
                chan_list,
                chan_num,
                scan_type,
                survey_list);
    if (true != rc) {
        (*survey_cb)(survey_list, survey_ctx, false);
        return false;
    }

    (*survey_cb)(survey_list, survey_ctx, true);

    return true;
}

bool target_stats_survey_convert(
        radio_entry_t              *radio_cfg,
        radio_scan_type_t           scan_type,
        target_survey_record_t     *data_new,
        target_survey_record_t     *data_old,
        dpp_survey_record_t        *survey_record)
{
    bool                            rc;

    rc =
        wl80211_survey_results_convert (
                radio_cfg,
                scan_type,
                data_new,
                data_old,
                survey_record);
    if (true != rc) {
        return false;
    }

    return true;
}

/******************************************************************************
 *  NEIGHBORS definitions
 *****************************************************************************/
bool target_stats_scan_start(
        radio_entry_t              *radio_cfg,
        uint32_t                   *chan_list,
        uint32_t                    chan_num,
        radio_scan_type_t           scan_type,
        int32_t                     dwell_time,
        target_scan_cb_t           *scan_cb,
        void                       *scan_ctx)
{
    bool                            rc;

    rc =
        wl80211_scan_channel(
            radio_cfg,
            chan_list,
            chan_num,
            scan_type,
            dwell_time,
            scan_cb,
            scan_ctx);
    if (true != rc) {
        return false;
    }

    return true;
}

bool target_stats_scan_stop(
        radio_entry_t              *radio_cfg,
        radio_scan_type_t           scan_type)
{
    // The current survey support is normalized over time, and we need to
    // resync it every time before we start to collect the samples.
    // Until the BCM adds microseconds we shall set the normalization to 10s
    // (sampling interval with 10 is started just after ...)
    bool                            rc;

    if (scan_type == RADIO_SCAN_TYPE_ONCHAN) {
        rc =
            wl80211_survey_set_interval (
                    radio_cfg,
                    10);
        if (true != rc) {
            return false;
        }
    }

    return true;
}

bool target_stats_scan_get(
        radio_entry_t              *radio_cfg,
        uint32_t                   *chan_list,
        uint32_t                    chan_num,
        radio_scan_type_t           scan_type,
        dpp_neighbor_report_data_t *scan_results)
{
    bool                            rc;

    rc =
        wl80211_scan_results_get(
            radio_cfg,
            chan_list,
            chan_num,
            scan_type,
            scan_results);
    if (true != rc) {
        return false;
    }

    return true;
}

/******************************************************************************
 *  DEVICE definitions
 *****************************************************************************/

bool target_stats_device_temp_get(radio_entry_t *radio_cfg,
                                  dpp_device_temp_t *temp_entry)
{
    temp_entry->type = radio_cfg->type;
    return wl80211_device_temp_results_get(radio_cfg->phy_name, &temp_entry->value);
}

bool target_stats_device_txchainmask_get(
        radio_entry_t              *radio_cfg,
        dpp_device_txchainmask_t   *txchainmask_entry)
{
    txchainmask_entry->type = radio_cfg->type;
    return wl80211_device_txchainmask_get(radio_cfg->phy_name, &txchainmask_entry->value);
}

/******************************************************************************
 *  CAPACITY definitions
 *****************************************************************************/
bool target_stats_capacity_enable(
        radio_entry_t              *radio_cfg,
        bool                        enabled)
{
    return true;
}

bool target_stats_capacity_get(
        radio_entry_t              *radio_cfg,
        target_capacity_data_t     *capacity_new)
{
    return true;
}

bool target_stats_capacity_convert(
        target_capacity_data_t     *capacity_new,
        target_capacity_data_t     *capacity_old,
        dpp_capacity_record_t      *capacity_entry)
{
    return true;
}
