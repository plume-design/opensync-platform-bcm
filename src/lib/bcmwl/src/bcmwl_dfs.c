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
#include <sys/types.h>
#include <dirent.h>
#include <time.h>

#include "target.h"
#include "log.h"
#include "schema.h"
#include "const.h"
#include "util.h"
#include "evx_debounce_call.h"
#include "bcmwl.h"
#include "bcmwl_nvram.h"
#include "bcmwl_debounce.h"

#include "bcmutil.h"


#define NV_NAME "plume"
#define NV_PROP "bcmwl_dfs_timer_iface"
#define NV_GET() (NVG(NV_NAME, NV_PROP) ?: "")
#define NV_SET(x) NVS(NV_NAME, NV_PROP, x)

#define NV_PROP_RADAR "bcmwl_dfs_radar"
#define NV_GET_RADAR() (NVG(NV_NAME, NV_PROP_RADAR) ?: "")
#define NV_SET_RADAR(x) NVS(NV_NAME, NV_PROP_RADAR, x)

#define NV_PROP_CHANNEL "bcmwl_dfs_channel"
#define NV_GET_CHANNEL() (NVG(NV_NAME, NV_PROP_CHANNEL) ?: "")
#define NV_SET_CHANNEL(x) NVS(NV_NAME, NV_PROP_CHANNEL, x)

#define NV_PROP_FALLBACK_2G "bcmwl_dfs_fallback_parents_2g"
#define NV_GET_FALLBACK_2G() (NVG(NV_NAME, NV_PROP_FALLBACK_2G) ?: "")
#define NV_SET_FALLBACK_2G(x) NVS(NV_NAME, NV_PROP_FALLBACK_2G, x)

static char fallback_radio[64];
struct fallback_parent {
    int channel;
    char bssid[18];
};

static ev_timer g_dfs_timer;

static void bcmwl_dfs_timer_cb(EV_P_ struct ev_timer *w, int revent)
{
    const char *phyname = NV_GET();

    LOGI("%s called for %s", __func__, phyname);

    evx_debounce_call(bcmwl_radio_state_report, phyname);
}

static void bcmwl_radar_detected_enable(void)
{
    struct dirent *p;
    DIR *d;

    for (d = opendir("/sys/class/net"); d && (p = readdir(d)); ) {
        if (bcmwl_is_phy(p->d_name)) {
            bcmwl_event_enable(p->d_name, WLC_E_RADAR_DETECTED);
        }
    }
    if (!WARN_ON(!d))
        closedir(d);
}

static void bcmwl_dfs_timer_stop(void)
{
    ev_timer_stop(EV_DEFAULT, &g_dfs_timer);
    NV_SET("");
}

static void bcmwl_dfs_timer_rearm(const char *phyname, double timeout)
{
    LOGI("%s: %s %f", phyname, __func__, timeout);

    bcmwl_dfs_timer_stop();
    NV_SET(phyname);
    ev_timer_set(&g_dfs_timer, timeout, 0.0);
    ev_timer_start(EV_DEFAULT, &g_dfs_timer);
}

/* Public */
void bcmwl_dfs_init(void)
{
    bcmwl_radar_detected_enable();
    ev_timer_init(&g_dfs_timer, bcmwl_dfs_timer_cb, 60.0, 0.0);
}

void
bcmwl_radio_dfs_demo_set(const char *cphy, const struct schema_Wifi_Radio_Config *rconf)
{
    const char *cmd;
    int value;

    LOGI("%s: radar: dfs_demo %d", cphy, rconf->dfs_demo);

    if (WARN_ON(!(cmd = WL(cphy, "radar"))))
        return;

    if (sscanf(cmd, "%d", &value) != 1 || value == rconf->dfs_demo) {
        if (WARN_ON(!WL(cphy, "radar", strfmta("%d", !rconf->dfs_demo))))
            return;
        if (WARN_ON(!(cmd = WL(cphy, "radar"))))
            return;
        if (sscanf(cmd, "%d", &value) != 1 || value == rconf->dfs_demo) {
            LOGW("%s: radar: seems we fail to set radar %d %s", cphy, !rconf->dfs_demo, cmd);
            return;
        }
    }
}

void
bcmwl_radio_dfs_demo_get(const char *cphy, struct schema_Wifi_Radio_State *rstate)
{
    const char *cmd;
    int radar;

    if (WARN_ON(!(cmd = WL(cphy, "radar"))))
        return;

    if (sscanf(cmd, "%d", &radar) != 1)
        return;

    SCHEMA_SET_INT(rstate->dfs_demo, !radar);
}

static int bcmwl_dfs_get_fallback_parents(const char *cphy, struct fallback_parent *parent, int size)
{
    const char *fallback;
    char bssid[32];
    char *line;
    char *buffer;
    int channel;
    int num;

    memset(parent, 0, sizeof(*parent) * size);
    num = 0;

    if (!cphy)
        return num;

    fallback = NV_GET_FALLBACK_2G();
    if (!fallback || !strlen(fallback))
        return num;

    /* We need buffer copy because of strsep() */
    buffer = strdup(fallback);
    if (!buffer)
        return num;

    while ((line = strsep(&buffer, ",")) != NULL) {
        if (sscanf(line, "%d %18s", &channel, bssid) != 2)
            continue;

        LOGT("%s: parsed fallback parent kv: %d/%d: %s %d", cphy, num, size, bssid, channel);
        if (num >= size)
            break;

        parent[num].channel = channel;
        strscpy(parent[num].bssid, bssid, sizeof(parent[num].bssid));
        num++;
    }
    free(buffer);

    return num;
}

void bcmwl_radio_fallback_parents_set(const char *cphy, const struct schema_Wifi_Radio_Config *rconf)
{
    char buf[512] = {};
    char *pbuf = NULL;
    int i;

    if (!strstr(rconf->freq_band, "2.4G"))
        return;

    strncpy(fallback_radio, cphy, sizeof(fallback_radio));
    for (i = 0; i < rconf->fallback_parents_len; i++) {
        LOGI("%s: fallback_parents[%d] %s %d", cphy, i,
             rconf->fallback_parents_keys[i],
             rconf->fallback_parents[i]);
        strscat(buf, strfmta("%d %s,", rconf->fallback_parents[i], rconf->fallback_parents_keys[i]), sizeof(buf));
    }

    if (strlen(buf))
        pbuf = buf;

    NV_SET_FALLBACK_2G(pbuf);
}

void bcmwl_radio_fallback_parents_get(const char *cphy, struct schema_Wifi_Radio_State *rstate)
{
    struct fallback_parent parents[8];
    int parents_num;
    int i;

    if (!strstr(rstate->freq_band, "2.4G"))
        return;

    parents_num = bcmwl_dfs_get_fallback_parents(cphy, &parents[0], ARRAY_SIZE(parents));

    for (i = 0; i < parents_num; i++)
        SCHEMA_KEY_VAL_APPEND_INT(rstate->fallback_parents, parents[i].bssid, parents[i].channel);
}

void bcmwl_event_handle_radar(const char *ifname)
{
    struct fallback_parent parents[8];
    struct fallback_parent *parent;
    int parents_num;
    const char *ovsh = strfmta("%s/../tools/ovsh", target_bin_dir());
    const char *parentchange = strfmta("%s/parentchange.sh", target_bin_dir());
    const char *rchan;
    const char *sta;
    const char *output;

    rchan = strexa(ovsh, "-r", "s", "Wifi_Radio_Config", "channel",
                         "-w", strfmta("if_name==%s", strdupa(ifname)));

    LOGI("%s: radar: channel %s", ifname, rchan);

    NV_SET_CHANNEL(rchan);
    NV_SET_RADAR(strfmta("%u", (unsigned int) time(NULL)));
    evx_debounce_call(bcmwl_radio_state_report, ifname);

    sta = strexa(ovsh, "-r", "s", "Wifi_VIF_Config", "mode",
                       "-w", strfmta("if_name==%s", strdupa(ifname)));

    if (!sta || !strstr(sta, "sta")) {
        LOGI("%s: radar: no STA found, skip parent change", ifname);
        return;
    }

    parents_num = bcmwl_dfs_get_fallback_parents(ifname, &parents[0], ARRAY_SIZE(parents));

    if (parents_num == 0) {
        LOGI("%s: radar: fallback parent list is empty, did cloud not fill it in?", ifname);
        target_device_restart_managers();
        return;
    }

    parent = &parents[0];
    LOGI("%s: radar: parentchange.sh %s %s %d", ifname, fallback_radio, parent->bssid, parent->channel);
    output = strexa(parentchange, fallback_radio, parent->bssid, strfmta("%d", parent->channel));
    (void)output;  // Ignore compiler warning - variable not used
}

void bcmwl_radio_radar_get(const char *phyname, struct schema_Wifi_Radio_State *rstate)
{
    const char *radar_time = NV_GET_RADAR();
    const char *radar_chan = NV_GET_CHANNEL();

    if (!strstr(rstate->freq_band, "5G"))
        return;

    if (!radar_time || !radar_chan)
        return;

    if (strlen(radar_time) == 0 || strlen(radar_chan) == 0)
        return;

    SCHEMA_KEY_VAL_APPEND(rstate->radar, "last_channel", radar_chan);
    SCHEMA_KEY_VAL_APPEND(rstate->radar, "num_detected", "1");
    SCHEMA_KEY_VAL_APPEND(rstate->radar, "time", radar_time);
}

void bcmwl_radio_channels_get(const char *phyname, struct schema_Wifi_Radio_State *rstate)
{
    char *cmd_out;
    char *line;
    char *ptr;
    int channel;
    enum bcmwl_chan_state state;
    int cur_chan[8];
    int cur_chan_num;
    double timeout;
    int nop_minutes;
    int cac_seconds;
    int cac_elapsed_ms;
    int dfs_preism;
    int aps_cnt;
    int i;

    timeout = 0.0;

    /* get dfs_preism */
    ptr = WL(phyname, "dfs_preism");
    if (!ptr || sscanf(ptr, "%d", &dfs_preism) != 1)
        dfs_preism = -1;

    cur_chan_num = bcmwl_get_current_channels(phyname, cur_chan, ARRAY_SIZE(cur_chan));

    cmd_out = WL(phyname, "chan_info");
    if (!cmd_out)
        return;

    /* In case we didn't configure this, use default 60 seconds */
    if (dfs_preism == -1)
        dfs_preism = 60;

    /* Check active APs counter */
    aps_cnt = bcmwl_radio_get_ap_active_cnt(phyname);

    while ((line = strsep(&cmd_out, "\r\n")))
    {
        if (sscanf(line, "Channel %d\n", &channel) != 1)
            continue;

        do {
            if (!strstr(line, "RADAR Sensitive")) {
                state = BCMWL_CHAN_STATE_ALLOWED;
                break;
            }

            /* default as CAC ready */
            state = BCMWL_CHAN_STATE_NOP_FINISHED;

            /* check NOP */
            if ((ptr = strstr(line, "Temporarily Out of Service for")) != NULL) {
                if (sscanf(ptr, "Temporarily Out of Service for %d minutes", &nop_minutes) != 1)
                    nop_minutes = 30;
                state = BCMWL_CHAN_STATE_NOP_STARTED;
                if (timeout == 0.0 || timeout > 60.0 * nop_minutes)
                    timeout = 60.0 * nop_minutes;
                break;
            }

            /* check CAC_COMPLETED - ISM */
            if (!strstr(line, "Passive")) {
                /* Warn only when current channel, skip pre-CAC */
                for (i = 0; i < cur_chan_num; i++) {
                    if (cur_chan[i] != channel)
                        continue;

                    if (!aps_cnt)
                        break;

                    if (rstate->dfs_demo)
                        break;

                    ptr = WL(phyname, "dfs_status");
                    if (!strstr(ptr, "state In-Service Monitoring(ISM)"))
                        LOGW("%s: lack of ISM (%s) channel %d", phyname, ptr, channel);
                    break;
                }
                state = BCMWL_CHAN_STATE_CAC_COMPLETED;
                break;
            }

            /* check CAC_STARTED - PRE-ISM */
            for (i = 0; i < cur_chan_num; i++) {
                if (cur_chan[i] != channel)
                    continue;

                state = BCMWL_CHAN_STATE_CAC_STARTED;

                /* set default 60 second timer */
                timeout = 60.0;

                if (!aps_cnt)
                    continue;

                if (rstate->dfs_demo)
                    continue;

                ptr = WL(phyname, "dfs_status");
                if (!strstr(ptr, "state PRE-ISM Channel Availability Check(CAC)"))
                    LOGW("%s: lack of PRE-ISM (%s)", phyname, ptr);

                if (sscanf(ptr, "state PRE-ISM Channel Availability Check(CAC) time elapsed %dms", &cac_elapsed_ms) != 1)
                    cac_elapsed_ms = 0;

                cac_seconds = ((dfs_preism * 1000) - cac_elapsed_ms) / 1000;
                /* we should never leave CAC_STARTED state with timeout = 0 */
                if (cac_seconds <= 0) {
                    LOGI("%s: cac_elapsed > cac_time (%d, %d)", phyname, cac_elapsed_ms, dfs_preism * 1000);
                    cac_seconds = 30.0;
                }

                if (timeout > cac_seconds)
                    timeout = cac_seconds;

                break;
            }
        } while (0);

        SCHEMA_KEY_VAL_APPEND(rstate->channels,
                              strfmta("%d", channel),
                              bcmwl_channel_state(state));
    }

    if (timeout != 0.0)
        bcmwl_dfs_timer_rearm(phyname, timeout + 10.0);
    else
        bcmwl_dfs_timer_stop();
}
