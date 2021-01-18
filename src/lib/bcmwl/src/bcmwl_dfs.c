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
#include <arpa/inet.h>

#include "target.h"
#include "log.h"
#include "schema.h"
#include "const.h"
#include "util.h"
#include "evx_debounce_call.h"
#include "bcmwl.h"
#include "bcmwl_nvram.h"
#include "bcmwl_debounce.h"
#include "bcmwl_event.h"

struct fallback_parent {
    int channel;
    char bssid[18];
};

struct timer_work {
    ev_timer timer;
    char ifname[32];
    void (*func)(const char *phyname);
    char fname[256];
};

static struct timer_work g_timer_work[4];
static char g_dfs_fallback_radio[16];

static void bcmwl_dfs_timer_cb(EV_P_ struct ev_timer *w, int revent)
{
    struct timer_work *work = (void *) w;

    LOGI("%s called %s(%s)", __func__, work->fname, work->ifname);

    if (work->func)
        work->func(work->ifname);
}

static void bcmwl_dfs_radio_state_report(const char *phyname)
{
    evx_debounce_call(bcmwl_radio_state_report, phyname);
}

static struct timer_work* bcmwl_dfs_get_timer(const char *phyname)
{
    struct timer_work *work = NULL;
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(g_timer_work); i++) {
        /* First check if already added */
        if (!strcmp(g_timer_work[i].ifname, phyname)) {
            work = &g_timer_work[i];
            break;
        }

        /* Use first empty ifname and init new timer */
        if (strlen(g_timer_work[i].ifname) == 0) {
            work = &g_timer_work[i];
            STRSCPY(work->ifname, phyname);
            ev_timer_init(&work->timer, bcmwl_dfs_timer_cb, 60.0, 0);
            break;
        }
    }

    return work;
}

static void bcmwl_dfs_timer_stop(const char *phyname)
{
    struct timer_work *work;

    work = bcmwl_dfs_get_timer(phyname);
    if (WARN_ON(!work))
        return;

    ev_timer_stop(EV_DEFAULT, &work->timer);
}

static void bcmwl_dfs_timer(const char *phyname, double timeout,
                            void (*func)(const char *), const char *fn)
{
    struct timer_work *work;
    LOGI("%s: %s %f %s", phyname, __func__, timeout, fn);

    work = bcmwl_dfs_get_timer(phyname);
    if (WARN_ON(!work))
        return;

    work->func = func;
    STRSCPY(work->fname, fn);

    ev_timer_stop(EV_DEFAULT, &work->timer);
    ev_timer_set(&work->timer, timeout, 0.0);
    ev_timer_start(EV_DEFAULT, &work->timer);
}

static void bcmwl_dfs_timer_rearm(const char *phyname, double timeout)
{
    bcmwl_dfs_timer(phyname, timeout, bcmwl_dfs_radio_state_report, "rupdate");
}

/* Public */
void bcmwl_dfs_init(void)
{
    bcmwl_event_enable_all(WLC_E_RADAR_DETECTED);
    bcmwl_event_enable_all(WLC_E_AP_CHAN_CHANGE);
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

    fallback = NVG(cphy, "dfs_fallback_parents");
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

    /* Set fallback radio for 2.4 */
    if (strstr(rconf->freq_band, "2.4G"))
        STRSCPY_WARN(g_dfs_fallback_radio, cphy);

    for (i = 0; i < rconf->fallback_parents_len; i++) {
        LOGI("%s: fallback_parents[%d] %s %d", cphy, i,
             rconf->fallback_parents_keys[i],
             rconf->fallback_parents[i]);
        strscat(buf, strfmta("%d %s,", rconf->fallback_parents[i], rconf->fallback_parents_keys[i]), sizeof(buf));
    }

    if (strlen(buf))
        pbuf = buf;

    NVS(cphy, "dfs_fallback_parents", pbuf);
}

void bcmwl_radio_fallback_parents_get(const char *cphy, struct schema_Wifi_Radio_State *rstate)
{
    struct fallback_parent parents[8];
    int parents_num;
    int i;

    parents_num = bcmwl_dfs_get_fallback_parents(cphy, &parents[0], ARRAY_SIZE(parents));

    for (i = 0; i < parents_num; i++)
        SCHEMA_KEY_VAL_APPEND_INT(rstate->fallback_parents, parents[i].bssid, parents[i].channel);
}

void bcmwl_event_handle_radar(const char *ifname)
{
    struct fallback_parent parents[8];
    struct fallback_parent *parent;
    int parents_num;
    const char *fallback_radio = g_dfs_fallback_radio;
    const char *ovsh = strfmta("%s/../tools/ovsh", target_bin_dir());
    const char *parentchange = strfmta("%s/parentchange.sh", target_bin_dir());
    const char *rchan;
    const char *sta;

    rchan = strexa(ovsh, "-r", "s", "Wifi_Radio_Config", "channel",
                         "-w", strfmta("if_name==%s", strdupa(ifname)));

    LOGI("%s: radar: channel %s", ifname, rchan);

    NVS(ifname, "dfs_radar_chan", rchan);
    NVS(ifname, "dfs_radar_time", strfmta("%u", (unsigned int) time(NULL)));
    evx_debounce_call(bcmwl_radio_state_report, ifname);

    sta = strexa(ovsh, "-r", "s", "Wifi_VIF_Config", "mode",
                       "-w", strfmta("if_name==%s", strdupa(ifname)));

    if (!sta || !strstr(sta, "sta")) {
        LOGI("%s: radar: no STA found, skip parent change", ifname);
        return;
    }

    parents_num = bcmwl_dfs_get_fallback_parents(fallback_radio, &parents[0], ARRAY_SIZE(parents));

    if (parents_num == 0) {
        LOGI("%s: radar: fallback parent list is empty, did cloud not fill it in?", ifname);
        target_device_restart_managers();
        return;
    }

    parent = &parents[0];
    LOGI("%s: radar: parentchange.sh %s %s %d", ifname, fallback_radio, parent->bssid, parent->channel);
    strexa(parentchange, fallback_radio, parent->bssid, strfmta("%d", parent->channel));
}

const char* bcmwl_event_ap_chan_change_reason(wl_chan_change_reason_t reason)
{
    switch (reason) {
    case WL_CHAN_REASON_CSA:
        return "CSA";
    case WL_CHAN_REASON_DFS_AP_MOVE_START:
        return "MOVE START";
    case WL_CHAN_REASON_DFS_AP_MOVE_RADAR_FOUND:
        return "RADAR FOUND";
    case WL_CHAN_REASON_DFS_AP_MOVE_ABORTED:
        return "MOVE ABORTED";
    case WL_CHAN_REASON_DFS_AP_MOVE_SUCCESS:
        return "MOVE SUCCESS";
    case WL_CHAN_REASON_DFS_AP_MOVE_STUNT:
        return "MOVE STUNT";
    default:
        break;
    }

    return "unknown";
};

void bcmwl_event_handle_ap_chan_change(const char *ifname, void *_ev)
{
    bcm_event_t *ev = _ev;
    wl_event_change_chan_t *event;
    char *phy;
    unsigned int length;

    event = (wl_event_change_chan_t *)(ev + 1);
    length = ntohl(ev->event.datalen);

    if (length < sizeof(*event)) {
        LOGI("%s: ap chan change incorrect length %d, skip parsing", ifname, length);
    } else {
        LOGI("%s: ap chan change reason %s target_chanspec 0x%04x",
             ifname,
             bcmwl_event_ap_chan_change_reason(event->reason),
             event->target_chanspec);
    }

    if (WARN_ON(!(phy = strdupa(ifname))))
        return;
    if (WARN_ON(!(phy = strsep(&phy, CONFIG_BCMWL_VAP_DELIMITER))))
        return;

    evx_debounce_call(bcmwl_radio_state_report, phy);
}

void bcmwl_radio_radar_get(const char *phyname, struct schema_Wifi_Radio_State *rstate)
{
    const char *radar_time = NVG(phyname, "dfs_radar_time");
    const char *radar_chan = NVG(phyname, "dfs_radar_chan");

    if (!radar_time || !radar_chan)
        return;

    if (strlen(radar_time) == 0 || strlen(radar_chan) == 0)
        return;

    SCHEMA_KEY_VAL_APPEND(rstate->radar, "last_channel", radar_chan);
    SCHEMA_KEY_VAL_APPEND(rstate->radar, "num_detected", "1");
    SCHEMA_KEY_VAL_APPEND(rstate->radar, "time", radar_time);
}

static int bcmwl_radio_get_cac_state_from_str(const char *str)
{
    if (strstr(str, "In-Service Monitoring(ISM)"))
        return WL_DFS_CACSTATE_ISM;
    else if (strstr(str, "PRE-ISM Channel Availability Check(CAC)"))
        return WL_DFS_CACSTATE_PREISM_CAC;
    else if (strstr(str, "IDLE"))
        return WL_DFS_CACSTATE_IDLE;
    else if (strstr(str, "Channel Switching Announcement(CSA)"))
        return WL_DFS_CACSTATE_CSA;
    else if (strstr(str, "POST-ISM Channel Availability Check"))
        return WL_DFS_CACSTATE_POSTISM_CAC;
    else if (strstr(str, "PRE-ISM Ouf Of Channels(OOC)"))
        return WL_DFS_CACSTATE_PREISM_OOC;
    else if (strstr(str, "POST-ISM Out Of Channels(OOC)"))
        return WL_DFS_CACSTATE_POSTISM_OOC;
    else
        return -1;
}

static const int* bcmwl_radio_get_cac_state_from_line(
        const char *line,
        int *state,
        unsigned int *time_elapsed_ms)
{
    char *ptr;
    char *block;
    int c, cw;

    if (!line)
        return NULL;

    /*
     * Line format:
     *  @0: state: In-Service Monitoring(ISM), time elapsed: 1050ms, chanspec: 36/160 (0xE832), chanspec last cleared: 36/160 (0xE832), sub type: 0x00
     */
    ptr = strdupa(line);
    if (!ptr)
        return NULL;

    if (time_elapsed_ms)
        *time_elapsed_ms = 0;
    c = -1;
    cw = -1;

    LOGT("from_line \'%s\'", line);
    while ((block = strsep(&ptr, ","))) {
        if (strstr(block, "state:")) {
            if (!state)
                continue;
            *state = bcmwl_radio_get_cac_state_from_str(block);
            if (*state == -1)
                return NULL;
        }

        if (strstr(block, "time elapsed:")) {
            if (!time_elapsed_ms)
                continue;
            if (sscanf(block, " time elapsed: %u", time_elapsed_ms) != 1)
                *time_elapsed_ms = 0;
        }

        if (strstr(block, "chanspec:")) {
            if (strstr(block, "chanspec: none"))
                return NULL;
            bcmwl_radio_chanspec_extract(block + strlen("chanspec:") + 1, &c, &cw);
        }
    }

    if (WARN_ON(c == -1 || cw == -1))
        return NULL;

    LOGT("from_line: c %d cw %d state %d elapsed_ms %u", c, cw,
         state ? *state : -2, time_elapsed_ms ? *time_elapsed_ms : 0);
    return unii_5g_chan2list(c, cw);
}

static bool bcmwl_radio_valid_cac_state(
        const char *dfs_ap_move,
        const char *dfs_status,
        int valid_state,
        int channel,
        unsigned int *elapsed_ms)
{
    const int *chans;
    char *ptr = NULL;
    int state = -1;
    char *line;

    LOGT("%s channel %d exp_state %d\n'%s'", __func__, channel, valid_state, dfs_ap_move);
    if (dfs_ap_move)
        ptr = strdupa(dfs_ap_move);

    if (ptr) {
        while ((line = strsep(&ptr, "\r\n"))) {
            /* Get status for main channel - @0 */
            if (!strstr(line, "@0"))
               continue;

            chans = bcmwl_radio_get_cac_state_from_line(line, &state, elapsed_ms);
            if (WARN_ON(!chans))
                return false;

            if (WARN_ON(state != valid_state))
                return false;

            while (*chans) {
                if (*chans == channel)
                    return true;
                chans++;
            }

            WARN_ON(1);
            return false;
        }
    }

    /* Just in case some platform don't support dfs_ap_move */
    if (dfs_status) {
        LOGT("%s chan %d fallback to dfs_status", __func__, channel);
        state = bcmwl_radio_get_cac_state_from_str(dfs_status);
        if (elapsed_ms) {
            ptr = strstr(dfs_status, "time elapsed");
            if (sscanf(ptr, "time elapsed %u", elapsed_ms) != 1)
                *elapsed_ms = 0;
        }

        if (state == valid_state)
            return true;
        else
            return false;
    }

    return false;
}

static bool bcmwl_radio_bg_pre_ism_state(
        const char *dfs_ap_move,
        const char *dfs_status,
        int channel,
        unsigned int *elapsed_ms)
{
    const int *chans;
    int state = -1;
    char *ptr = NULL;
    char *line;

    LOGT("%s channel %d\n'%s'", __func__, channel, dfs_ap_move);
    if (dfs_ap_move)
        ptr = strdupa(dfs_ap_move);

    if (ptr) {
        while ((line = strsep(&ptr, "\r\n"))) {
            if (!strstr(line, "@1:"))
               continue;

            chans = bcmwl_radio_get_cac_state_from_line(line, &state, elapsed_ms);
            if (!chans)
                return false;

            if (state != WL_DFS_CACSTATE_PREISM_CAC)
                return false;

            while (*chans) {
                if (*chans == channel)
                    return true;
                chans++;
            }
        }
    }

    return false;
}

bool bcmwl_radio_is_dfs_channel(const char *phy, uint8_t chan, const char *ht_mode)
{
    char *ptr;
    char *line;
    int channel;
    const int *c;
    const int *chans;

    chans = unii_5g_chan2list(chan, bcmwl_radio_ht_mode_to_int(ht_mode));
    if (WARN_ON(!chans))
        return false;

    ptr = WL(phy, "chan_info");
    if (WARN_ON(!ptr))
        return false;

    while ((line = strsep(&ptr, "\r\n"))) {
        if (sscanf(line, "Channel %d\n", &channel) != 1)
            continue;

        c = chans;
        while (*c) {
            if (*c++ == channel && strstr(line, "RADAR Sensitive"))
                return true;
        }
    }

    return false;
}

bool bcmwl_dfs_bgcac_active(const char *phy, uint8_t chan, const char *ht_mode)
{
    char *ptr;
    int c, cw, bw;

    bw = bcmwl_radio_ht_mode_to_int(ht_mode);

    ptr = WL(phy, "dfs_ap_move");
    if (WARN_ON(!ptr))
        return false;

    if (!strstr(ptr, "Radar Scan In Progress"))
        return false;

    ptr = strstr(ptr, "AP Target Chanspec");
    if (WARN_ON(!ptr))
        return false;

    bcmwl_radio_chanspec_extract(ptr, &c, &cw);
    if (chan != c)
        return false;

    if (bw != cw)
        return false;

    return true;
}

void bcmwl_dfs_bgcac_deactivate(const char *phy)
{
    char *apvifs = bcmwl_radio_get_vifs(phy) ?: strdupa("");
    const char *apvif = strsep(&apvifs, " ");
    char *ptr;

    ptr = WL(phy, "dfs_ap_move");
    if (!ptr)
        return;

    if (!strstr(ptr, "Radar Scan In Progress"))
        return;

    WARN_ON(!WL(apvif, "dfs_ap_move", "-1"));
}

static bool bcmwl_dfs_get_cac_ready_channels(const char *phy, int *chan, int *bw)
{
    /*
     * TODO rewrite this function - correct only for Cyrus.
     * On Cyrus we can't change BW and cloud using 60/108/124.
     */
    int cw80[] = {60, 108, 124};
    int c, cw;
    int channel;
    char *ptr;
    char *line;
    unsigned int i;

    ptr = WL(phy, "chan_info");
    if (WARN_ON(!ptr))
        return false;

    if (!bcmwl_radio_get_chanspec(phy, &c, &cw)) {
        LOGI("%s bgcac no current chanspec", phy);
        return false;
    }

    *chan = 0;
    *bw = 0;

    while ((line = strsep(&ptr, "\r\n")))
    {
        if (sscanf(line, "Channel %d\n", &channel) != 1)
            continue;

        /* skip nonDFS channels */
        if (!strstr(line, "RADAR Sensitive"))
            continue;

        /* skip CAC completed */
        if (!strstr(line, "Passive"))
            continue;

        /* TODO check NOP correctly */
        if (strstr(line, "Temporarily Out of Service"))
            continue;

        for (i = 0; i < ARRAY_SIZE(cw80); i++) {
            if (cw80[i] != channel)
                continue;
            /* TODO skip adjacent channels correctly */
            if (abs(channel - c) < 20)
                continue;
            *chan = channel;
            *bw = 80;
            break;
        }

        if (*chan)
            break;
    }

    return !!(*chan);
}

static bool bcmwl_dfs_bgcac_get_next_chan(const char *phy, int *c, int *cw)
{
    char *apvifs = bcmwl_radio_get_vifs(phy) ?: strdupa("");
    const char *apvif = strsep(&apvifs, " ");
    char *ptr;

    ptr = NVG(phy, "zero_wait_dfs");
    if (!ptr)
        return false;
    if (strcmp(ptr, "precac"))
        return false;

    if (!apvif) {
        LOGI("%s: backgroud CAC - no apvif", phy);
        return false;
    }

    ptr = WL(phy, "dfs_ap_move");
    if (WARN_ON(!ptr))
        return false;

    if (strstr(ptr, "Radar Scan In Progress") &&
        strstr(ptr, "@1: state: PRE-ISM Channel Availability Check(CAC)")) {
        LOGI("%s: backgroud CAC - in progress", phy);
        return false;
    }

    if (!bcmwl_dfs_get_cac_ready_channels(phy, c, cw)) {
        LOGI("%s: background CAC - no available channels found", phy);
        return false;
    }

    return true;
}

static bool bcmwl_dfs_bgcac_action_required(const char *phy)
{
    int c, cw;

    return bcmwl_dfs_bgcac_get_next_chan(phy, &c, &cw);
}

void bcmwl_dfs_bgcac_recalc(const char *phy)
{
    char *apvifs = bcmwl_radio_get_vifs(phy) ?: strdupa("");
    const char *apvif = strsep(&apvifs, " ");
    char *ptr;
    int c, cw;

    /*
     * With background CAC driver rejects scans. In case
     * we have active station we expect this station need
     * to run scans which are necessary to connect/reconnect.
     */
    if (bcmwl_vap_is_sta(phy)) {
        if (((ptr = NVG(phy, "plume_bss_enabled")) && atoi(ptr))) {
            LOGD("%s we have active station, skip bgcac", phy);
            bcmwl_dfs_bgcac_deactivate(phy);
            return;
        }
    }

    if (!bcmwl_dfs_bgcac_get_next_chan(phy, &c, &cw))
        return;

    LOGI("%s start background CAC on %d/%d", phy, c, cw);
    /* TODO fix it for HT40 low/up case */
    WARN_ON(!WL(apvif, "dfs_ap_move", strfmta("%d/%d", c, cw)));
    WARN_ON(!WL(apvif, "dfs_ap_move", "-2"));

    /* Use timer here to be sure dfs_ap_move will show correct status */
    bcmwl_dfs_timer_rearm(phy, 5.0);
}

static void bcmwl_dfs_bgcac_timer_rearm(const char *phyname, double timeout)
{
    bcmwl_dfs_timer(phyname, timeout, bcmwl_dfs_bgcac_recalc, "bgcac");
}

static double bcmwl_radio_recalc_cac_timeout(
        int dfs_preism,
        unsigned int cac_elapsed_ms,
        double timeout)
{
    int cac_seconds;

    cac_seconds = dfs_preism - (cac_elapsed_ms / 1000);
    if (cac_seconds <= 0)
        cac_seconds = dfs_preism/2;

    if (timeout == 0.0 || timeout > cac_seconds)
        timeout = cac_seconds;

    return timeout;
}

void bcmwl_radio_channels_get(
        const char *phyname,
        struct schema_Wifi_Radio_State *rstate)
{
    char *cmd_out;
    char *line;
    char *ptr;
    const char *dfs_ap_move;
    const char *dfs_status;
    int channel;
    enum bcmwl_chan_state state;
    int cur_chan[8];
    int cur_chan_num;
    double timeout;
    int nop_minutes;
    unsigned int cac_elapsed_ms;
    int dfs_preism;
    int aps_cnt;
    int i;

    timeout = 0.0;

    /* get dfs_preism */
    ptr = WL(phyname, "dfs_preism");
    if (!ptr || sscanf(ptr, "%d", &dfs_preism) != 1 || dfs_preism == -1)
        dfs_preism = 60;

    cmd_out = WL(phyname, "chan_info");
    dfs_ap_move = WL(phyname, "dfs_ap_move");
    dfs_status = WL(phyname, "dfs_status");
    cur_chan_num = bcmwl_get_current_channels(phyname, cur_chan, ARRAY_SIZE(cur_chan));

    if (!cmd_out)
        return;

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

                    if (!bcmwl_radio_valid_cac_state(dfs_ap_move, dfs_status, WL_DFS_CACSTATE_ISM,
                                                     channel, NULL)) {
                        /* Compare chan_info and dfs_ap_move status, should say the same */
                        timeout = 30.0;
                        LOGW("%s: lack of ISM, channel %d", phyname, channel);
                    }
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

                if (!aps_cnt)
                    continue;

                if (rstate->dfs_demo)
                    continue;

                if (!bcmwl_radio_valid_cac_state(dfs_ap_move, dfs_status, WL_DFS_CACSTATE_PREISM_CAC,
                                                 channel, &cac_elapsed_ms)) {
                    /* Compare chan_info and dfs_ap_move status, should say the same */
                    timeout = 30.0;
                    LOGW("%s: lack of PRE-ISM, channel %d", phyname, channel);
                }

                timeout = bcmwl_radio_recalc_cac_timeout(dfs_preism, cac_elapsed_ms, timeout);
                break;
            }

            if (bcmwl_radio_bg_pre_ism_state(dfs_ap_move, dfs_status, channel, &cac_elapsed_ms)) {
                state = BCMWL_CHAN_STATE_CAC_STARTED;
                timeout = bcmwl_radio_recalc_cac_timeout(dfs_preism, cac_elapsed_ms, timeout);
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
        bcmwl_dfs_timer_stop(phyname);

    /* Postpone bgcac because it can unintentionally cancel ongoing csa */
    if (bcmwl_dfs_bgcac_action_required(phyname))
        bcmwl_dfs_bgcac_timer_rearm(phyname, 10.0);
}
