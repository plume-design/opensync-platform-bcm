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

/**
 * bcmwl_roam
 *
 * Helpers to deal with station interface roaming logic.
 *
 * Broadcom wl driver doesn't support any kind of station interface
 * roaming in nas/eapd nor internally in the driver. That is what
 * support says. There are some odd "wl" commands but they don't seem
 * to work nor would I rely on them.
 *
 * There's also no "sticky bssid" support so it's not guaranteed for a
 * station interface to re-connect upon a transient connectivity loss.
 *
 * Current roaming implementation is bare minimum for single ssid/psk.
 *
 * FIXME:
 *  - support multiple ssid/psk (for credential config support)
 *  - support other than wpa2-only networks
 *  - consider scan results
 *  - consider matching rsn/wpa ie
 *  - optimize for speed
 *  - reduce number of unnecessary bss down/up/join calls
 */
#define _GNU_SOURCE

/* std libc */
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <arpa/inet.h>

/* internal */
#include <evx.h>
#include <evx_debounce_call.h>
#include <log.h>
#include <bcmwl.h>
#include <bcmwl_roam.h>
#include <bcmwl_nvram.h>
#include <bcmwl_debounce.h>

#define BCMWL_ROAM_MAX_VIFS 4
#define BCMWL_ROAM_DEBOUNCE_SECS 1.0
#define BCMWL_ROAM_TIMEOUT_SECS 20.0

struct bcmwl_roam {
    ev_timer timeout;
    ev_debounce update;
};

static struct bcmwl_roam g_bcmwl_roam_states[BCMWL_ROAM_MAX_VIFS];

static int
bcmwl_roam_ifname2idx(const char *ifname)
{
    return atoi(strpbrk(ifname, "1234567890") ?: "");
}

static struct bcmwl_roam *
bcmwl_roam_get(const char *ifname)
{
    size_t i = bcmwl_roam_ifname2idx(ifname);
    if (WARN_ON(i >= ARRAY_SIZE(g_bcmwl_roam_states)))
            return NULL;
    return &g_bcmwl_roam_states[i];
}

static const char *
bcmwl_roam_ptr2ifname(struct bcmwl_roam *r)
{
    int i = r - g_bcmwl_roam_states;
    switch (i) {
        case 0: return "wl0";
        case 1: return "wl1";
        case 2: return "wl2";
    }
    return "wl999";
}

static char *
bcmwl_roam_get_allowed_channels(const char *ifname)
{
    const char *c;
    char *chan_info;
    char *channels;
    char *line;

    if (WARN_ON(!(channels = WL(ifname, "channels"))))
        return NULL;
    if (WARN_ON(!(chan_info = WL(ifname, "chan_info"))))
        return NULL;
    while ((line = strsep(&chan_info, "\r\n")))
        if (strstr(line, "RADAR") && strsep(&line, "\t ") && (c = strsep(&line, "\t ")))
            strdel(channels, c, strcasecmp);
    return strdup(channels);
}

static bool
bcmwl_roam_is_chan_allowed(const char *ifname, int chan)
{
    char *chans = strdupafree(bcmwl_roam_get_allowed_channels(ifname));
    char *i;
    while ((i = strsep(&chans, " ")))
        if (atoi(i) == chan)
            return true;
    return false;
}

enum bcmwl_roam_status
bcmwl_roam_get_status(const char *ifname)
{
    struct bcmwl_roam *r = bcmwl_roam_get(ifname);
    struct wl_status status;
    const char *bssid;
    const char *ssid;
    const char *p;

    if (!r)
        return BCMWL_ROAM_DISABLED;

    bcmwl_vap_get_status(ifname, &status);

    if (!status.is_sta) {
        LOGD("roam: %s: not a sta, ignoring", ifname);
        return BCMWL_ROAM_DISABLED;
    }

    if (strcmp("1", NVG(ifname, "plume_bss_enabled") ?: "0")) {
        LOGD("roam: %s: is down, ignoring", ifname);
        return BCMWL_ROAM_DISABLED;
    }

    if (!(p = strexa("ip", "link", "show", "dev", ifname, "up")) || !strlen(p))
        LOGW("roam: %s: netdev is down, expect keying issues", ifname);

    bssid = NVG(ifname, "plume_desired_bssid") ?: "";
    ssid = NVG(ifname, "ssid") ?: "";

    if (!status.is_up) {
        LOGI("roam: %s: not associated yet", ifname);
        return BCMWL_ROAM_MISMATCH;
    }

    if (strcmp(ssid, status.ssid)) {
        LOGI("roam: %s: wrong ssid (%s vs %s)", ifname, ssid, status.ssid);
        return BCMWL_ROAM_MISMATCH;
    }

    if (strlen(bssid) && strcasecmp(bssid, status.bssid)) {
        LOGI("roam: %s: wrong bssid (%s vs %s)", ifname, bssid, status.bssid);
        return BCMWL_ROAM_MISMATCH;
    }

    if (!strlen(bssid) && !bcmwl_roam_is_chan_allowed(ifname, status.channel)) {
        LOGI("roam: %s: channel %d not allowed", ifname, status.channel);
        return BCMWL_ROAM_MISMATCH;
    }

    if (!status.is_authorized) {
        LOGI("roam: %s: not authorized yet", ifname);
        if (ev_is_active(&r->timeout))
            return BCMWL_ROAM_BUSY;
        else
            return BCMWL_ROAM_NEEDED;
    }

    LOGD("roam: %s: connected to '%s' [desired=%s current=%s] chan=%d, ignoring",
         ifname, ssid, bssid, status.bssid, status.channel);
    return BCMWL_ROAM_COMPLETE;
}

static bool
bcmwl_roam_prep(const char *ifname)
{
    const char *p;
    int c;
    int w;

    WARN_ON(!WL(ifname, "bss", "down"));

    if ((p = NVG(ifname, "chanspec")) && strlen(p)) {
        LOGD("roam: %s: chanspec '%s' found, syncing", ifname, p);
        bcmwl_radio_chanspec_extract(p, &c, &w);
        if (WARN_ON(!bcmwl_radio_channel_set(ifname, c, strfmta("HT%d", w))))
            return false;
    }

    return true;
}

static void
bcmwl_roam_join(const char *ifname)
{
    static const char *bssid_any = "ff:ff:ff:ff:ff:ff";
    const char *allowed = strdupafree(bcmwl_roam_get_allowed_channels(ifname));
    const char *bssid = NVG(ifname, "plume_desired_bssid") ?: "";
    const char *chan = NVG(ifname, "channel") ?: allowed;
    const char *ssid = NVG(ifname, "ssid") ?: "";

    if (!strlen(bssid)) {
        bssid = bssid_any;
        chan = allowed;
    }

    if (!strlen(chan))
        chan = allowed;

    LOGI("roam: %s: connecting to '%s' bssid %s chans [%s]", ifname, ssid, bssid, chan);
    WARN_ON(!WL(ifname, "join", ssid, "amode", "wpa2psk", "-b", bssid, "-c", chan));
}

static void
bcmwl_roam_now(const char *ifname)
{
    struct bcmwl_roam *r = bcmwl_roam_get(ifname);

    if (WARN_ON(!r))
        return;
    switch (bcmwl_roam_get_status(ifname)) {
        case BCMWL_ROAM_DISABLED:
            break;
        case BCMWL_ROAM_BUSY:
            break;
        case BCMWL_ROAM_NEEDED:
        case BCMWL_ROAM_MISMATCH:
            bcmwl_roam_prep(ifname);
            bcmwl_roam_join(ifname);
            ev_timer_set(&r->timeout, BCMWL_ROAM_TIMEOUT_SECS, 0.0);
            ev_timer_start(EV_DEFAULT_ &r->timeout);
            evx_debounce_call(bcmwl_vap_state_report, ifname);
            break;
        case BCMWL_ROAM_COMPLETE:
            ev_timer_stop(EV_DEFAULT_ &r->timeout);
            evx_debounce_call(bcmwl_vap_state_report, ifname);
            break;
    }
}

void
bcmwl_roam_later(const char *ifname)
{
    struct bcmwl_roam *r = bcmwl_roam_get(ifname);

    if (WARN_ON(!r))
        return;
    if (!r->update.timer.cb)
        return;
    if (ev_is_active(&r->update))
        return;

    LOGD("roam: %s: scheduling", ifname);
    ev_debounce_start(EV_DEFAULT_ &r->update);
}

static void
bcmwl_roam_update_cb(struct ev_loop *loop, ev_debounce *ev, int revent)
{
    struct bcmwl_roam *r = container_of(ev, struct bcmwl_roam, update);
    const char *ifname = bcmwl_roam_ptr2ifname(r);
    if (WARN_ON(!r))
        return;
    LOGD("roam: %s: roaming now", ifname);
    bcmwl_roam_now(ifname);
}

static void
bcmwl_roam_timeout_cb(EV_P_ ev_timer *ev, int revent)
{
    struct bcmwl_roam *r = container_of(ev, struct bcmwl_roam, timeout);
    const char *ifname = bcmwl_roam_ptr2ifname(r);
    if (WARN_ON(!r))
        return;
    LOGD("roam: %s: timed out", ifname);
    bcmwl_roam_later(ifname);
}

void
bcmwl_roam_init(const char *ifname, const char *bssid)
{
    struct bcmwl_roam *r = bcmwl_roam_get(ifname);
    if (WARN_ON(!r))
        return;
    WARN_ON(!NVS(ifname, "plume_desired_bssid", bssid));
    if (r->update.timer.cb)
        return;
    LOGI("roam: %s: initializing", ifname);
    ev_debounce_init(&r->update, bcmwl_roam_update_cb,
            BCMWL_ROAM_DEBOUNCE_SECS);
    ev_timer_init(&r->timeout, bcmwl_roam_timeout_cb,
            BCMWL_ROAM_TIMEOUT_SECS, 0.0);
}

void
bcmwl_roam_event_handler(const bcm_event_t *ev)
{
    const char *ifname = ev->event.ifname;
    struct bcmwl_roam *r = bcmwl_roam_get(ifname);
    int status = ntohl(ev->event.status);
    int type = ntohl(ev->event.event_type);

    if (r)
        return;

    switch (type) {
        //case WLC_E_SCAN_COMPLETE:
        //case WLC_E_ESCAN_RESULT:
        case WLC_E_SET_SSID:
        case WLC_E_DEAUTH:
        case WLC_E_DEAUTH_IND:
        case WLC_E_DISASSOC:
        case WLC_E_DISASSOC_IND:
        case WLC_E_JOIN:
        case WLC_E_LINK:
        case WLC_E_EAPOL_MSG:
        case WLC_E_CSA_COMPLETE_IND:
        case WLC_E_AUTHORIZED:
            if (!bcmwl_vap_is_sta(ifname))
                return;

            LOGD("roam: %s: processing event %d", ifname, type);

            if (type == WLC_E_SET_SSID) {
                if (status > 0)
                    LOGI("roam: %s: failed to connect: %d", ifname, status);
                ev_timer_stop(EV_DEFAULT_ &r->timeout);
            }

            bcmwl_roam_later(ifname);
            evx_debounce_call(bcmwl_vap_state_report, ifname);
            break;
    }
}
