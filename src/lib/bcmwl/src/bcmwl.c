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

/* std libc */
#include <sys/types.h>
#include <dirent.h>

/* internal */
#include <evx.h>
#include <target.h>
#include <log.h>
#include <bcmwl.h>
#include <bcmwl_nvram.h>
#include <bcmwl_lan.h>
#include <bcmwl_roam.h>
#include <bcmwl_ioctl.h>
#include <bcmwl_nas.h>
#include <bcmwl_debounce.h>
#include <bcmwl_wps.h>
#include <bcmwl_hostap.h>
#include <bcmwl_acl.h>

/* local */
static void bcmwl_radar_onsta(void)
{
    struct dirent *p;
    DIR *d;

    /* Stock driver behavior would exempt regular APSTA
     * operation from radar detection assuming the AP
     * (master) will merely send a CSA when it detects a
     * radar. The driver is already running (as expected)
     * radar detection on MAP-based APSTA though. Since
     * we're using GRE (and still will be for a while) the
     * regular APSTA needs to respect radars too. The driver
     * has been patched by BCM to expose this business
     * policy as an iovar in recent drivers. Tweak it on
     * best-effort basis so older drivers still work to the
     * best of their ability.
     */
    for (d = opendir("/sys/class/net"); d && (p = readdir(d)); )
        if (bcmwl_is_phy(p->d_name))
            WL(p->d_name, "dfs_handle_radar_onsta", "1");
    if (!WARN_ON(!d))
        closedir(d);
}

static void bcmwl_keep_ap_up(void)
{
    struct dirent *p;
    DIR *d;

    /* Normally when STA BSS disconnects the local AP will
     * follow suit unless keep_ap_up is enabled. 1=always
     * 2=non-dfs. There's also a side-effect that if
     * keep_ap_up=0 radar=0 then it's impossible to start an
     * AP on dfs channel if no STA BSS is associated. Not
     * all drivers support keep_ap_up or require it, so
     * WARN_ON isn't used here.
     */
    for (d = opendir("/sys/class/net"); d && (p = readdir(d)); )
        if (bcmwl_is_phy(p->d_name))
            WL(p->d_name, "keep_ap_up", "1");
    if (!WARN_ON(!d))
        closedir(d);
}

static void bcmwl_mpc_disable(void)
{
    struct dirent *p;
    DIR *d;

    /* MPC is a radio power state station powersaving. When
     * station interface is down, there are no access point
     * interfaces and MPC is enabled then the radio is
     * powered off. It is transiently powered on, e.g. for
     * scans. This is unnecessary for an AP/Repeater device
     * and introduces unnecessary churn since it causes
     * extra radio power transitions.
     */
    for (d = opendir("/sys/class/net"); d && (p = readdir(d)); )
        if (bcmwl_is_phy(p->d_name))
            WARN_ON(!WL(p->d_name, "mpc", "0"));
    if (!WARN_ON(!d))
        closedir(d);
}

static void bcmwl_mask_nonstd_11n_2ghz_rates(void)
{
    struct dirent *p;
    DIR *d;
    const char *band;
    char *bands;

    /* Some wifi client implementations are buggy and will
     * refuse to associate with 11n capabilities enabled.
     * Instead they would downgrade to 11g/b legacy mode.
     *
     * This implies they'd run a lot slower than they should.
     * Given these are top-end rates mostly achievable only
     * in pristine rf conditions (e.g. labs) disabling them
     * should have little effect on real-world peak
     * performance.
     */
    for (d = opendir("/sys/class/net"); d && (p = readdir(d)); )
        if (bcmwl_is_phy(p->d_name))
            if ((bands = WL(p->d_name, "bands")))
                while ((band = strsep(&bands, " ")))
                    if (!strcmp(band, "b")) {
                        LOGI("%s: applying explicit rateset to avoid non-std 11n mcs", p->d_name);
                        WARN_ON(!WL(p->d_name, "rateset", "-m", "0xff", "0xff", "0xff", "0xff"));
                    }
    if (!WARN_ON(!d))
        closedir(d);
}

bool bcmwl_init_wm(void)
{
    LOGI("bcmwl: wm: initializing");
    bcmwl_event_discard_probereq();
    bcmwl_event_enable_all(WLC_E_ACTION_FRAME);
    bcmwl_event_enable_all(WLC_E_AP_CHAN_CHANGE);
    bcmwl_event_enable_all(WLC_E_ASSOC);
    bcmwl_event_enable_all(WLC_E_ASSOC_IND);
    bcmwl_event_enable_all(WLC_E_AUTH);
    bcmwl_event_enable_all(WLC_E_AUTHORIZED);
    bcmwl_event_enable_all(WLC_E_AUTH_IND);
    bcmwl_event_enable_all(WLC_E_CSA_COMPLETE_IND);
    bcmwl_event_enable_all(WLC_E_DEAUTH);
    bcmwl_event_enable_all(WLC_E_DEAUTH_IND);
    bcmwl_event_enable_all(WLC_E_DISASSOC);
    bcmwl_event_enable_all(WLC_E_DISASSOC_IND);
    bcmwl_event_enable_all(WLC_E_EAPOL_MSG);
    bcmwl_event_enable_all(WLC_E_ESCAN_RESULT);
    bcmwl_event_enable_all(WLC_E_JOIN);
    bcmwl_event_enable_all(WLC_E_LINK);
    bcmwl_event_enable_all(WLC_E_PROBREQ_MSG);
    bcmwl_event_enable_all(WLC_E_PROBREQ_MSG_RX);
    bcmwl_event_enable_all(WLC_E_PRUNE);
    bcmwl_event_enable_all(WLC_E_RADAR_DETECTED);
    bcmwl_event_enable_all(WLC_E_RADIO);
    bcmwl_event_enable_all(WLC_E_REASSOC_IND);
    bcmwl_event_enable_all(WLC_E_SCAN_COMPLETE);
    bcmwl_event_enable_all(WLC_E_SET_SSID);
    bcmwl_event_enable_all(WLC_E_IF);
    bcmwl_radar_onsta();
    bcmwl_keep_ap_up();
    bcmwl_mpc_disable();
    bcmwl_mask_nonstd_11n_2ghz_rates();
    bcmwl_dfs_init();
    bcmwl_nas_init();
    if (WARN_ON(!bcmwl_wps_init()))
        return false;
    return true;
}

bool bcmwl_init(const struct target_radio_ops *ops)
{
    LOGI("bcmwl: initializing");
    assert(strexa("which", "wl"));
    assert(strexa("which", "nvram"));
    bcmwl_debounce_init(ops);
    bcmwl_hostap_init();
    bcmwl_event_init();
    if (WARN_ON(!bcmwl_ioctl_init()))
        return false;
    if (WARN_ON(!bcmwl_acl_init()))
        return false;

    return true;
}
