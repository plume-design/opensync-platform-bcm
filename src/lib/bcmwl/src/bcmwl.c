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

/* local */
static void bcmwl_csa_ind_enable(void)
{
    struct dirent *p;
    DIR *d;

    /* CSA indication isn't guaranteed to be always enabled.
     * E.g. I've found 2.4GHz has it disabled by default and
     * enabled on 5GHz radio on one of the extender
     * platforms.
     */
    for (d = opendir("/sys/class/net"); d && (p = readdir(d)); )
        if (bcmwl_is_phy(p->d_name))
            bcmwl_event_enable(p->d_name, WLC_E_CSA_COMPLETE_IND);
    if (!WARN_ON(!d))
        closedir(d);
}

static void bcmwl_radio_ind_enable(void)
{
    struct dirent *p;
    DIR *d;

    for (d = opendir("/sys/class/net"); d && (p = readdir(d)); )
        if (bcmwl_is_phy(p->d_name))
            bcmwl_event_enable(p->d_name, WLC_E_RADIO);
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
    assert(strexa("which", "eapd"));
    assert(strexa("which", "nas"));
    bcmwl_event_discard_probereq();
    bcmwl_csa_ind_enable();
    bcmwl_radio_ind_enable();
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
    if (WARN_ON(!bcmwl_ioctl_init()))
        return false;
    if (WARN_ON(!bcmwl_acl_init()))
        return false;

    return true;
}
