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

/* std libc */
#define _GNU_SOURCE
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <glob.h>

/* internal */
#include <os_proc.h>
#include <evx.h>
#include <target.h>
#include <log.h>
#include <bcmwl.h>
#include <bcmwl_nvram.h>
#include <bcmwl_wps.h>

/* local */
struct ev_timer g_bcmwl_nas_supervise_timer;
struct ev_signal g_bcmwl_nas_sigusr1;

#define BCMWL_NAS_SUPERVISE_INTERVAL_SEC 30
#define BCMWL_NAS_SUPERVISE_FIRST_DELAY_SEC 30

static void bcmwl_nas_sigusr1(struct ev_loop *loop, ev_signal *s, int revent)
{
    LOGI("nas: fast reload completed");
}

bool bcmwl_nas_multipsk_is_supported(void)
{
    const char *pid = strexa("pidof", "nas") ?: "";
    const char *path = strfmta("/proc/%s/exe", pid);
    return path && strexa("grep", "-q", "%s_sta_%s_keyid", path);
}

static bool bcmwl_nas_reload_fast_is_supported(void)
{
    const char *pid = strexa("pidof", "nas") ?: "";
    const char *path = strfmta("/proc/%s/exe", pid);
    return path && strexa("grep", "-q", "nas_fast_reload_notify_pid", path);
}

static bool bcmwl_nas_reload_fast(void)
{
    LOGN("reloading auth (fast)");

    bcmwl_wps_restart();

    return strexa("killall", "-USR2", "nas");
}

static void bcmwl_nas_reload_full(void)
{
    struct dirent *p;
    DIR *d;

    LOGN("reloading auth");

    /* Can't use strexa() or a naive fork+exec-waitpid
     * because nas/eapd are not properly closing their
     * descriptors so they would hang indefinitely.
     */
    system("killall -KILL eapd nas; nas </dev/null >/dev/null 2>/dev/null; eapd </dev/null >/dev/null 2>/dev/null");

    bcmwl_wps_restart();

    if (!(d = opendir("/sys/class/net")))
        return;
    while ((p = readdir(d)))
        if (strstr(p->d_name, "wl") == p->d_name)
            if (!bcmwl_vap_is_sta(p->d_name))
                WL(p->d_name, "deauthenticate", "ff:ff:ff:ff:ff:ff");
    closedir(d);
}

void bcmwl_nas_reload(const char *arg)
{
    int flag;

    flag = atoi(NVG("nas", "reload") ?: "0");
    NVU("nas", "reload");

    if (flag & (1 << BCMWL_NAS_RELOAD_FAST) && !bcmwl_nas_reload_fast_is_supported()) {
        LOGI("nas: fast reload scheduled, but not supported. performing full reload");
        flag &= ~(1 << BCMWL_NAS_RELOAD_FAST);
        flag |= 1 << BCMWL_NAS_RELOAD_FULL;
    }

    if (flag & (1 << BCMWL_NAS_RELOAD_FULL)) {
        bcmwl_nas_reload_full();
        return;
    }

    if (flag & (1 << BCMWL_NAS_RELOAD_FAST)) {
        if (WARN_ON(!bcmwl_nas_reload_fast()))
            bcmwl_nas_reload_full();
        return;
    }
}

static int bcmwl_nas_supervise(const char *name)
{
    pid_t pid = os_name_to_pid(name);
    LOGT("supervise: %s: checking for pid: %d", name, pid);
    if (pid > 0)
        return 0;
    LOGW("supervise: %s: found dead", name);
    return -1;
}

static void bcmwl_nas_supervise_timer(struct ev_loop *loop, ev_timer *s, int revent)
{
    int err = 0;
    LOGD("supervise: checking");
    err |= bcmwl_nas_supervise("nas");
    err |= bcmwl_nas_supervise("eapd");
    if (bcmwl_wps_enabled())
        err |= bcmwl_nas_supervise(bcmwl_wps_process_name());
    if (err) {
        LOGI("supervise: restarting services because something crashed");
        bcmwl_nas_reload_full();
    }
}

void bcmwl_nas_init(void)
{
    ev_timer_init(&g_bcmwl_nas_supervise_timer,
                  bcmwl_nas_supervise_timer,
                  BCMWL_NAS_SUPERVISE_FIRST_DELAY_SEC,
                  BCMWL_NAS_SUPERVISE_INTERVAL_SEC);
    ev_timer_start(EV_DEFAULT_ &g_bcmwl_nas_supervise_timer);
    ev_signal_init(&g_bcmwl_nas_sigusr1, bcmwl_nas_sigusr1, SIGUSR1);
    ev_signal_start(EV_DEFAULT, &g_bcmwl_nas_sigusr1);
    NVS("nas", "fast_reload_notify_pid", strfmta("%d", getpid()));
}
