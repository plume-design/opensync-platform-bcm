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
#include <errno.h>
#include <sys/types.h>
#include <dirent.h>
#include <net/if.h>
#include <linux/un.h>
#include <linux/rtnetlink.h>
#include <linux/socket.h>
#include <linux/netlink.h>

/* internal */
#include <kconfig.h>
#include <evx_debounce_call.h>
#include <target.h>
#include <log.h>
#include <opensync-ctrl.h>
#include <opensync-wpas.h>
#include <opensync-hapd.h>
#include <bcmwl.h>
#include <bcmwl_hostap.h>

/* local */
#define MODULE_ID LOG_MODULE_ID_TARGET

static ev_async g_nl_async;
static ev_io g_nl_io;

/* helpers */
static void
bcmwl_hostap_bss_report(const char *bss)
{
    const char *phy;
    int r;
    int v;

    if (WARN_ON(!bcmwl_parse_vap(bss, &r, &v)))
        return;

    phy = strfmta("wl%d", r);
    evx_debounce_call(bcmwl_vap_state_report, bss);
    evx_debounce_call(bcmwl_radio_state_report, phy);
}

/* hapd */
static void
bcmwl_hostap_hapd_ctrl_opened(struct ctrl *ctrl)
{
    bcmwl_hostap_bss_report(ctrl->bss);
    bcmwl_sta_resync(ctrl->bss);
}

static void
bcmwl_hostap_hapd_ctrl_closed(struct ctrl *ctrl)
{
    bcmwl_hostap_bss_report(ctrl->bss);
    bcmwl_sta_resync(ctrl->bss);
}

static void
bcmwl_hostap_hapd_ctrl_overrun(struct ctrl *ctrl)
{
    bcmwl_hostap_bss_report(ctrl->bss);
    bcmwl_sta_resync(ctrl->bss);
}

static void
bcmwl_hostap_hapd_ctrl_sta_connected(struct hapd *hapd, const char *mac, const char *keyid)
{
    /* relying on wl events for this */
}

static void
bcmwl_hostap_hapd_ctrl_sta_disconnected(struct hapd *hapd, const char *mac)
{
    /* relying on wl events for this */
}

static void
bcmwl_hostap_hapd_ctrl_ap_enabled(struct hapd *hapd)
{
    bcmwl_hostap_bss_report(hapd->ctrl.bss);
}

static void
bcmwl_hostap_hapd_ctrl_ap_disabled(struct hapd *hapd)
{
    bcmwl_hostap_bss_report(hapd->ctrl.bss);
}

/* wpas */
static void
bcmwl_hostap_wpas_ctrl_opened(struct ctrl *ctrl)
{
    bcmwl_hostap_bss_report(ctrl->bss);
}

static void
bcmwl_hostap_wpas_ctrl_closed(struct ctrl *ctrl)
{
    bcmwl_hostap_bss_report(ctrl->bss);
}

static void
bcmwl_hostap_wpas_ctrl_overrun(struct ctrl *ctrl)
{
    bcmwl_hostap_bss_report(ctrl->bss);
}

static void
bcmwl_hostap_wpas_ctrl_connected(struct wpas *wpas, const char *bssid, int id, const char *id_str)
{
    bcmwl_hostap_bss_report(wpas->ctrl.bss);
}

static void
bcmwl_hostap_wpas_ctrl_disconnected(struct wpas *wpas, const char *bssid, int reason, int local)
{
    bcmwl_hostap_bss_report(wpas->ctrl.bss);
}

/* helpers */
static void
bcmwl_hostap_fill_freqlist(struct wpas *wpas)
{
    char *chans = WL(wpas->phy, "channels");
    char *chan;
    size_t i = 0;

    if (WARN_ON(!chans))
        return;
    while ((chan = strsep(&chans, " \r\n")))
        if (i < ARRAY_SIZE(wpas->freqlist))
            wpas->freqlist[i++] = (atoi(chan) > 30 ? 5000 : 2407) + (5 * atoi(chan));
}

static void
bcmwl_hostap_init_bss(const char *bss)
{
    struct hapd *hapd = hapd_lookup(bss);
    struct wpas *wpas = wpas_lookup(bss);
    const char *phy;
    int r;
    int v;

    if (!bcmwl_parse_vap(bss, &r, &v))
        return;

    phy = strfmta("wl%d", r);

    if (v == 0 && kconfig_enabled(CONFIG_TARGET_CAP_EXTENDER)) {
        if (WARN_ON(hapd)) return;
        if (wpas) return;
        wpas = wpas_new(phy, bss);
    } else {
        if (WARN_ON(wpas)) return;
        if (hapd) return;
        hapd = hapd_new(phy, bss);
    }

    if (hapd) {
        hapd->ctrl.opened = bcmwl_hostap_hapd_ctrl_opened;
        hapd->ctrl.closed = bcmwl_hostap_hapd_ctrl_closed;
        hapd->ctrl.overrun = bcmwl_hostap_hapd_ctrl_overrun;
        hapd->sta_connected = bcmwl_hostap_hapd_ctrl_sta_connected;
        hapd->sta_disconnected = bcmwl_hostap_hapd_ctrl_sta_disconnected;
        hapd->ap_enabled = bcmwl_hostap_hapd_ctrl_ap_enabled;
        hapd->ap_disabled = bcmwl_hostap_hapd_ctrl_ap_disabled;
        ctrl_enable(&hapd->ctrl);
        hapd = NULL;
    }

    if (wpas) {
        bcmwl_hostap_fill_freqlist(wpas);
        wpas->ctrl.opened = bcmwl_hostap_wpas_ctrl_opened;
        wpas->ctrl.closed = bcmwl_hostap_wpas_ctrl_closed;
        wpas->ctrl.overrun = bcmwl_hostap_wpas_ctrl_overrun;
        wpas->connected = bcmwl_hostap_wpas_ctrl_connected;
        wpas->disconnected = bcmwl_hostap_wpas_ctrl_disconnected;
        ctrl_enable(&wpas->ctrl);
        wpas = NULL;
    }
}

static void
bcmwl_hostap_nl_io(EV_P_ ev_io *io, int events)
{
    const struct nlmsghdr *nlh;
    const struct rtattr *rta;
    ssize_t n;
    char buf[4096];
    int len;

    n = recv(io->fd, buf, sizeof(buf), MSG_DONTWAIT);
    LOGD("netlink buffer recvfrom() = %d", n);
    if (n < 0) {
        if (errno == EAGAIN)
            return;
        LOGI("restarting netlink socket (errno = %d)", errno);
        ev_io_stop(EV_DEFAULT_ io);
        ev_async_send(EV_DEFAULT_ &g_nl_async);
        return;
    }

    for (nlh = (void *)buf; NLMSG_OK(nlh, n); nlh = NLMSG_NEXT(nlh, n))
        if (nlh->nlmsg_type == RTM_NEWLINK)
            for (rta = IFLA_RTA(NLMSG_DATA(nlh)), len = IFLA_PAYLOAD(nlh);
                 RTA_OK(rta, len);
                 rta = RTA_NEXT(rta, len))
                if (rta->rta_type == IFLA_IFNAME)
                    bcmwl_hostap_init_bss(RTA_DATA(rta));
}

static void
bcmwl_hostap_init_all(void)
{
    struct dirent *p;
    DIR *d;

    for (d = opendir("/sys/class/net"); d && (p = readdir(d)); )
        bcmwl_hostap_init_bss(p->d_name);

    closedir(d);
}

static void
bcmwl_hostap_init_nl(EV_P_ ev_async *async, int events)
{
    struct sockaddr_nl addr = {
        .nl_family = AF_NETLINK,
        .nl_groups = RTMGRP_LINK
    };
    int fd;

    LOGI("opening netlink socket");

    if (WARN_ON((fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0))
        return;
    if (WARN_ON((bind(fd, (struct sockaddr *)&addr, sizeof(addr))) < 0))
        return;
    if (WARN_ON((setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (int []){ 2*1024*1024 } , sizeof(int))) < 0))
        return;

    ev_io_init(&g_nl_io, bcmwl_hostap_nl_io, fd, EV_READ);
    ev_io_start(EV_DEFAULT_ &g_nl_io);
    bcmwl_hostap_init_all();
}

/* api */
void
bcmwl_hostap_init(void)
{
    ev_async_init(&g_nl_async, bcmwl_hostap_init_nl);
    ev_async_start(EV_DEFAULT_ &g_nl_async);
    ev_async_send(EV_DEFAULT_ &g_nl_async);
}

void
bcmwl_hostap_bss_apply(const struct schema_Wifi_VIF_Config *vconf,
                       const struct schema_Wifi_Radio_Config *rconf,
                       const struct schema_Wifi_Credential_Config *cconf,
                       const struct schema_Wifi_VIF_Config_flags *vchanged,
                       size_t n_cconf)
{
    struct hapd *hapd = hapd_lookup(vconf->if_name);
    struct wpas *wpas = wpas_lookup(vconf->if_name);

    if (WARN_ON(hapd && wpas))
        return;

    if (hapd) {
        WARN_ON(hapd_conf_gen(hapd, rconf, vconf) < 0);
        WARN_ON(hapd_conf_apply(hapd) < 0);
    }

    if (wpas) {
        WARN_ON(wpas_conf_gen(wpas, rconf, vconf, cconf, n_cconf) < 0);
        WARN_ON(wpas_conf_apply(wpas) < 0);
    }
}

void
bcmwl_hostap_bss_get(const char *bss,
                     struct schema_Wifi_VIF_State *vstate)
{
    struct hapd *hapd = hapd_lookup(bss);
    struct wpas *wpas = wpas_lookup(bss);

    if (WARN_ON(hapd && wpas))
        return;

    if (hapd) {
        SCHEMA_SET_STR(vstate->mode, "ap");
        hapd_bss_get(hapd, vstate);
    }

    if (wpas) {
        SCHEMA_SET_STR(vstate->mode, "sta");
        wpas_bss_get(wpas, vstate);
    }
}

void bcmwl_hostap_sta_get(const char *bss,
                          const char *mac,
                          struct schema_Wifi_Associated_Clients *client)
{
    struct hapd *hapd = hapd_lookup(bss);
    if (WARN_ON(!hapd))
        return;
    hapd_sta_get(hapd, mac, client);
}
