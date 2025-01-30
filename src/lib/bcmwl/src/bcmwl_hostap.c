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
#include <stdio.h>
#include <errno.h>
#include <glob.h>
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
#include <opensync-ctrl-dpp.h>
#include <bcmwl.h>
#include <bcmwl_hostap.h>

/* local */
#define MODULE_ID LOG_MODULE_ID_TARGET
#define BCMWL_HOSTAP_DFS_SCAN_FAILURES_KEEPAPUP 3
#define BCMWL_HOSTAP_DFS_SCAN_FAILURES_BSSDOWN 6

static ev_async g_nl_async;
static ev_io g_nl_io;
static int g_scan_failures;

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

static void
bcmwl_hostap_all_local_bss_down(struct wpas *wpas)
{
    const char *bss = wpas->ctrl.bss;
    int r;
    int v;
    if (WARN_ON(!bcmwl_parse_vap(bss, &r, &v)))
        return;

    glob_t g;
    const char *pattern = strfmta("/sys/class/net/wl%d.*", r);
    const int err = glob(pattern, 0, NULL, &g);
    if (err) return;

    size_t i;
    for (i = 0; i < g.gl_pathc; i++) {
        char *path = strdupa(g.gl_pathv[i]);
        char *if_name = basename(path);
        if (if_name == NULL) continue;
        WL(if_name, "bss", "down");
    }
    globfree(&g);
}

static void
bcmwl_hostap_all_local_bss_down_maybe(struct wpas *wpas)
{
    if (g_scan_failures < BCMWL_HOSTAP_DFS_SCAN_FAILURES_BSSDOWN) return;

    LOGI("%s: trying to disable all local bsses (scan failures=%d)",
         wpas->ctrl.bss, g_scan_failures);

    bcmwl_hostap_all_local_bss_down(wpas);
}

static void
bcmwl_hostap_disable_keep_ap_up_maybe(struct wpas *wpas)
{
    if (g_scan_failures < BCMWL_HOSTAP_DFS_SCAN_FAILURES_KEEPAPUP) return;

    LOGI("%s: trying to disable keep_ap_up (scan failures=%d)",
         wpas->ctrl.bss, g_scan_failures);

    WARN_ON(!WL(wpas->ctrl.bss, "keep_ap_up", "0"));
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
bcmwl_hostap_ctrl_dpp_chirp_received(struct ctrl *ctrl,
                                     const struct target_dpp_chirp_obj *chirp)
{
    if (WARN_ON(!bcmwl_ops.op_dpp_announcement))
        return;
    bcmwl_ops.op_dpp_announcement(chirp);
}

static void
bcmwl_hostap_ctrl_dpp_conf_sent(struct ctrl *ctrl,
                                const struct target_dpp_conf_enrollee *enrollee)
{
    if (WARN_ON(!bcmwl_ops.op_dpp_conf_enrollee))
        return;
    bcmwl_ops.op_dpp_conf_enrollee(enrollee);
}

static void
bcmwl_hostap_ctrl_dpp_conf_received(struct ctrl *ctrl,
                                    const struct target_dpp_conf_network *conf)
{
    if (WARN_ON(!bcmwl_ops.op_dpp_conf_network))
        return;
    bcmwl_ops.op_dpp_conf_network(conf);
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

static void
bcmwl_hostap_hapd_ctrl_wps_active(struct hapd *hapd)
{
    bcmwl_vap_state_report(hapd->ctrl.bss);
    bcmwl_hostap_reset_wps_pbc(hapd->ctrl.bss);
}

static void
bcmwl_hostap_hapd_ctrl_wps_success(struct hapd *hapd)
{
    bcmwl_vap_state_report(hapd->ctrl.bss);
}

static void
bcmwl_hostap_hapd_ctrl_wps_timeout(struct hapd *hapd)
{
    bcmwl_vap_state_report(hapd->ctrl.bss);
}

static void
bcmwl_hostap_hapd_ctrl_wps_disable(struct hapd *hapd)
{
    bcmwl_vap_state_report(hapd->ctrl.bss);
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
    WARN_ON(!WL(ctrl->bss, "keep_ap_up", "1"));
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
    WARN_ON(!WL(wpas->ctrl.bss, "keep_ap_up", "1"));
}

static void
bcmwl_hostap_wpas_ctrl_disconnected(struct wpas *wpas, const char *bssid, int reason, int local)
{
    bcmwl_hostap_bss_report(wpas->ctrl.bss);
}

static void
bcmwl_hostap_wpas_scan_results(struct wpas *wpas)
{
    g_scan_failures = 0;
}

static void
bcmwl_hostap_wpas_scan_failed(struct wpas *wpas, int status)
{
    g_scan_failures++;
    bcmwl_hostap_disable_keep_ap_up_maybe(wpas);
    bcmwl_hostap_all_local_bss_down_maybe(wpas);
}

/* helpers */
static void
bcmwl_hostap_fill_freqlist(struct wpas *wpas)
{
    char *chans = WL(wpas->phy, "chanspecs");
    char *line;
    int freq;
    int cs;
    size_t i = 0;

    if (WARN_ON(!chans))
        return;

    while ((line = strsep(&chans, "\n")))
        if (i < ARRAY_SIZE(wpas->freqlist))
        {
            if (1 == sscanf(line, "%*s (%x)", &cs))
            {
                if (bcmwl_chanspec_get_bw_mhz(cs) == 20)
                    if ((freq = bcmwl_chanspec_get_center_freq(cs)) > 0)
                        wpas->freqlist[i++] = freq;
            }
            else
            {
                LOG(WARN, "bcmwl: unexpected %s chanspecs report format: %s", wpas->phy, line);
            }
        }

    WARN_ON(i == ARRAY_SIZE(wpas->freqlist));
}

static bool
bcmwl_hostap_is_ap(const char *bss)
{
    return bcmwl_vap_is_sta(bss) == false &&
           bcmwl_vap_is_ap(bss) == true;
}

static bool
bcmwl_hostap_is_sta(const char *bss)
{
    return bcmwl_vap_is_sta(bss) == true &&
           bcmwl_vap_is_ap(bss) == false;
}

void
bcmwl_hostap_init_bss(const char *bss)
{
    struct hapd *hapd = hapd_lookup(bss);
    struct wpas *wpas = wpas_lookup(bss);
    const char *phy;
    int r;
    int v;

    if (!bcmwl_parse_vap(bss, &r, &v))
        return;

    if (strstr(bss, "wds") == bss)
        return;

    phy = strfmta("wl%d", r);

    if (bcmwl_hostap_is_ap(bss)) {
        if (wpas) wpas_destroy(wpas);
        wpas = NULL;

        if (hapd) return;
        hapd = hapd_new(phy, bss);
    }

    if (bcmwl_hostap_is_sta(bss)) {
        if (hapd) hapd_destroy(hapd);
        hapd = NULL;

        if (wpas) return;
        wpas = wpas_new(phy, bss);
    }

    if (hapd) {
        hapd->ctrl.opened = bcmwl_hostap_hapd_ctrl_opened;
        hapd->ctrl.closed = bcmwl_hostap_hapd_ctrl_closed;
        hapd->ctrl.overrun = bcmwl_hostap_hapd_ctrl_overrun;
        hapd->ctrl.dpp_chirp_received = bcmwl_hostap_ctrl_dpp_chirp_received;
        hapd->ctrl.dpp_conf_sent = bcmwl_hostap_ctrl_dpp_conf_sent;
        hapd->ctrl.dpp_conf_received = bcmwl_hostap_ctrl_dpp_conf_received;
        hapd->sta_connected = bcmwl_hostap_hapd_ctrl_sta_connected;
        hapd->sta_disconnected = bcmwl_hostap_hapd_ctrl_sta_disconnected;
        hapd->ap_enabled = bcmwl_hostap_hapd_ctrl_ap_enabled;
        hapd->ap_disabled = bcmwl_hostap_hapd_ctrl_ap_disabled;
        hapd->wps_active = bcmwl_hostap_hapd_ctrl_wps_active;
        hapd->wps_success = bcmwl_hostap_hapd_ctrl_wps_success;
        hapd->wps_timeout = bcmwl_hostap_hapd_ctrl_wps_timeout;
        hapd->wps_disable = bcmwl_hostap_hapd_ctrl_wps_disable;
        hapd->use_driver_rrb_lo = true;
        /* FIXME - the below options will be determined at runtime
         * inside hapd.c */
        hapd->use_reload_rxkhs = true;
        hapd->use_rxkh_file = true;
        hapd->use_op_class = false;
        ctrl_enable(&hapd->ctrl);
        hapd = NULL;
    }

    if (wpas) {
        bcmwl_hostap_fill_freqlist(wpas);
        wpas->ctrl.opened = bcmwl_hostap_wpas_ctrl_opened;
        wpas->ctrl.closed = bcmwl_hostap_wpas_ctrl_closed;
        wpas->ctrl.overrun = bcmwl_hostap_wpas_ctrl_overrun;
        wpas->ctrl.dpp_chirp_received = bcmwl_hostap_ctrl_dpp_chirp_received;
        wpas->ctrl.dpp_conf_sent = bcmwl_hostap_ctrl_dpp_conf_sent;
        wpas->ctrl.dpp_conf_received = bcmwl_hostap_ctrl_dpp_conf_received;
        wpas->connected = bcmwl_hostap_wpas_ctrl_connected;
        wpas->disconnected = bcmwl_hostap_wpas_ctrl_disconnected;
        wpas->scan_failed = bcmwl_hostap_wpas_scan_failed;
        wpas->scan_results = bcmwl_hostap_wpas_scan_results;
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

    for (nlh = (void *)buf; NLMSG_OK(nlh, (unsigned)n); nlh = NLMSG_NEXT(nlh, n))
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
                       const struct schema_Wifi_VIF_Neighbors *nbors_list,
                       const struct schema_RADIUS *radius_list,
                       size_t num_cconf,
                       size_t num_nbors_list,
                       size_t num_radius_list,
                       const char *bssid)
{
    struct hapd *hapd = hapd_lookup(vconf->if_name);
    struct wpas *wpas = wpas_lookup(vconf->if_name);

    if (WARN_ON(hapd && wpas))
        return;

    if (hapd) {
        struct schema_Wifi_VIF_Config tmp_vconf;

        /* The driver doesn't really care but this is
         * necessary to make hostapd work with dfs channels
         * and dfs offload on broadcom wl/dhd.
         */
        STRSCPY_WARN(hapd->country, "00");

        memcpy(&tmp_vconf, vconf, sizeof(tmp_vconf));
        if (tmp_vconf.rrm) {
            /* Disable hostapd rrm_neighbor_report, let driver handle Neighbor
             * Request. Otherwise device will send two inconsistent Neighbor
             * Reports on each Neighbor Request (one sent by hostapd and
             * second by driver).
             */
            tmp_vconf.rrm = 0;
        }

        WARN_ON(hapd_conf_gen2(hapd, rconf, &tmp_vconf, nbors_list, radius_list,
                               num_nbors_list, num_radius_list, bssid) < 0);
        WARN_ON(hapd_conf_apply(hapd) < 0);
    }

    if (wpas) {
        WARN_ON(wpas_conf_gen(wpas, rconf, vconf, cconf, num_cconf) < 0);
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

void
bcmwl_hostap_nbors_get(const char *bss,
                       struct schema_Wifi_VIF_Neighbors *nbors_list,
                       int max_nbors_num,
                       int *num_nbors_list)
{
    struct hapd *hapd = hapd_lookup(bss);
    if (WARN_ON(!hapd))
        return;
    hapd_lookup_nbors(hapd, nbors_list, max_nbors_num, num_nbors_list);
}

void
bcmwl_hostap_radius_get(const char *bss,
                        struct schema_RADIUS *radius_list,
                        int max_radius_num,
                        int *num_radius_list)
{
    struct hapd *hapd = hapd_lookup(bss);
    if (WARN_ON(!hapd))
        return;
    hapd_lookup_radius(hapd, radius_list, max_radius_num, num_radius_list);
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

bool bcmwl_hostap_dpp_set(const struct schema_DPP_Config **config)
{
    return ctrl_dpp_config(config);
}

void bcmwl_hostap_ctrl_wps_session(const char *bss, int wps, int wps_pbc)
{
    struct hapd *hapd = hapd_lookup(bss);

    if (!hapd || !wps)
        return;

    if (WARN_ON(hapd_wps_cancel(hapd) != 0))
        return;

    if (!wps_pbc)
        return;

    if (WARN_ON(hapd_wps_activate(hapd) != 0))
        return;
}

void bcmwl_hostap_reset_wps_pbc(const char* ifname)
{
    struct schema_Wifi_VIF_Config vconf;
    const char *phy;
    int r;
    int v;

    if (bcmwl_ops.op_vconf == NULL)
        return;

    if (WARN_ON(!bcmwl_parse_vap(ifname, &r, &v)))
        return;

    phy = strfmta("wl%d", r);
    memset(&vconf, 0, sizeof(vconf));
    vconf._partial_update = true;
    SCHEMA_SET_STR(vconf.if_name, ifname);
    SCHEMA_UNSET_FIELD(vconf.wps_pbc);

    bcmwl_ops.op_vconf(&vconf, phy);
}
