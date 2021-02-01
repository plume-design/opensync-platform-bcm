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
#include <arpa/inet.h>
#include <sys/types.h>
#include <dirent.h>

#include "target.h"
#include "log.h"
#include "schema.h"
#include "os_nif.h"
#include "evx_debounce_call.h"
#include "kconfig.h"

#include "bcmwl.h"
#include "bcmwl_nvram.h"
#include "bcmwl_roam.h"
#include "bcmwl_nas.h"
#include "bcmwl_debounce.h"
#include "bcmwl_wps.h"
#include "bcmwl_hostap.h"
#include "bcmwl_event.h"
#include "bcmwl_acl.h"
#include "bcmwl_ioctl.h"

/**
 * Private
 */

#define BCMWL_VAP_PREALLOC_MAX 8 /* drv hard limit is 16, leave some for wds */

// some platforms use "wl1.1", some "wl1_1"
// vif index 0 is just "wl1" not "wl1.0"
bool bcmwl_parse_vap(const char *ifname, int *ri, int *vi)
{
    int ret;
    int si;
    ret = sscanf(ifname, "wl%d"CONFIG_BCMWL_VAP_DELIMITER"%d", ri, vi);
    if (ret == 2) {
        return true;
    }
    if (ret == 1) {
        *vi = 0;
        return true;
    }
    ret = sscanf(ifname, "wds%d"CONFIG_BCMWL_VAP_DELIMITER"%d"CONFIG_BCMWL_VAP_DELIMITER"%d", ri, vi, &si);
    if (ret == 3) {
        return true;
    }
    *ri = *vi = 0;
    return false;
}

static char *
bcmwl_vap_ssid_decode(char *ssid)
{
    char *l, *r;
    ssid++; /* remove heading " */
    if (strlen(ssid) == 0)
        return NULL;
    ssid[strlen(ssid) - 1] = 0; /* remove trailing " */
    for (l = r = ssid; *r; ) {
        switch (*r) {
            case '\\':
                switch (*++r) {
                    case '\\': *l++ = *r++; break;
                    case 'x': sscanf(++r, "%02hhx", l++); r += 2; break;
                    default: return NULL;
                }
                break;
            default: *l++ = *r++; break;
        }
    }
    *l = 0;
    return ssid;
}

/**
 * Public
 */

void
bcmwl_vap_get_status(const char *ifname, struct wl_status *status)
{
    static const char *bssid_zero = "00:00:00:00:00:00";
    static const char *ssid_prefix = "Current SSID: ";
    char *p, *i;
    int isap;

    memset(status, 0, sizeof(*status));

    /* FIXME: This differentiation needs to
     * eventually go away. Wrapping the "rssi"
     * into a fastpath iovar is tricky and not
     * worth the trobule so this just avoids going
     * over the "rssi" call.
     */
    if (kconfig_enabled(CONFIG_BCM_PREFER_IOV)) {
        if (!bcmwl_GIOV(ifname, "ap", NULL, &isap))
            return;

        status->is_sta = isap ? false : true;
    } else {
        /* Earlier drivers would report Bad Argument for APs.
         * However new drivers report 96 regardless if BSS
         * is up or down. STA will almost never, in practice,
         * reach RSSI (SNR really) readout of 96.
         *
         * FIXME: Perhaps rely on `iw`, but not
         * sure if 941789 exhibits the same logic.
         */
        if ((p = WL(ifname, "rssi")) &&
            !strstr(p, "Bad Argument") &&
            atoi(p) != 96) {
            status->is_sta = 1;
            status->rssi = atoi(p);
        }
    }

    if ((p = WL(ifname, "bss"))) {
        if (!strcmp(p, "up"))
            status->is_up = true;

        if (status->is_up) {
            if ((p = WL(ifname, "chanspec")))
                bcmwl_radio_chanspec_extract(p,
                                             &status->channel,
                                             &status->width_mhz);
        }

        if ((p = WL(ifname, "ssid")) && strstr(p, ssid_prefix) == p)
            if (!WARN_ON(!(p = bcmwl_vap_ssid_decode(p + strlen(ssid_prefix)))))
                STRSCPY(status->ssid, p);

        if ((p = WL(ifname, "bssid")) && strcasecmp(p, bssid_zero))
            STRSCPY(status->bssid, str_tolower(p));

        if (status->is_sta && strlen(status->bssid))
            if ((p = WL(ifname, "autho_sta_list")))
                while ((i = strsep(&p, " \r\n")))
                    if (!strcasecmp(i, status->bssid))
                        status->is_authorized = true;

        if (status->is_sta)
            if ((p = NVG(ifname, "ssid")))
                STRSCPY(status->ssid, p);
    }

    LOGD("%s: ssid='%s' bssid='%s' rssi=%d channel=%d/%d is_sta=%d is_auth=%d",
         ifname,
         status->ssid,
         status->bssid,
         status->rssi,
         status->channel,
         status->width_mhz,
         status->is_sta,
         status->is_authorized);
}

bool bcmwl_restart_userspace(void)
{
    bcmwl_nas_reload_full();
    bcmwl_wps_restart();
    return true;
}

bool bcmwl_vap_ready(const char *ifname)
{
    bool exists = false;
    bool running = false;

    os_nif_exists((char *)ifname, &exists);
    if (exists)
        os_nif_is_running((char *)ifname, &running);

    return (exists && running);
}

static const char *bcmwl_vap_map_int2str(int map)
{
    switch (map) {
        case 0: return "none";
        case 1: return "fronthaul_bss";
        case 2: return "backhaul_bss";
        case 3: return "fronthaul_backhaul_bss";
        case 4: return "backhaul_sta";
        default: LOGW("unknown map value: %d", map); break;
    }
    return "none";
}

bool
bcmwl_vap_state(const char *ifname,
                struct schema_Wifi_VIF_State *vstate)
{
    struct wl_status status;
    char *p, *mac;
    int i, j;

    TRACE("%s", ifname ?: "");

    if (WARN_ON(!ifname || !*ifname))
        return false;

    memset(vstate, 0, sizeof(*vstate));
    schema_Wifi_VIF_State_mark_all_present(vstate);
    vstate->associated_clients_present = false;
    vstate->vif_config_present = false;
    vstate->_partial_update = true;

    bcmwl_vap_get_status(ifname, &status);

    SCHEMA_SET_STR(vstate->if_name, ifname);
    SCHEMA_SET_STR(vstate->mode, status.is_sta ? "sta" : "ap");
    WARN_ON(!bcmwl_nas_get_security(ifname, vstate));
    bcmwl_hostap_bss_get(ifname, vstate);

    if (status.is_sta) {
        if ((p = NVG(ifname, "plume_bss_enabled")))
            SCHEMA_SET_INT(vstate->enabled, atoi(p) == 1);
        if ((p = WL(ifname, "bss")) && !strcmp(p, "up"))
            SCHEMA_SET_INT(vstate->enabled, 1);
    } else {
        if ((p = WL(ifname, "bss")))
            SCHEMA_SET_INT(vstate->enabled, !strcmp(p, "up"));
    }
    if (!vstate->ssid_exists && strlen(status.ssid))
        SCHEMA_SET_STR(vstate->ssid, status.ssid);
    if (!vstate->parent_exists && status.is_sta)
        SCHEMA_SET_STR(vstate->parent, (bcmwl_roam_get_status(ifname) == BCMWL_ROAM_COMPLETE
                                        ? status.bssid
                                        : ""));
    if (!vstate->channel_exists && status.channel)
        SCHEMA_SET_INT(vstate->channel, status.channel);
    if ((p = WL(ifname, "cur_etheraddr")) && WL_VAL(p))
        SCHEMA_SET_STR(vstate->mac, str_tolower(p));
    if ((bcmwl_radio_is_dhd(ifname)
         ? (p = DHD(ifname, "ap_isolate"))
         : (p = WL(ifname, "ap_isolate"))) &&
        (i = (atoi(p) == 0 ? 1 :
              atoi(p) == 1 ? 0 :
              -1)) >= 0)
        SCHEMA_SET_INT(vstate->ap_bridge, i);
    if ((p = WL(ifname, "closednet")))
        SCHEMA_SET_STR(vstate->ssid_broadcast,
                       atoi(p) == 0 ? "enabled" :
                       atoi(p) == 1 ? "disabled" :
                       strfmta("unknown=%s", p));
    if ((p = WL(ifname, "dynbcn")))
        SCHEMA_SET_INT(vstate->dynamic_beacon, atoi(p));

    if ((bcmwl_radio_is_dhd(ifname))
        ? (p = DHD(ifname, "wmf_bss_enable"))
        : (p = WL(ifname, "wmf_bss_enable")))
        SCHEMA_SET_INT(vstate->mcast2ucast, atoi(p));

    if (bcmwl_acl_is_synced(ifname)) {
        if ((p = BCMWL_ACL_POLICY_GET(ifname, BCMWL_ACL_WM)) && strlen(p) > 0)
            SCHEMA_SET_STR(vstate->mac_list_type,
                           atoi(p) == 0 ? "none" :
                           atoi(p) == 1 ? "blacklist" :
                           atoi(p) == 2 ? "whitelist" :
                           strfmta("unknown=%s", p));
        if ((p = BCMWL_ACL_GET(ifname, BCMWL_ACL_WM)))
            while ((mac = strsep(&p, " ")))
                if (strlen(mac))
                    SCHEMA_VAL_APPEND(vstate->mac_list, str_tolower(mac));
    }
    if ((p = NVG(ifname, "plume_min_hw_mode")) && strlen(p))
        SCHEMA_SET_STR(vstate->min_hw_mode, p);
    if ((p = WL(ifname, "wme_apsd")))
        SCHEMA_SET_INT(vstate->uapsd_enable, atoi(p));
    if ((p = WL(ifname, "wds_type")))
        SCHEMA_SET_INT(vstate->wds, !!atoi(p));
    if (bcmwl_parse_vap(ifname, &i, &j))
        SCHEMA_SET_INT(vstate->vif_radio_idx, j);
    if ((p = WL(ifname, "fbt")))
        SCHEMA_SET_INT(vstate->ft_psk, atoi(p));
    if ((p = WL(ifname, "rrm")))
        if ((p = strsep(&p, " :")))
            SCHEMA_SET_INT(vstate->rrm, ((strtol(p, NULL, 16) & BCMWL_RRM) == BCMWL_RRM) ? 1 : 0);
    if ((p = WL(ifname, "wnm")))
        if ((p = strsep(&p, " :")))
            SCHEMA_SET_INT(vstate->btm, strtol(p, NULL, 16) & 1);
    if ((p = WL(ifname, "map")))
        if ((p = strsep(&p, ":")))
            SCHEMA_SET_STR(vstate->multi_ap,
                           bcmwl_vap_map_int2str(strtol(p, NULL, 16)));
    if ((p = WL(ifname, "wds_remote_mac"))) {
        SCHEMA_SET_STR(vstate->mode, "ap_vlan");
        SCHEMA_SET_STR(vstate->ap_vlan_sta_addr, str_tolower(p));
    }

    /* FIXME
     *  - min_hw_mode
     */

    return true;
}

void bcmwl_vap_state_report(const char *ifname)
{
    struct schema_Wifi_VIF_State vstate;
    const char *phy;
    int r;
    int v;

    if (!bcmwl_ops.op_vstate)
        return;
    if (WARN_ON(!bcmwl_parse_vap(ifname, &r, &v)))
        return;
    phy = strfmta("wl%d", r);
    LOGD("vif: %s@%s: updating", ifname, phy);
    if (bcmwl_vap_state(ifname, &vstate))
        bcmwl_ops.op_vstate(&vstate, phy);
}

bool bcmwl_vap_is_sta(const char *ifname)
{
    /* I'm told only primary bss can be used for STA */
    int apsta = atoi(WL(ifname, "apsta") ?: "0");
    bool is_primary = strstr(ifname, CONFIG_BCMWL_VAP_DELIMITER) ? false : true;
    return apsta && is_primary;
}

void bcmwl_vap_mac_xfrm(char *addr, int idx, int max)
{
    if (!idx)
        return;

    /* Driver validates mac addresses by checking
     * if the addr[5] complies with a bssmax-based
     * mask. This is a hardware requirement and is
     * referred to as ucidx (uCode index).
     *
     * Upon first multi-bss interface config it
     * derives a base for all these virtual macs.
     *
     * Original wlconf formula would end up with
     * mac addresses clashes either within a
     * single device between phys or between two
     * devices provisioned one after another.
     *
     * To avoid these clashes the original bits
     * that are dedicated for ucidx mask are all
     * moved as upper 6 bits of addr[0]. The
     * original addr[6] upper bits are lost.
     *
     * This maintains uniqueness across our
     * devices and allows for up to 63 interfaces
     * which is more than enough.
     */
    WARN_ON(max >= 64);
    addr[0] = ((addr[5] & (max - 1)) << 2) | 0x2;
    addr[5] = (addr[5] & ~(max - 1))
            | ((max - 1) & (addr[5] + idx));
}

static bool bcmwl_vap_prealloc_one(const char *phy, int idx, void (*mac_xfrm)(char *addr, int idx, int max))
{
    const char *vif = STRFMTA_VIF(phy, idx);
    char *mac;
    char *perm;
    char addr[6];
    int max;
    int phys;

    if (WARN_ON(!mac_xfrm))
        return false;
    if (access(strfmta("/sys/class/net/%s", vif), X_OK) == 0)
        return true;
    if (WARN_ON(!WL(phy, "down")))
        return false;
    if (WARN_ON(!(perm = WL(phy, "perm_etheraddr")) || !WL_VAL(perm)))
        return false;
    if (WARN_ON(!(mac = strexa("cat", strfmta("/sys/class/net/%s/address", phy)))))
        return false;
    if (strcasecmp(mac, perm))
        LOGI("%s: perm_etheraddr not properly set!", phy);
    if (WARN_ON(sscanf(mac, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                       &addr[0], &addr[1], &addr[2], &addr[3], &addr[4], &addr[5]) != 6))
        return false;
    if (WARN_ON((max = bcmwl_radio_max_vifs(phy)) < 1))
        return false;
    if (WARN_ON((phys = bcmwl_radio_count()) < 1))
        return false;
    LOGD("%s: supports up to %d vifs for %d radios", phy, max, phys);
    if (phys > max) {
        LOGE("%s: number of radios(%d) exceeds max bss(%d). "
             "mac addresses will overlap. "
             "cowardly refusing to continue. ",
             phy, phys, max);
        return false;
    }
    if (WARN_ON(idx > max))
        return false;
    mac_xfrm(addr, idx, max);
    mac = strfmta("%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                  addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    LOGI("%s: creating interface with mac %s", vif, mac);
    if (WARN_ON(!WL(phy, "ssid", "-C", strfmta("%d", idx), "")))
        return false;
    if (WARN_ON(!WL(vif, "ap", "1")))
        return false;
    if (WARN_ON(!WL(vif, "cur_etheraddr", mac)))
        return false;
    if (WARN_ON(!strexa("ip", "link", "set", "dev", vif, "addr", mac)))
        return false;

    WARN_ON(!(NVS(vif, "hwaddr", mac)));

    /* This is intended to init bss inside the driver
     * slightly. It seems newer driver, or at least impl55,
     * errors out on `fbt` iovar readout unless bss was up
     * at least once. This actually works even if radio is
     * down and `bss up` itself seems to fail.
     */
    WL(vif, "bss", "up");
    WL(vif, "bss", "down");

    return true;
}

/* FIXME: mac_xfrm() probably should be kept private and
 *        non-configurable by the caller because BCM has a very
 *        specific requirements how non-primary vif mac addresses
 *        should be generated.
 */
bool bcmwl_vap_prealloc(const char *phy, int max_idx, void (*mac_xfrm)(char *addr, int idx, int max))
{
    bool was_up = !strcmp(WL(phy, "isup") ?: "0", "1");
    int i;
    if (strcmp(WL(phy, "mbss") ?: "", "1")) {
        WARN_ON(!WL(phy, "down"));
        WARN_ON(!WL(phy, "mbss", "1"));
    }
    WARN_ON(max_idx < 1);
    for (i = 1; i <= max_idx; i++)
        if (WARN_ON(!bcmwl_vap_prealloc_one(phy, i, mac_xfrm)))
            return false;
    if (was_up)
        WARN_ON(!WL(phy, "up"));
    return true;
}

void bcmwl_vap_prealloc_all(void)
{
    struct dirent *p;
    int bssmax;
    DIR *d;

    if (WARN_ON(!(d = opendir("/sys/class/net"))))
        return;

    while ((p = readdir(d))) {
        if (bcmwl_is_phy(p->d_name)) {
            bssmax = bcmwl_radio_max_vifs(p->d_name);
            if (bssmax > BCMWL_VAP_PREALLOC_MAX)
                bssmax = BCMWL_VAP_PREALLOC_MAX;
            bcmwl_vap_prealloc(p->d_name, bssmax - 1, bcmwl_vap_mac_xfrm);
        }
    }

    closedir(d);
}

bool bcmwl_vap_update_acl(const struct schema_Wifi_VIF_Config *vconf,
                          const struct schema_Wifi_Radio_Config *rconf,
                          const struct schema_Wifi_VIF_Config_flags *vchanged)
{
    const char *vif = vconf->if_name;
    enum bcmwl_acl_policy policy;
    char *macs = strdupa("");
    int i;

    policy = !strcmp(vconf->mac_list_type, "none") ?  BCMWL_ACL_NONE :
             !strcmp(vconf->mac_list_type, "blacklist") ? BCMWL_ACL_DENY :
             !strcmp(vconf->mac_list_type, "whitelist") ? BCMWL_ACL_ALLOW :
             BCMWL_ACL_NONE;

    for (i = 0; i < vconf->mac_list_len; i++)
        macs = strfmta("%s %s", vconf->mac_list[i], macs);

    if (WARN_ON(!BCMWL_ACL_POLICY_SET(vif, BCMWL_ACL_WM, policy)))
        return false;
    if (WARN_ON(!BCMWL_ACL_SET(vif, BCMWL_ACL_WM, strchomp(macs, " "))))
        return false;
    if (WARN_ON(!bcmwl_acl_commit(vif)))
        return false;

    return true;
}

static bool bcmwl_vap_update_uapsd(const struct schema_Wifi_VIF_Config *vconf,
                                   const struct schema_Wifi_Radio_Config *rconf,
                                   const struct schema_Wifi_VIF_Config_flags *vchanged)
{
    const char *vif = vconf->if_name;
    const char *phy = rconf->if_name;
    bool is_up;
    bool ok;

    /* FIXME: This will likely cause service interruption during
     *        onboarding.
     *
     *        The best we can do is avoid updating wme_apsd if it's
     *        already in desired state and then make sure target glue
     *        preps pre-allocated interfaces into a "most likely"
     *        state beforehand.
     */
    if (atoi(WL(vif, "wme_apsd") ?: "-1") == vconf->uapsd_enable)
        return true;

    is_up = !strcmp(WL(phy, "isup") ?: "0", "1");
    if (is_up)
        if (WARN_ON(!WL(vif, "down")))
            return false;
    WARN_ON(!(ok = WL(vif, "wme_apsd", strfmta("%d", vconf->uapsd_enable))));
    if (is_up)
        if (WARN_ON(!WL(vif, "up")))
            return false;
    return ok;
}

static bool bcmwl_vap_has_correct_mode(const char *ifname, const char *mode)
{
    bool is_sta = !strcmp(mode, "sta");
    if (is_sta && strcmp("1", WL(ifname, "apsta")))
        return false;
    if (is_sta != bcmwl_vap_is_sta(ifname))
        return false;
    return true;
}

static void bcmwl_vap_update_rrm(const struct schema_Wifi_Radio_Config *rconf,
                                 const struct schema_Wifi_VIF_Config *vconf)
{
    const char *disable = strfmta("-%d", BCMWL_RRM);
    const char *enable = strfmta("+%d", BCMWL_RRM);
    const char *vif = vconf->if_name;
    const char *phy = rconf->if_name;
    const char *word;
    char *line;
    int was_up;
    int rrm;

    /* E.g. output of wlctl: `0x1  Link_Measurement` */

    if (WARN_ON(!vconf->rrm_exists))
        return;
    if (WARN_ON(!(line = WL(vif, "rrm"))))
        return;
    if (WARN_ON(!(word = strsep(&line, "\t "))))
        return;
    rrm = strtol(word, NULL, 16);
    rrm = (rrm & BCMWL_RRM) ? 1 : 0;

    if (rrm == vconf->rrm)
        return;

    was_up = atoi(WL(phy, "isup") ?: "0");
    if (was_up)
        WARN_ON(!WL(phy, "down"));

    WARN_ON(!WL(vif, "rrm", vconf->rrm ? enable : disable));

    if (was_up)
        WARN_ON(!WL(phy, "up"));
}

/* FIXME: The following is intended to deprecate and
 * eventually replace bcmwl_vap_update().
 */
bool bcmwl_vap_update2(const struct schema_Wifi_VIF_Config *vconf,
                       const struct schema_Wifi_Radio_Config *rconf,
                       const struct schema_Wifi_Credential_Config *cconfs,
                       const struct schema_Wifi_VIF_Config_flags *vchanged,
                       int num_cconfs)
{
    const char *vif = vconf->if_name;
    const char *phy = rconf->if_name;
    struct wlc_ssid ssid = {0};
    char *p;
    bool skip_map = false;
    int i, j;

    TRACE("%s, %s", phy ?: "", vif ?: "");

    if (WARN_ON(!phy || !*phy))
        return false;
    if (WARN_ON(!vif || !*vif))
        return false;

    /* FIXME:
     *  - register for netlink events and keep track of
     *    interface up/down states and warn if NM tries to
     *    mess up with us
     */

    if (vchanged->enabled || vchanged->mode) {
        WARN_ON(!NVS(vif, "plume_bss_enabled", vconf->enabled ? "1" : "0"));
        WARN_ON(!WL(vif, "bss", "down"));

        /* Start/stop background CAC */
        bcmwl_dfs_bgcac_recalc(phy);

        if (!vconf->enabled) {
            bcmwl_hostap_bss_apply(vconf, rconf, cconfs, vchanged, num_cconfs);
            goto report;
        }

        if (!bcmwl_vap_has_correct_mode(vif, vconf->mode)) {
            LOGI("%s: must down radio set mode", vif);
            WARN_ON(!WL(vif, "down"));
            /* WAR: Some drivers think they're running AP
             * interface even if they aren't and ignore
             * re-setting the same "ap" or "apsta" iovar.
             * This makes sure for the iovar to work.
             */
            WL(vif, "ap", "0");
            WARN_ON(!WL(vif, !strcmp(vconf->mode, "ap") ? "ap" :
                             !strcmp(vconf->mode, "sta") ? "apsta" :
                             "ap", "1"));
            WARN_ON(!WL(vif, "up"));
        }

        if (!strcmp(vconf->mode, "sta")) {
            /* By default driver roams autonomously to once
             * configured ssid. This is undesired because
             * there's no way to explicitly tell it to do
             * that on a given channel, or to a given bssid.
             *
             * The following prevents it from doing all that
             * and instead waits for either `wl join` or
             * wpa_supplicant.
             */
            WARN_ON(!WL(vif, "assoc_retry_max", "6"));
            WARN_ON(!WL(vif, "sta_retry_time", "0"));
            WARN_ON(!WL(vif, "roam_off", "1"));
        }

        WARN_ON(!strexa("ip", "link", "set", vif, "up"));
        /* dhd datapath doesn't work unless phy netdev is also up */
        WARN_ON(!strexa("ip", "link", "set", phy, "up"));
    }

    if (vchanged->vif_radio_idx) {
        /* WAR
         *
         * Creating and destroying interfaces in bcm wl is
         * buggy. Moreover dynamic mac address adjustments
         * are cumbersome or intrusive (require radio to be
         * downed).
         *
         * Therefore interfaces are expected to be
         * pre-created. Just make sure it has all expected
         * parameters.
         */
        if (!bcmwl_parse_vap(vif, &i, &j))
            j = 0;
        if (vconf->vif_radio_idx_exists)
            if (WARN_ON(vconf->vif_radio_idx != j))
                return false;
            // FIXME: verify if macaddr is also as expected
    }

    if (vchanged->security ||
        vchanged->ssid ||
        vchanged->bridge ||
        vchanged->group_rekey ||
        vchanged->ft_psk ||
        vchanged->ft_mobility_domain)
        WARN_ON(!bcmwl_nas_update_security(vconf, rconf, cconfs, vchanged, num_cconfs));

    if (vchanged->ssid_broadcast)
        WARN_ON(!WL(vif, "closednet",
                    !strcmp(vconf->ssid_broadcast, "enabled") ? "0" :
                    !strcmp(vconf->ssid_broadcast, "disabled") ? "1" :
                    "0")); // FIXME: WARN_ON

    if (vchanged->dynamic_beacon)
        WARN_ON(!WL(vif, "dynbcn", vconf->dynamic_beacon ? "1" : "0"));

    if (vchanged->mcast2ucast) {
        if (bcmwl_radio_is_dhd(vif))
            WARN_ON(!DHD(vif, "wmf_bss_enable", vconf->mcast2ucast ? "1" : "0"));
        else
            WARN_ON(!WL(vif, "wmf_bss_enable", vconf->mcast2ucast ? "1" : "0"));
    }

    if (vchanged->ap_bridge) {
        if (bcmwl_radio_is_dhd(vif))
            WARN_ON(!DHD(vif, "ap_isolate", vconf->ap_bridge ? "0" : "1"));
        else
            WARN_ON(!WL(vif, "ap_isolate", vconf->ap_bridge ? "0" : "1"));
    }

    if (vchanged->mac_list_type || vchanged->mac_list)
        WARN_ON(!bcmwl_vap_update_acl(vconf, rconf, vchanged));

    if (vchanged->uapsd_enable)
        WARN_ON(!bcmwl_vap_update_uapsd(vconf, rconf, vchanged));

    if (vchanged->ssid && !strcmp(vconf->mode, "ap")) {
        ssid.SSID_len = strlen(vconf->ssid);
        if (WARN_ON(ssid.SSID_len > sizeof(ssid.SSID)))
            ssid.SSID_len = sizeof(ssid.SSID);
        memcpy(ssid.SSID, vconf->ssid, ssid.SSID_len);
        WARN_ON(!bcmwl_SIOC(vif, WLC_SET_SSID, &ssid));
    }

    if (vchanged->enabled || vchanged->mode) {
        if (!strcmp(vconf->mode, "ap")) {
            if (rconf->channel_exists && rconf->ht_mode_exists)
                WARN_ON(!bcmwl_radio_channel_set(phy, rconf->channel, rconf->ht_mode));
            WARN_ON(!WL(vif, "bss", "up"));
        }
    }

    if (vchanged->btm)
        WARN_ON(!WL(vif, "wnm", vconf->btm ? "+1" : "-1"));

    if (vchanged->rrm)
        bcmwl_vap_update_rrm(rconf, vconf);

    /* Due to intricacies of WM in its current state (it
     * pre-creates VIF_State for VIF_Config with empty
     * columns to avoid some corner cases) it'll often mark
     * multi_ap as changed, even though it isn't.  This has
     * a nasty side effect of pulling down phy and losing
     * ISM states. This in turn can lead to races and other
     * bugs. As such prevent that for good measure.
     */
    if ((p = WL(vif, "map")) && (p = strsep(&p, ":"))) {
        const char *str = bcmwl_vap_map_int2str(strtol(p, NULL, 16));
        if (strcmp(str, vconf->multi_ap) == 0) {
            LOGI("%s: skipping multi-ap reconfig to avoid hiccups", vif);
            skip_map = true;
        }
    }

    if (vchanged->multi_ap && !skip_map) {
        WL(phy, "down");
        WARN_ON(!WL(vif, "map",
                    !strcmp(vconf->multi_ap, "none") ? "0" :
                    !strcmp(vconf->multi_ap, "fronthaul_bss") ? "1" :
                    !strcmp(vconf->multi_ap, "backhaul_bss") ? "2" :
                    !strcmp(vconf->multi_ap, "fronthaul_backhaul_bss") ? "3" :
                    !strcmp(vconf->multi_ap, "backhaul_sta") ? "4" :
                    "0"));
        if (rconf->enabled)
            WL(phy, "up");
    }

    if (!strcmp(vconf->mode, "sta"))
        bcmwl_roam_init(vif, vconf->parent);

    NVS(vif, "plume_min_hw_mode", vconf->min_hw_mode_exists
                                  ? vconf->min_hw_mode
                                  : NULL);

    bcmwl_hostap_bss_apply(vconf, rconf, cconfs, vchanged, num_cconfs);
    bcmwl_roam_later(vconf->if_name);

report:
    evx_debounce_call(bcmwl_vap_state_report, vconf->if_name);
    evx_debounce_call(bcmwl_radio_state_report, rconf->if_name);
    return true;
}
