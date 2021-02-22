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
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <glob.h>

/* internal */
#include <os_proc.h>
#include <evx.h>
#include <evx_debounce_call.h>
#include <target.h>
#include <log.h>
#include <bcmwl.h>
#include <bcmwl_nvram.h>
#include <bcmwl_wps.h>
#include <bcmwl_lan.h>
#include <bcmwl_priv.h>
#include <bcmwl_nas.h>

/* local */
struct ev_timer g_bcmwl_nas_supervise_timer;
struct ev_signal g_bcmwl_nas_sigusr1;

#define BCMWL_NAS_SUPERVISE_INTERVAL_SEC 30
#define BCMWL_NAS_SUPERVISE_FIRST_DELAY_SEC 30

static void bcmwl_nas_sigusr1(struct ev_loop *loop, ev_signal *s, int revent)
{
    LOGI("nas: fast reload completed");
}

static bool bcmwl_nas_multipsk_is_supported(void)
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

int bcmwl_system_start_closefd(const char *command)
{
    int res = 0;
    int ret;

    pid_t pid = fork();
    if (pid < 0) {
        LOGW("Error starting %s (fork)", command);
        return -1;
    }

    if (pid > 0) {
        do {
            ret = waitpid(pid, &res, 0);
            // restart call if interrupted by signal
        } while (ret == -1 && errno == EINTR);
        if (res != 0)
            LOGE("Error starting %s (%d)", command, res);
        return res;
    }

    // need to close all open fds otherwise the fd can be kept open by the
    // child process and that can cause hangs in other processes in case
    // the fd is a pipe or a lock
    int fd;
    for (fd = 0; fd < sysconf(_SC_OPEN_MAX); fd++)
        close(fd);

    // re-open local standard FDs
    open("/dev/null", O_RDONLY); // 0: stdin
    open("/dev/null", O_WRONLY); // 1: stdout
    open("/dev/null", O_WRONLY); // 2: stderr

    res = system(command);

    exit(res);
}

void bcmwl_nas_reload_full(void)
{
    struct dirent *p;
    DIR *d;

    LOGN("reloading auth");

    // kill eapd + nas
    strexa("killall", "-KILL", "eapd", "nas");

    // short delay to allow nas/eapd cleanup
    // before a new instance is started
    sleep(1);

    /* Can't use strexa() or a naive fork+exec-waitpid
     * because nas/eapd are not properly closing their
     * descriptors so they would hang indefinitely.
     */

    // start nas + eapd
    bcmwl_system_start_closefd("nas");
    bcmwl_system_start_closefd("eapd");

    bcmwl_wps_restart();

    if (!(d = opendir("/sys/class/net")))
        return;

    while ((p = readdir(d)))
        if (strstr(p->d_name, "wl") == p->d_name)
            if (!bcmwl_vap_is_sta(p->d_name))
                WL(p->d_name, "deauthenticate", "ff:ff:ff:ff:ff:ff");
    closedir(d);
}

static void bcmwl_nas_reload(const char *arg)
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
    if (bcmwl_wps_enabled() && bcmwl_wps_configured())
        err |= bcmwl_nas_supervise(bcmwl_wps_process_name());
    if (err) {
        LOGI("supervise: restarting services because something crashed");
        bcmwl_nas_reload_full();
    }
}

void bcmwl_nas_init(void)
{
    assert(strexa("which", "eapd"));
    assert(strexa("which", "nas"));
    ev_timer_init(&g_bcmwl_nas_supervise_timer,
                  bcmwl_nas_supervise_timer,
                  BCMWL_NAS_SUPERVISE_FIRST_DELAY_SEC,
                  BCMWL_NAS_SUPERVISE_INTERVAL_SEC);
    ev_timer_start(EV_DEFAULT_ &g_bcmwl_nas_supervise_timer);
    ev_signal_init(&g_bcmwl_nas_sigusr1, bcmwl_nas_sigusr1, SIGUSR1);
    ev_signal_start(EV_DEFAULT, &g_bcmwl_nas_sigusr1);
    NVS("nas", "fast_reload_notify_pid", strfmta("%d", getpid()));
}

static unsigned short int bcmwl_fletcher16(const char *data, int count)
{
    unsigned short int sum1 = 0;
    unsigned short int sum2 = 0;
    int index;

    for (index = 0; index < count; ++index)
    {
        sum1 = (sum1 + data[index]) % 255;
        sum2 = (sum2 + sum1) % 255;
    }

    return (sum2 << 8) | sum1;
}

static const char* bcmwl_ft_nas_id(void)
{
    return "plumewifi";
}

static int bcmwl_ft_reassoc_deadline_tu(void)
{
    return 5000;
}

static void bcmwl_nas_update_ft_psk(
        const struct schema_Wifi_VIF_Config *vconf,
        const struct schema_Wifi_Radio_Config *rconf,
        const struct schema_Wifi_VIF_Config_flags *vchanged)
{
    const char *vif = vconf->if_name;
    const char *phy = rconf->if_name;
    const char *fbt;
    const char *fbt_mdid;
    unsigned short int mdid;
    bool is_up;

    if (!vchanged->ft_psk &&
        !vchanged->ssid &&
        !vchanged->ft_mobility_domain)
        return;

    if (WARN_ON(!(fbt = WL(vif, "fbt"))))
        return;

    /* When disabled we don't need to check MDID (base on ssid) */
    if (!vconf->ft_psk && atoi(fbt) == vconf->ft_psk)
        return;

    fbt_mdid = WL(vif, "fbt_mdid");
    if (!fbt_mdid)
        fbt_mdid = "";

    if (vconf->ft_mobility_domain_exists)
        mdid = htons(vconf->ft_mobility_domain);
    else
        mdid = htons(bcmwl_fletcher16(vconf->ssid, strlen(vconf->ssid)));

    if (atoi(fbt) == vconf->ft_psk && atoi(fbt_mdid) == mdid)
        return;

    is_up = !strcmp(WL(phy, "isup") ?: "0", "1");
    if (is_up) {
        LOGI("%s@%s: pulling radio down to reconfigure ft psk", vif, phy);
        if (WARN_ON(!WL(vif, "down")))
            return;
    }

    WARN_ON(!WL(vif, "fbt", strfmta("%d", vconf->ft_psk)));
    WARN_ON(!WL(vif, "fbt_ap", strfmta("%d", vconf->ft_psk)));
    WARN_ON(!WL(vif, "fbt_mdid", strfmta("%d", mdid)));
    WARN_ON(!WL(vif, "fbtoverds", "0"));
    WARN_ON(!WL(vif, "fbt_reassoc_time", strfmta("%d", bcmwl_ft_reassoc_deadline_tu())));
    WARN_ON(!WL(vif, "fbt_r0kh_id", bcmwl_ft_nas_id()));

    if (is_up) {
        LOGI("%s@%s: pulling radio up after reconfigure ft psk", vif, phy);
        if (WARN_ON(!WL(vif, "up")))
            return;
    }
}

static void bcmwl_nas_update_security_multipsk(
        const struct schema_Wifi_VIF_Config *vconf,
        int *changed)
{
    const char *vif = vconf->if_name;
    const char *keysumold;
    const char *keysum;
    const char *oftag;
    const char *keyid;
    const char *key;
    int keynum;
    int i;

    for (keynum = 0, keysumold = "";; keynum++) {
        key = NVG(vif, strfmta("wpa_psk%d", keynum));
        if (!key || !strlen(key))
            break;

        keysumold = strfmta("%s,[%d]=%s", keysumold, keynum, key);
    }

    for (i = 0, keynum = 0, keysum = ""; i < vconf->security_len; i++) {
        if (strstr(vconf->security_keys[i], "key-") != vconf->security_keys[i])
            continue;

        key = vconf->security[i];
        keyid = vconf->security_keys[i];
        oftag = SCHEMA_KEY_VAL(vconf->security, strfmta("oftag-%s", keyid));
        keysumold = strfmta("%s,[%d]=%s", keysumold, keynum, key);
        LOGD("%s: setting wpa_psk %d to '%s' [%s, %s]", vif, keynum, key, keyid, oftag);
        WARN_ON(!NVS(vif, strfmta("wpa_psk%d", keynum), key));
        WARN_ON(!NVS(vif, strfmta("wpa_psk%d_keyid", keynum), keyid));
        WARN_ON(!NVS(vif, strfmta("plume_oftag_%s", keyid), oftag));
        keynum++;
    }

    WARN_ON(!NVU(vif, strfmta("wpa_psk%d", keynum)));

    LOGT("%s: keysum old='%s' new='%s'", vif, keysumold, keysum);
    if (strcmp(keysum, keysumold)) {
        if (!bcmwl_nas_multipsk_is_supported())
            LOGE("%s: cannot configure multi-psk, nas does not support it", vif);
        *changed |= 1;
    }
}

bool bcmwl_nas_update_security(
        const struct schema_Wifi_VIF_Config *vconf,
        const struct schema_Wifi_Radio_Config *rconf,
        const struct schema_Wifi_Credential_Config *cconfs,
        const struct schema_Wifi_VIF_Config_flags *vchanged,
        int num_cconfs)
{
    const char *vif = vconf->if_name;
    const char *crypto = SCHEMA_KEY_VAL(vconf->security, "mode");
    const char *oftag = SCHEMA_KEY_VAL(vconf->security, "oftag");
    const char *akm = SCHEMA_KEY_VAL(vconf->security, "encryption");
    const char *key = SCHEMA_KEY_VAL(vconf->security, "key");
    const char *br = vconf->bridge_exists && strlen(vconf->bridge) ? vconf->bridge : vif;
    const char *nv_akm;
    const char *nv_crypto;
    const char *nv_auth_mode;
    const char *nv_radius_ipaddr;
    const char *nv_radius_port;
    const char *nv_radius_key;
    const char *wl_eap;
    const char *wl_wsec;
    const char *wl_wsec_restrict;
    const char *wl_wpa_auth;
    const char *wl_wpa_auth_prev;
    int wl_crypto;
    int drv_wsec;
    int was_up;
    int full = 0;
    int fast = 0;
    int flag;

    if (!strcmp(crypto, "mixed"))
        crypto = "3";

    WARN_ON(strcmp(akm, "WPA-PSK") &&
            strcmp(akm, "WPA-EAP") &&
            strcmp(akm, "OPEN") &&
            strcmp(akm, ""));

    if (strcmp(akm, "WPA-PSK") == 0) {
        nv_akm = atoi(crypto) == 1 ? "psk" :
                 atoi(crypto) == 2 ? "psk2" :
                 atoi(crypto) == 3 ? "psk psk2" :
                 "psk2";
        nv_crypto = atoi(crypto) == 1 ? "tkip+aes" :
                    atoi(crypto) == 2 ? "aes" :
                    atoi(crypto) == 3 ? "tkip+aes" :
                    "aes";
        nv_auth_mode = "";
        nv_radius_ipaddr = "";
        nv_radius_port = "";
        nv_radius_key = "";
        wl_eap = "1";
        wl_wsec = strfmta("%d", atoi(crypto) == 1 ? TKIP_ENABLED + AES_ENABLED :
                                 atoi(crypto) == 2 ? AES_ENABLED :
                                 atoi(crypto) == 3 ? TKIP_ENABLED + AES_ENABLED :
                                 AES_ENABLED);
        wl_wsec_restrict = "1";
        wl_crypto = atoi(crypto) == 1 ? WPA_AUTH_PSK :
                    atoi(crypto) == 2 ? WPA2_AUTH_PSK :
                    atoi(crypto) == 3 ? WPA_AUTH_PSK | WPA2_AUTH_PSK :
                    WPA2_AUTH_PSK;
    }
    else if (strcmp(akm, "WPA-EAP") == 0) {
        /* WPA-EAP support solely WPA2 */
        nv_akm = "wpa2";
        nv_crypto = "aes";
        nv_auth_mode = "radius";
        nv_radius_ipaddr = SCHEMA_KEY_VAL(vconf->security, "radius_server_ip");
        nv_radius_port = SCHEMA_KEY_VAL(vconf->security, "radius_server_port");
        nv_radius_key = SCHEMA_KEY_VAL(vconf->security, "radius_server_secret");
        wl_eap = "1";
        wl_wsec = strfmta("%d", AES_ENABLED);
        wl_wsec_restrict = "1";
        wl_crypto = WPA2_AUTH_UNSPECIFIED;
    }
    else if (strcmp(akm, "OPEN") == 0) {
        nv_akm = "";
        nv_crypto = "";
        nv_auth_mode = "";
        nv_radius_ipaddr = "";
        nv_radius_port = "";
        nv_radius_key = "";
        wl_eap = "0";
        wl_wsec = "0";
        wl_wsec_restrict = "0";
        wl_crypto = 0;
    }
    else {
        LOGW("%s: AKM '%s' not supported", vif, akm);
        return false;
    }

    /*
     * We have to save bss up/down state here, because
     * bcmwl_nas_update_ft_psk() could run vif down/up
     * which also do bss down and take some time before
     * up again. In some cases, when we change wl_wpa_auth,
     * bss left down all the time and we didn't send
     * beacons.
     */
    was_up = !strcmp(WL(vif, "bss") ?: "", "up");

    if (vconf->ft_psk_exists && vconf->ft_psk) {
        nv_akm = strfmta("%s psk2ft", nv_akm);
        wl_crypto |= WPA2_AUTH_FT;
    }

    wl_wpa_auth = strfmta("0x%02x", wl_crypto);
    wl_wpa_auth_prev = strtok(WL(vif, "wpa_auth") ?: strdupa(""), " ") ?: "";

    drv_wsec = atoi(WL(vif, "wsec") ?: "0");
    drv_wsec &= ~SES_OW_ENABLED; /* wps_monitor adds it outside our control */

    full |= strcmp(strdupafree(bcmwl_lan_search(vif)) ?: "", br)
         |  strcmp(NVG(vif, "mode") ?: "", vconf->mode)
         |  strcmp(NVG(vif, "plume_oftag") ?: "", oftag)
         |  strcmp(NVG(vif, "akm") ?: "", nv_akm)
         |  strcmp(NVG(vif, "crypto") ?: "", nv_crypto)
         |  strcmp(NVG(vif, "auth_mode") ?: "", nv_auth_mode)
         |  strcmp(NVG(vif, "radius_ipaddr") ?: "", nv_radius_ipaddr)
         |  strcmp(NVG(vif, "radius_port") ?: "", nv_radius_port)
         |  strcmp(NVG(vif, "radius_key") ?: "", nv_radius_key)
         |  strcmp(WL(vif, "eap") ?: "", wl_eap)
         |  strcmp(WL(vif, "wsec_restrict") ?: "", wl_wsec_restrict)
         |  (atoi(wl_wpa_auth_prev) != atoi(wl_wpa_auth))
         |  (drv_wsec != atoi(wl_wsec))
         ;
    fast |= strcmp(NVG(vif, "ssid") ?: "", vconf->ssid)
         |  strcmp(NVG(vif, "wpa_psk") ?: "", key)
         |  (atoi(NVG(vif, "wpa_gtk_rekey") ?: "-1") != vconf->group_rekey)
         ;

    WARN_ON(!bcmwl_lan_set(vif, br));
    WARN_ON(!NVS(vif, "ifname", vif));
    WARN_ON(!NVS(vif, "radio", "1"));
    WARN_ON(!NVS(vif, "bss_enabled", "1"));
    WARN_ON(!NVS(vif, "mode", vconf->mode));
    WARN_ON(!NVS(vif, "plume_oftag", strlen(oftag) ? oftag : NULL));
    WARN_ON(!NVS(vif, "akm", nv_akm));
    WARN_ON(!NVS(vif, "crypto", nv_crypto));
    WARN_ON(!NVS(vif, "auth_mode", nv_auth_mode));
    WARN_ON(!NVS(vif, "radius_ipaddr", nv_radius_ipaddr));
    WARN_ON(!NVS(vif, "radius_port", nv_radius_port));
    WARN_ON(!NVS(vif, "radius_key", nv_radius_key));
    WARN_ON(!NVS(vif, "ssid", vconf->ssid));
    WARN_ON(!NVS(vif, "wpa_psk", strlen(key) ? key : NULL));
    WARN_ON(!NVS(vif, "plume_wpa_mode", atoi(crypto) ? "true" : "false"));
    WARN_ON(!NVS(vif, "wpa_gtk_rekey", vconf->group_rekey_exists
                                       ? strfmta("%d", vconf->group_rekey)
                                       : NULL));

    WARN_ON(!WL(vif, "eap", wl_eap));
    WARN_ON(!WL(vif, "wsec", wl_wsec));
    WARN_ON(!WL(vif, "wsec_restrict", wl_wsec_restrict));

    if (strcmp(wl_wpa_auth, wl_wpa_auth_prev)) {
        WARN_ON(!WL(vif, "bss", "down"));
        WARN_ON(!WL(vif, "wpa_auth", wl_wpa_auth));
    }

    bcmwl_nas_update_ft_psk(vconf, rconf, vchanged);
    if (was_up)
        WARN_ON(!WL(vif, "bss", "up"));

    bcmwl_nas_update_security_multipsk(vconf, &fast);

    flag = atoi(NVG("nas", "reload") ?: "0")
         | (full ? (1 << BCMWL_NAS_RELOAD_FULL) : 0)
         | (fast ? (1 << BCMWL_NAS_RELOAD_FAST) : 0)
         ;

    if (flag) {
        LOGI("%s: scheduling auth reload due to %d (full=%d, fast=%d)",
             vif, flag, full, fast);
        WARN_ON(!NVS("nas", "reload", strfmta("%d", flag)));
        evx_debounce_call(bcmwl_nas_reload, NULL);
    }

    return true;
}


bool bcmwl_nas_get_security(
        const char *ifname,
        struct schema_Wifi_VIF_State *vstate)
{
    const char *oftag;
    const char *keyid;
    const char *key;
    char *p;
    int i;

    if ((p = WL(ifname, "wpa_auth")) &&
        (i = (strstr(p, "WPA-PSK") ? 1 : 0) |
             (strstr(p, "WPA2-PSK") ? 2 : 0))) {
        if ((p = NVG(ifname, "wpa_psk"))) {
            SCHEMA_KEY_VAL_APPEND(vstate->security, "encryption", "WPA-PSK");
            SCHEMA_KEY_VAL_APPEND(vstate->security, "key", p);
            /* Do not advertise [mode] unless it was asked in the config.
             * Otherwise WM2 will detect [security] as changed all the time.
             */
            if ((p = NVG(ifname, "plume_wpa_mode")) && !strcmp(p, "true"))
                SCHEMA_KEY_VAL_APPEND(vstate->security, "mode", i == 3 ? "mixed" : strfmta("%d", i));
        }
        if ((oftag = NVG(ifname, "plume_oftag")) && strlen(oftag))
            SCHEMA_KEY_VAL_APPEND(vstate->security, "oftag", oftag);
        for (i = 0;; i++) {
            if (!(key = NVG(ifname, strfmta("wpa_psk%d", i))) || !strlen(key))
                break;
            if (!(keyid = NVG(ifname, strfmta("wpa_psk%d_keyid", i))) || !strlen(keyid))
                break;
            if (!(oftag = NVG(ifname, strfmta("plume_oftag_%s", keyid))) || !strlen(oftag))
                break;

            SCHEMA_KEY_VAL_APPEND(vstate->security, keyid, key);
            SCHEMA_KEY_VAL_APPEND(vstate->security, strfmta("oftag-%s", keyid), oftag);
        }
    } else if ((p = WL(ifname, "wpa_auth")) && strstr(p, "WPA2-802.1x")) {
        SCHEMA_KEY_VAL_APPEND(vstate->security, "encryption", "WPA-EAP");
        if ((p = NVG(ifname, "radius_ipaddr")))
            SCHEMA_KEY_VAL_APPEND(vstate->security, "radius_server_ip", p);
        if ((p = NVG(ifname, "radius_port")))
            SCHEMA_KEY_VAL_APPEND(vstate->security, "radius_server_port", p);
        if ((p = NVG(ifname, "radius_key")))
            SCHEMA_KEY_VAL_APPEND(vstate->security, "radius_server_secret", p);
    } else {
        if ((p = WL(ifname, "wpa_auth")) && strstr(p, "Disabled"))
            SCHEMA_KEY_VAL_APPEND(vstate->security, "encryption", "OPEN");
    }

    if ((p = NVG(ifname, "wpa_gtk_rekey")) && strlen(p))
        SCHEMA_SET_INT(vstate->group_rekey, atoi(p));

    if ((p = bcmwl_lan_search(ifname)) && (p = strdupafree(p)))
        SCHEMA_SET_STR(vstate->bridge, strcmp(ifname, p) ? p : "");

    return true;
}
