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

#include "bcmwl.h"
#include "bcmwl_nvram.h"
#include "bcmwl_lan.h"
#include "bcmwl_roam.h"
#include "bcmwl_nas.h"
#include "bcmwl_debounce.h"
#include "bcmutil.h"
#include "bcmwl_wps.h"
#include "bcmwl_event.h"

/**
 * Data maps
 */

static c_item_t g_map_mac_list_type[] = {
    C_ITEM_STR(0,       "none"),
    C_ITEM_STR(1,       "blacklist"),
    C_ITEM_STR(2,       "whitelist")
};

static c_item_t g_map_ssid_broadcast[] = {
    C_ITEM_STR(0,       "enabled"),
    C_ITEM_STR(1,       "disabled")
};

/**
 * Private
 */

// some platforms use "wl1.1", some "wl1_1"
// vif index 0 is just "wl1" not "wl1.0"
bool bcmwl_parse_vap(const char *ifname, int *ri, int *vi)
{
    int ret;
    ret = sscanf(ifname, "wl%d"CONFIG_BCMWL_VAP_DELIMITER"%d", ri, vi);
    if (ret == 2) {
        return true;
    }
    if (ret == 1) {
        *vi = 0;
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

static unsigned short int
bcmwl_fletcher16(const char *data, int count)
{
    unsigned short int sum1 = 0;
    unsigned short int sum2 = 0;
    int index;

    for( index = 0; index < count; ++index )
    {
       sum1 = (sum1 + data[index]) % 255;
       sum2 = (sum2 + sum1) % 255;
    }

    return (sum2 << 8) | sum1;
}

static const char *
bcmwl_ft_nas_id(void)
{
    return "plumewifi";
}

static int
bcmwl_ft_reassoc_deadline_tu(void)
{
    return 5000;
}

static void bcmwl_vap_update_ft_psk(const struct schema_Wifi_VIF_Config *vconf,
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

/**
 * Public
 */

void
bcmwl_vap_get_status(const char *ifname, struct wl_status *status)
{
    static const char *bssid_zero = "00:00:00:00:00:00";
    static const char *ssid_prefix = "Current SSID: ";
    char *p, *i;

    memset(status, 0, sizeof(*status));

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

int bcmwl_vap_mac_list_type_to_int(const char *mac_list_type)
{
    c_item_t *item;

    if ((item = c_get_item_by_str(g_map_mac_list_type, mac_list_type)))
    {
        return item->key;
    }

    LOGE("Unsupported mac_list_type value: %s!", mac_list_type);
    return 0;
}

const char *bcmwl_vap_mac_list_type_to_str(int mac_list_type)
{
    c_item_t *item;

    if ((item = c_get_item_by_key(g_map_mac_list_type, mac_list_type)))
    {
        return (const char *)item->data;
    }

    LOGE("Unsupported mac_list_type value: %d!", mac_list_type);
    return "none";
}

int bcmwl_vap_ssid_broadcast_to_int(const char *ssid_broadcast)
{
    c_item_t *item;

    if ((item = c_get_item_by_str(g_map_ssid_broadcast, ssid_broadcast)))
    {
        return item->key;
    }

    LOGE("Unsupported ssid_broadcast str value: %s!", ssid_broadcast);
    return 0;
}

const char *bcmwl_vap_ssid_broadcast_to_str(int ssid_broadcast)
{
    c_item_t *item;

    if ((item = c_get_item_by_key(g_map_ssid_broadcast, ssid_broadcast)))
    {
        return (const char *)item->data;
    }

    LOGE("Unsupported ssid_broadcast int value: %d!", ssid_broadcast);
    return "disabled";
}

bool bcmwl_vap_mac_list_foreach(const char *ifname,
                                bcmwl_vap_mac_list_cb_t cb,
                                void *context)
{
    int index;
    FILE *fp;
    char buf[512];
    char cmd[512];
    os_macaddr_t macaddr;

    // Setup pipe
    snprintf(cmd, sizeof(cmd), "wlctl -i %s mac", ifname);
    fp = popen(cmd, "r");
    if (!fp)
    {
        LOGE("Unable to open pipe! :: cmd=%s", cmd);
        return false;
    }

    // Parse output
    for (index=0; fgets(buf, sizeof(buf), fp); index++)
    {
        if (6 == sscanf(buf,
                        "mac %2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
                        &macaddr.addr[0], &macaddr.addr[1], &macaddr.addr[2],
                        &macaddr.addr[3], &macaddr.addr[4], &macaddr.addr[5]))
        {
            // Run user callback
            cb(ifname, &macaddr, index, context);
        }
    }

    pclose(fp);
    return false;
}

bool bcmwl_vap_assoc_list_foreach(const char *ifname,
                                  bcmwl_vap_assoc_list_cb_t cb,
                                  void *context)
{
    int index;
    FILE *fp;
    char buf[512];
    char cmd[512];
    os_macaddr_t macaddr;

    // Setup pipe
    snprintf(cmd, sizeof(cmd), "wlctl -i %s assoclist", ifname);
    fp = popen(cmd, "r");
    if (!fp)
    {
        LOGE("Unable to open pipe! :: cmd=%s", cmd);
        return false;
    }

    // Parse output
    for (index=0; fgets(buf, sizeof(buf), fp); index++)
    {
        if (6 == sscanf(buf,
                        "assoclist %2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
                        &macaddr.addr[0], &macaddr.addr[1], &macaddr.addr[2],
                        &macaddr.addr[3], &macaddr.addr[4], &macaddr.addr[5]))
        {
            // Run user callback
            cb(ifname, &macaddr, index, context);
        }
    }

    pclose(fp);
    return false;
}

bool bcmwl_vap_mac_list_type_get(const char *ifname, int *mac_list_type)
{
    FILE *fp;
    char *ptr;
    char cmd[512];
    char buf[512];
    bool success;

    *mac_list_type = -1;

    snprintf(cmd, sizeof(cmd), "wlctl -i %s macmode", ifname);

    fp = popen(cmd, "r");
    if (fp && fgets(buf, sizeof(buf), fp))
    {
        *mac_list_type = strtol(buf, &ptr, 10);
        success = true;
    }

    if (fp)
        pclose(fp);

    return success;
}

bool bcmwl_vap_ssid_broadcast_get(const char *ifname, int *ssid_broadcast)
{
    FILE *fp;
    char *ptr;
    char cmd[512];
    char buf[512];
    bool success;

    *ssid_broadcast = -1;

    snprintf(cmd, sizeof(cmd), "wlctl -i %s closed", ifname);

    fp = popen(cmd, "r");
    if (fp && fgets(buf, sizeof(buf), fp))
    {
        *ssid_broadcast = strtol(buf, &ptr, 10);
        success = true;
    }

    if (fp)
        pclose(fp);

    return success;
}


bool bcmwl_vap_br_tag_get(const char *ifname, char *brtag, size_t len)
{
    // FIXME we need to find a sane way to safely "reserve" brtag that
    // will be used for current interface.

    return !!snprintf(brtag, len, "%s",
                      strstr(ifname, "wl0") ? "lan5" : "lan6");
}

bool bcmwl_vap_br_name_get(const char *ifname, char *brname, size_t len)
{
    return !!snprintf(brname, len, "br-%s", ifname);
}

bool bcmwl_restart_userspace()
{
    bcmwl_nas_reload_full();
    bcmwl_wps_restart();
    return true;
}

bool bcmwl_vap_psk_get(const char *ifname, char *psk, ssize_t psk_len)
{
    return util_nvram_get_fmt(psk, psk_len, "%s_wpa_psk", ifname);
}

bool bcmwl_vap_ssid_get(const char *ifname, char *ssid, ssize_t ssid_len)
{
    return util_nvram_get_fmt(ssid, ssid_len, "%s_ssid", ifname);
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


bool bcmwl_vap_create(const struct bcmwl_vap_config_t *bcmwl_vap_config,
                      const struct schema_Wifi_VIF_Config *vconfig,
                      const struct schema_Wifi_Radio_Config *rconfig)
{
    int i;
    const char *ifname  = vconfig->if_name;
    const char *phyname = rconfig->if_name;
    char brtag[32]      = { 0 };

    LOGD("Create VAP :: %s", ifname);

    // Set vap bridge settings -- note that this only works for vaps that
    // are not added to any bridge. We will need to add handling for vaps
    // that need to be added new or existing to bridge.
    bcmwl_vap_br_tag_get(ifname, brtag, sizeof(brtag));
    util_nvram_set_fmt("%s_ifname=%s",          brtag, ifname);
    util_nvram_set_fmt("%s_ifnames=%s",         brtag, ifname);
    util_nvram_set_fmt("%s_hwaddr="PRI(os_macaddr_t),
                                                brtag, FMT(os_macaddr_t, bcmwl_vap_config->bssid));

    // Set VAP nvram settings
    util_nvram_set_fmt("%s_ssid=%s",            ifname, vconfig->ssid);
    util_nvram_set_fmt("%s_akm=%s",             ifname, "psk2");
    util_nvram_set_fmt("%s_wep=%s",             ifname, "disabled");
    util_nvram_set_fmt("%s_mode=%s",            ifname, "ap");
    util_nvram_set_fmt("%s_crypto=%s",          ifname, "aes");
    util_nvram_set_fmt("%s_wpa_psk=%s",         ifname, SCHEMA_KEY_VAL(vconfig->security, "key"));
    util_nvram_set_fmt("%s_hwaddr="PRI(os_macaddr_t),
                                                ifname, FMT(os_macaddr_t, bcmwl_vap_config->bssid));
    util_nvram_set_fmt("%s_preauth=%d",         ifname, 0);
    util_nvram_set_fmt("%s_net_reauth=%d",      ifname, 36000);
    util_nvram_set_fmt("%s_bss_enabled=%d",     ifname, 1);
    util_nvram_set_fmt("%s_wpa_gtk_rekey=%d",   ifname, 0);
    util_nvram_set_fmt("%s_channel=%d",         ifname, 0);
    util_nvram_set_fmt("%s_ifname=%s",          ifname, ifname);
    util_nvram_set_fmt("%s_radio=%d",           ifname, 1);

    // Plume specific
    if (SCHEMA_KEY_VAL(vconfig->security, "mode"))
    {
        util_nvram_set_fmt("%s_plume_wpa_mode=%s", ifname, "true");
    }

    // Create VAP interface

    util_wlctl_fmt("-i %s ssid -C %d %s",       phyname, bcmwl_vap_config->index, vconfig->ssid);
    util_wlctl_fmt("-i %s bss down",            ifname);
    util_wlctl_fmt("-i %s down",                ifname);

    os_nif_up(                                  (char *)ifname, false);

    // Set MAC/BSSID
    os_nif_macaddr_set(                         (char *)ifname, bcmwl_vap_config->bssid);
    util_wlctl_fmt("-i %s cur_etheraddr "PRI(os_macaddr_t),
                                                ifname, FMT(os_macaddr_t, bcmwl_vap_config->bssid));


    // ACL
    util_wlctl_fmt("-i %s macmode %d",          ifname,
                                                bcmwl_vap_mac_list_type_to_int(vconfig->mac_list_type));
    util_wlctl_fmt("-i %s mac none",            ifname);

    for (i = 0; i < vconfig->mac_list_len; i++)
    {
        util_wlctl_fmt("-i %s mac %s",          ifname, vconfig->mac_list[i]);
    }

    // Disable probe responses in case that client is blacklisted or not
    // whitelisted.
    util_wlctl_fmt("-i %s probresp_sw %d",      ifname, 1);

    // Security
    util_wlctl_fmt("-i %s wsec_restrict %d",    ifname, 1);
    util_wlctl_fmt("-i %s wsec %d",             ifname, 4);
    util_wlctl_fmt("-i %s wpa_auth %d",         ifname, 128);
    util_wlctl_fmt("-i %s eap %d",              ifname, 1);

    // SSID broadcast
    util_wlctl_fmt("-i %s closed %d",           ifname,
                                                bcmwl_vap_ssid_broadcast_to_int(vconfig->ssid_broadcast));

    // Finalize
    os_nif_up(                                  (char *)ifname, true);
    util_wlctl_fmt("-i %s bss down",            ifname);
    util_wlctl_fmt("-i %s down",                ifname);
    util_wlctl_fmt("-i %s up",                  ifname);
    util_wlctl_fmt("-i %s bss up",              ifname);

    // Restart EADP/NAS
    bcmwl_restart_userspace();

    return 0;
}

bool
bcmwl_vap_state(const char *ifname,
                struct schema_Wifi_VIF_State *vstate)
{
    struct wl_status status;
    const char *key, *keyid, *oftag;
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

    if (status.is_sta) {
        if ((p = NVG(ifname, "plume_bss_enabled")))
            SCHEMA_SET_INT(vstate->enabled, atoi(p) == 1);
    } else {
        if ((p = WL(ifname, "bss")))
            SCHEMA_SET_INT(vstate->enabled, !strcmp(p, "up"));
    }
    if (strlen(status.ssid))
        SCHEMA_SET_STR(vstate->ssid, status.ssid);
    if (status.is_sta)
        SCHEMA_SET_STR(vstate->parent, (bcmwl_roam_get_status(ifname) == BCMWL_ROAM_COMPLETE
                                        ? status.bssid
                                        : ""));
    if (status.channel)
        SCHEMA_SET_INT(vstate->channel, status.channel);
    if ((p = bcmwl_lan_search(ifname)) && (p = strdupafree(p)))
        SCHEMA_SET_STR(vstate->bridge, strcmp(ifname, p) ? p : "");
    if ((p = WL(ifname, "cur_etheraddr")) && WL_VAL(p))
        SCHEMA_SET_STR(vstate->mac, str_tolower(p));
    if ((bcmwl_radio_is_dhd(ifname)
         ? (p = DHD(ifname, "ap_isolate"))
         : (p = WL(ifname, "ap_isolate"))) &&
        (i = (atoi(p) == 0 ? 1 :
              atoi(p) == 1 ? 0 :
              -1)) >= 0)
        SCHEMA_SET_INT(vstate->ap_bridge, i);
    if ((p = WL(ifname, "closed")))
        SCHEMA_SET_STR(vstate->ssid_broadcast,
                       atoi(p) == 0 ? "enabled" :
                       atoi(p) == 1 ? "disabled" :
                       strfmta("unknown=%s", p));
    if ((p = WL(ifname, "dynbcn")))
        SCHEMA_SET_INT(vstate->dynamic_beacon, atoi(p));
    if (bcmwl_acl_is_synced(ifname)) {
        if ((p = BCMWL_ACL_POLICY_GET(ifname, BCMWL_ACL_WM)) && strlen(p) > 0)
            SCHEMA_SET_STR(vstate->mac_list_type,
                           atoi(p) == 0 ? "none" :
                           atoi(p) == 1 ? "blacklist" :
                           atoi(p) == 2 ? "whitelist" :
                           strfmta("unknown=%p", p));
        if ((p = BCMWL_ACL_GET(ifname, BCMWL_ACL_WM)))
            while ((mac = strsep(&p, " ")))
                if (strlen(mac))
                    SCHEMA_VAL_APPEND(vstate->mac_list, str_tolower(mac));
    }
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
    } else {
        if ((p = WL(ifname, "wpa_auth")) && strstr(p, "Disabled"))
            SCHEMA_KEY_VAL_APPEND(vstate->security, "encryption", "OPEN");
    }
    if ((p = NVG(ifname, "plume_min_hw_mode")) && strlen(p))
        SCHEMA_SET_STR(vstate->min_hw_mode, p);
    if ((p = NVG(ifname, "wpa_gtk_rekey")) && strlen(p))
        SCHEMA_SET_INT(vstate->group_rekey, atoi(p));
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

    /* FIXME
     *  - min_hw_mode
     */

    return true;
}

void bcmwl_vap_state_report(const char *ifname)
{
    struct schema_Wifi_VIF_State vstate;

    if (!bcmwl_ops.op_vstate)
        return;
    LOGD("vif: %s: updating", ifname);
    if (bcmwl_vap_state(ifname, &vstate))
        bcmwl_ops.op_vstate(&vstate);
}

bool bcmwl_vap_update(const struct schema_Wifi_VIF_Config *vconfig,
                      const struct schema_Wifi_Radio_Config *rconfig,
                      const struct schema_Wifi_VIF_Config_flags *vchanged)
{
    int i;

    // TODO depreacte this function and use bcmwl_vap_update2()

    // Update MAC list type
    if (vchanged->mac_list_type)
    {
        util_wlctl_fmt("-i %s macmode %d",          vconfig->if_name,
                                                    bcmwl_vap_mac_list_type_to_int(vconfig->mac_list_type));
    }

    // Update MAC list
    if (vchanged->mac_list)
    {
        util_wlctl_fmt("-i %s mac none",            vconfig->if_name);
        for (i = 0; i < vconfig->mac_list_len; i++)
        {
            util_wlctl_fmt("-i %s mac %s",          vconfig->if_name, vconfig->mac_list[i]);
        }
    }

    if (vchanged->enabled)
    {
        WARN_ON(!WL(vconfig->if_name, "bss", vconfig->enabled ? "up" : "down"));
        os_nif_up((char *)vconfig->if_name,  vconfig->enabled ? true : false);
    }

    return true;
}

bool bcmwl_vap_is_sta(const char *ifname)
{
    const char *p = WL(ifname, "rssi");
    return p && !strstr(p, "Bad Argument") && atoi(p) != 96;
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

void bcmwl_vap_update_security_multipsk(const struct schema_Wifi_VIF_Config *vconf,
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

bool bcmwl_vap_update_security(const struct schema_Wifi_VIF_Config *vconf,
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

    WARN_ON(strcmp(akm, "WPA-PSK") &&
            strcmp(akm, "OPEN") &&
            strcmp(akm, ""));

    nv_akm = !strcmp(akm, "WPA-PSK")
             ? (atoi(crypto) == 1 ? "psk" :
                atoi(crypto) == 2 ? "psk2" :
                atoi(crypto) == 3 ? "psk psk2" :
                "psk2")
             : "";
    nv_crypto = !strcmp(akm, "WPA-PSK")
                ?  atoi(crypto) == 1 ? "tkip+aes" :
                   atoi(crypto) == 2 ? "aes" :
                   atoi(crypto) == 3 ? "tkip+aes" :
                   "aes"
                : "";

    wl_eap = !strcmp(akm, "WPA-PSK") ? "1" : "0";
    wl_wsec = strfmta("%d", !strcmp(akm, "WPA-PSK")
                            ? (atoi(crypto) == 1 ? TKIP_ENABLED :
                               atoi(crypto) == 2 ? AES_ENABLED :
                               atoi(crypto) == 3 ? TKIP_ENABLED + AES_ENABLED :
                               AES_ENABLED)
                            : 0);
    wl_wsec_restrict = !strcmp(akm, "WPA-PSK") ? "1" : "0";
    wl_crypto = !strcmp(akm, "WPA-PSK")
                ? (atoi(crypto) == 1 ? WPA_AUTH_PSK :
                    atoi(crypto) == 2 ? WPA2_AUTH_PSK :
                    atoi(crypto) == 3 ? WPA_AUTH_PSK | WPA2_AUTH_PSK :
                    WPA2_AUTH_PSK)
                : 0;

    /*
     * We have to save bss up/down state here, because
     * bcmwl_vap_update_ft_psk() could run vif down/up
     * which also do bss down and take some time before
     * up again. In some cases, when we change wl_wpa_auth,
     * bss left down all the time and we didn't send
     * beacons.
     */
    was_up = !strcmp(WL(vif, "bss") ?: "", "up");
    bcmwl_vap_update_ft_psk(vconf, rconf, vchanged);

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
         |  strcmp(WL(vif, "eap") ?: "", wl_eap)
         |  strcmp(WL(vif, "wsec_restrict") ?: "", wl_wsec_restrict)
         |  strcmp(wl_wpa_auth_prev, wl_wpa_auth)
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
        if (was_up)
            WARN_ON(!WL(vif, "bss", "up"));
    }

    bcmwl_vap_update_security_multipsk(vconf, &fast);

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
    int i, j;
    char *p;

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
        WARN_ON(!NVS(vif, "ifname", vif));
        WARN_ON(!NVS(vif, "radio", "1"));
        WARN_ON(!NVS(vif, "bss_enabled", "1"));
        WARN_ON(!NVS(vif, "plume_bss_enabled", vconf->enabled ? "1" : "0"));
        if (vconf->enabled)
            WARN_ON(!NVS(vif, "mode", vconf->mode));
        if ((p = WL(vif, "cur_etheraddr")) && WL_VAL(p))
            WARN_ON(!(NVS(vif, "hwaddr", p)));

        WARN_ON(!WL(vif, "bss", "down"));

        if (!vconf->enabled)
            goto report;

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

        WARN_ON(!strexa("ip", "link", "set", vif, "up"));
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

    if (vchanged->parent)
        WARN_ON(!NVS(vif, "plume_desired_bssid", vconf->parent));

    if (vchanged->security ||
        vchanged->ssid ||
        vchanged->bridge ||
        vchanged->group_rekey ||
        vchanged->ft_psk ||
        vchanged->ft_mobility_domain)
        WARN_ON(!bcmwl_vap_update_security(vconf, rconf, cconfs, vchanged, num_cconfs));

    if (vchanged->ssid_broadcast)
        WARN_ON(!WL(vif, "closed",
                    !strcmp(vconf->ssid_broadcast, "enabled") ? "0" :
                    !strcmp(vconf->ssid_broadcast, "disabled") ? "1" :
                    "0")); // FIXME: WARN_ON

    if (vchanged->dynamic_beacon)
        WARN_ON(!WL(vif, "dynbcn", vconf->dynamic_beacon ? "1" : "0"));

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

    if (vchanged->ssid && !strcmp(vconf->mode, "ap"))
        WARN_ON(!WL(vif, "ssid", vconf->ssid));

    if (vchanged->enabled || vchanged->mode) {
        if (!strcmp(vconf->mode, "ap")) {
            WARN_ON(!WL(vif, "bss", "up"));
            if (rconf->channel_exists && rconf->ht_mode_exists)
                WARN_ON(!bcmwl_radio_channel_set(phy, rconf->channel, strstr(rconf->freq_band, "2.4G") ? "HT20" : rconf->ht_mode));
        }
    }

    if (vchanged->btm)
        WARN_ON(!WL(vif, "wnm", vconf->btm ? "+1" : "-1"));

    if (vchanged->rrm)
        bcmwl_vap_update_rrm(rconf, vconf);

    if (!strcmp(vconf->mode, "sta"))
        bcmwl_roam_init(vif);

    NVS(vif, "plume_min_hw_mode", vconf->min_hw_mode_exists
                                  ? vconf->min_hw_mode
                                  : NULL);

    bcmwl_event_setup(EV_DEFAULT);
    bcmwl_roam_later(vconf->if_name);

report:
    evx_debounce_call(bcmwl_vap_state_report, vconf->if_name);
    evx_debounce_call(bcmwl_radio_state_report, rconf->if_name);
    return true;
}
