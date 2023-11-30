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
#include <glob.h>
#include <byteswap.h>

#include "target.h"
#include "log.h"
#include "schema.h"
#include "const.h"
#include "util.h"
#include "evx_debounce_call.h"
#include "kconfig.h"
#include "bcmwl.h"
#include "bcmwl_nvram.h"
#include "bcmwl_debounce.h"
#include "bcmwl_ioctl.h"
#include <wlioctl.h>


#define PLUME_CSA_MODE        0     // Does not block Tx during CSA
#define PLUME_CSA_COUNT       15    // General value used by Plume

/**
 * Data maps
 */

static c_item_t g_map_band[] = {
    C_ITEM_STR_STR("a",     SCHEMA_CONSTS_RADIO_TYPE_STR_5G),
    C_ITEM_STR_STR("b",     SCHEMA_CONSTS_RADIO_TYPE_STR_2G),
    C_ITEM_STR_STR("6g",    SCHEMA_CONSTS_RADIO_TYPE_STR_6G),
};

static c_item_t g_map_ht_mode[] = {
    C_ITEM_STR(20,          "HT20"),
    C_ITEM_STR(2040,        "HT2040"),
    C_ITEM_STR(40,          "HT40"),
    C_ITEM_STR(80,          "HT80"),
    C_ITEM_STR(160,         "HT160"),
    C_ITEM_STR(320,         "HT320"),
};

/**
 * Public
 */

const char* bcmwl_radio_band_to_str(char *band)
{
    c_item_t *item;

    if ((item = c_get_item_by_strkey(g_map_band, band)))
    {
        return (const char *)item->data;
    }

    LOGE("Unsupported band value: %s", band);
    return SCHEMA_CONSTS_RADIO_TYPE_STR_2G;
}

const char* bcmwl_radio_band_type_str(const char *phyname, char *band)
{
    const char *band_str = bcmwl_radio_band_to_str(band);
    if (!strcmp(band_str, SCHEMA_CONSTS_RADIO_TYPE_STR_5G)) {
        /* identify if it's a 5G, 5GL or 5GU type radio */
        const char *dis_ch_grp = WL(phyname, "dis_ch_grp");
        int dis_ch = dis_ch_grp ? atoi(dis_ch_grp) : 0;
        /* wl dis_ch_grp sample output: "24 (0x18)"
         * Meaning:
         * Bit Channels-Disabled Band
         * 0 ... - 51  UNII-1
         * 1  52 - 61  UNII-2a
         * 2  62 - 99  UNII-2b
         * 3 100 - 148 UNII-2-ext
         * 4 149 - ... UNII-3, ISM
         */
        if (dis_ch > 0) {
            if (dis_ch & 0x18) {
                return SCHEMA_CONSTS_RADIO_TYPE_STR_5GL;
            }
            if (dis_ch & 0x7) {
                return SCHEMA_CONSTS_RADIO_TYPE_STR_5GU;
            }
        }
    }
    return band_str;
}

int bcmwl_radio_ht_mode_to_int(const char *ht_mode)
{
    c_item_t *item;

    if ((item = c_get_item_by_str(g_map_ht_mode, ht_mode)))
    {
        return item->key;
    }

    LOGE("Unsupported ht_mode value: %s", ht_mode);
    return 20;
}

const char* bcmwl_radio_ht_mode_to_str(int ht_mode)
{
    c_item_t *item;

    if ((item = c_get_item_by_key(g_map_ht_mode, ht_mode)))
    {
        return (const char *)item->data;
    }

    LOGE("Unsupported ht_mode value: %d", ht_mode);
    return "HT20";
}

bool bcmwl_radio_is_dhd_fast(const char *ifname)
{
    unsigned int magic;
    bool is_dongle;

    if (!bcmwl_DHDGIOC(ifname, DHD_GET_MAGIC, NULL, &magic))
        return false;

    is_dongle = magic == DHD_IOCTL_MAGIC ||
                magic == bswap_32(DHD_IOCTL_MAGIC);
    return is_dongle;
}

bool bcmwl_radio_is_dhd(const char *ifname)
{
    if (kconfig_enabled(CONFIG_BCM_PREFER_IOV))
        return bcmwl_radio_is_dhd_fast(ifname);

    /* In case there is no dhdctl available we assume that we operate
     * only on non-dongle radios.
     */
    if (!strexa("which", "dhdctl"))
        return false;

    /* FIXME: This can be optimized to call ioctl(SIOCDEVPRIVATE) and
     *        use DHD_GET_MAGIC command to check if the result is
     *        DHD_IOCTL_MAGIC (0x00444944).
     */
    return DHD(ifname, "cap") != NULL;
}

/* CONFIG_BCMWL_HE_FEATURES:
 * Using -1 will enable all features that a radio supports
 * wl he features [<features mask>] - query or enable/disable HE sub-features
 * 0x01: HE 5G support
 * 0x02: HE 2G support
 * 0x04: HE DL OFDMA support
 * 0x08: HE UL OFDMA support
 * 0x10: HE DL MUMIMO support
 * 0x20: HE UL MUMIMO support
 * 0x40: HE STA ULMU support
 * 0x80: HE ER SU Rx support
 */

static const char* bcmwl_radio_get_hwmode(const char *dphy)
{
    const int feat = atoi(CONFIG_BCMWL_HE_FEATURES);
    const int eht_feat = atoi(CONFIG_BCMWL_EHT_FEATURES);

    if (atoi(WL(dphy, "eht", "enab") ?: "0") && atoi(WL(dphy, "eht", "features") ?: "0") == eht_feat)
        return "11be";
    if (atoi(WL(dphy, "he", "enab") ?: "0") && atoi(WL(dphy, "he", "features") ?: "0") == feat)
        return "11ax";
    if (atoi(WL(dphy, "vhtmode") ?: "0"))
        return "11ac";
    if (atoi(WL(dphy, "nmode") ?: "0"))
        return "11n";
    if ((WL(dphy, "bands") ?: "b")[0] == 'a')
        return "11a";

    /* FIXME: 11b? */
    return "11g";
}

static const char* bcmwl_radio_get_hwname(const char *dphy)
{
    static const char *hwnames[] = {
        "0xaa52", "bcm4360",
        "0xaa90", "bcm4366",
        "0xd145", "bcm47189",
        "0x6362", "bcm2057",
        "0x4360", "bcm4360",
        "0x4366", "bcm4366",
        "0xaaa4", "bcm43684",
        "0xf6ca", "bcm6755",
        "0x6710", "bcm6710",
        "0x6715", "bcm6715",
        "0x6717", "bcm6717",
        "0x6726", "bcm6726",
        "0x6756", "bcm6756",
        NULL, NULL,
    };
    const char *const*hw;
    char *buf, *l, *k, *v;
    if (!(buf = strexa("wlctl", "-i", dphy, "revinfo")))
        return NULL;
    while ((l = strsep(&buf, "\n")))
        if ((k = strsep(&l, " ")) && (v = strsep(&l, "")))
            if (!strcmp(k, "chipnum"))
                for (hw = hwnames; *hw; hw += 2)
                    if (strtol(hw[0], NULL, 16) == strtol(v, NULL, 16))
                        return hw[1];
    return NULL;
}

bool bcmwl_radio_band_get(const char *phyname, char *band, ssize_t band_len)
{
    const char *selected = WL(phyname, "band");
    const char *all = WL(phyname, "bands");

    if (!all) return false;
    if (!selected) return false;

    if (strcmp(selected, "auto")) {
        strscpy(band, selected, band_len);
        return true;
    }

    if (strstr(all, " ")) {
        LOGW("%s: multiple bands avilable, none selected, fix at integration please", phyname);
        return false;
    }

    /* reaching here means there's only 1 band on the phy */
    strscpy(band, all, band_len);
    return true;
}

void bcmwl_radio_chanspec_extract(const char *chanspec, int *chan, int *centerchan, int *width)
{
    /* Example chanspecs:
     * 1 (0x1801)
     * 1l (0x1803)
     * 11u (0x1909)
     * 44/80 (0xe22a)
     * 6g1 (0x5001)
     * 6g1/320-1 (0x7000)
     * 6g33/320-2 (0x7001)
     * 6g161/320-1 (0x7204)
     * 6g161/320-2 (0x7005)
     */
    char *buf = strdupa(strpbrk(chanspec, "1234567890") ?: "");
    char *str = strsep(&buf, " ");
    const char *prefix_6g = "6g";
    const char *c, *w;
    bool is_6g = false;
    bool is_l = false;
    bool is_u = false;
    int bandscheme;
    int num;
    if (strstr(str, prefix_6g) == str) {
        str += strlen(prefix_6g);
        is_6g = true;
    }
    num = atoi(str);
    if ((is_l = (strstr(str, "l") != NULL)) || (is_u = (strstr(str, "u") != NULL))) {
        *chan = atoi(str);
        *centerchan = *chan + ((is_l) ? 2 : -2);
        *width = 40;
    }
    else if ((c = strsep(&str, "/")) && (w = strsep(&str, "-"))) {
        *chan = atoi(c);
        *width = atoi(w);
        switch (*width) {
            case 40: /* fallthrough */
            case 80: /* fallthrough */
            case 160:
                *centerchan = is_6g
                            ? chanlist_to_center(unii_6g_chan2list(*chan, *width))
                            : chanlist_to_center(unii_5g_chan2list(*chan, *width));
                WARN_ON(*centerchan == 0);
                break;
            case 320:
                bandscheme = atoi(str ?: "0");
                if (bandscheme == 1)
                    *centerchan = chanlist_to_center(unii_6g_320_1_chan2list(*chan));
                if (bandscheme == 2)
                    *centerchan = chanlist_to_center(unii_6g_320_2_chan2list(*chan));
                WARN_ON(*centerchan == 0);
                break;
        }
    }
    else {
        *chan = num;
        *centerchan = *chan;
        *width = 20;
        WARN_ON(*chan == 0);
    }
}

int bcmwl_radio_get_ap_active_cnt(const char *phy)
{
    struct dirent *p;
    const char *q;
    DIR *d;
    int cnt = 0;

    if (WARN_ON(!(d = opendir("/sys/class/net/"))))
        return cnt;
    while ((p = readdir(d)))
        if (strstr(p->d_name, phy) == p->d_name && !bcmwl_vap_is_sta(p->d_name))
            if ((q = WL(p->d_name, "bss")) && !strcmp(q, "up"))
                cnt++;
    closedir(d);

    return cnt;
}

bool bcmwl_radio_get_chanspec(const char *phy, int *chan, int *centerchan, int *width)
{
    struct dirent *p;
    const char *q = NULL;
    DIR *d;
    if (WARN_ON(!(d = opendir("/sys/class/net/"))))
        return false;
    while ((p = readdir(d)))
        if (strstr(p->d_name, phy) == p->d_name)
            if ((q = WL(p->d_name, "bss")) && !strcmp(q, "up"))
                if ((q = WL(p->d_name, "chanspec")))
                    break;
    closedir(d);
    if (!p)
        return false;
    bcmwl_radio_chanspec_extract(q, chan, centerchan, width);
    return true;
}

static char* bcmwl_radio_chanspec_prep(const char *phy, int channel, int center_channel, const char *ht_mode)
{
    int bw = atoi(strpbrk(ht_mode, "1234567890") ?: "");
    const char *prefix = "";
    const char *prefix_6g = "6g";
    const char *band_6g = "6g";
    char band[32] = {0};
    char *i, *p;

    if (!bcmwl_radio_band_get(phy, band, sizeof(band)))
        return NULL;

    if (strcmp(band, band_6g) == 0)
        prefix = prefix_6g;

    switch (bw) {
        default:
            /* FALLTHROUGH */
        case 20:
            return strfmt("%s%d", prefix, channel);
        case 2040:
            /*
             * This is a special case where obss_coex is enabled to
             * juggle between HT20 and HT40 so the upper limit of the
             * bandwidth should be used here.
             */
            bw = 40;
            /* FALLTHROUGH */
        case 40:
            for (p = WL(phy, "chanspecs"); (i = strsep(&p, "\r\n")); )
                if ((i = strsep(&i, " "))) {
                    if (strstr(i, prefix_6g) == i)
                        i += strlen(prefix_6g);
                    if (strstr(i, "l") || strstr(i, "u") || strstr(i, "/40"))
                        if (atoi(i) == channel)
                            return strfmt("%s%s", prefix, i);
                }
            return NULL;
        case 80:
        case 160:
            return strfmt("%s%d/%d", prefix, channel, bw);
        case 320:
            if (unii_6g_is_320_1(center_channel))
                return strfmt("%s%d/%d-1", prefix, channel, bw);
            if (unii_6g_is_320_2(center_channel))
                return strfmt("%s%d/%d-2", prefix, channel, bw);
    }
    return NULL;
}

/**
 * Returns a malloc()-ed string with space-separated
 * interfaces names that are running AP interfaces.
 */
char* bcmwl_radio_get_vifs(const char *phy)
{
    struct dirent *p;
    char *vifs = "";
    DIR *d;

    if (WARN_ON(!(d = opendir("/sys/class/net"))))
        goto out;

    while ((p = readdir(d)))
        if (strstr(p->d_name, phy) == p->d_name)
            if (!bcmwl_vap_is_sta(p->d_name))
                if (!strcmp(WL(p->d_name, "bss") ?: "", "up"))
                    vifs = strchomp(strfmta("%s %s", p->d_name, vifs), " ");

    closedir(d);
out:
    return strdup(vifs);
}

bool bcmwl_radio_channel_set(const char *phy, int channel, int center_channel, const char *ht_mode)
{
    const char *chanspec = strdupafree(bcmwl_radio_chanspec_prep(phy, channel, center_channel, ht_mode)) ?: "";
    const char *current;
    bool move = false;
    struct dirent *p;
    const char *q;
    char *apvifs = strdupafree(bcmwl_radio_get_vifs(phy));
    char *apvif;
    int c, cc, cw;
    DIR *d;

    if (WARN_ON(!chanspec))
        return false;

    if (channel) {
        WARN_ON(!NVS(phy, "chanspec", chanspec));
        WARN_ON(!NVS(phy, "channel", strfmta("%d", channel)));
    }

    if ((q = NVG(phy, "zero_wait_dfs")) &&
        (!strcmp(q, "enable") || !strcmp(q, "precac")) &&
        bcmwl_radio_is_dfs_channel(phy, channel, ht_mode))
            move = true;

    if (!channel)
        return true;
    if (!strlen(ht_mode))
        return true;
    if (!bcmwl_radio_get_chanspec(phy, &c, &cc, &cw))
        return true;
    current = strdupafree(bcmwl_radio_chanspec_prep(phy, c, cc, strfmta("HT%d", cw)) ?: "x");
    if (!strcmp(chanspec, current))
        return true;
    if (WARN_ON(strlen(chanspec) == 0))
        return false;
    if ((apvif = strdupa(apvifs ?: "")) &&
        (apvif = strsep(&apvif, " ")) &&
        (strlen(apvif) > 0)) {
        if (move) {
            if (bcmwl_dfs_bgcac_active(phy, channel, ht_mode)) {
                LOGI("%s backgroud CAC active for %d @ %s, skip moving",
                     phy, channel, ht_mode);
            } else {
                if (WARN_ON(!WL(apvif, "dfs_ap_move", chanspec)))
                    return false;
            }
        } else {
            /* Skip background CAC, in other case csa will fail */
            bcmwl_dfs_bgcac_deactivate(phy);
            if (WARN_ON(!WL(apvif, "csa", "0", "15", chanspec)))
                return false;
        }
    } else {
        LOGI("%s: no ap vifs: skipping csa, will set chanspec only", phy);
        /* chanspec needs to be set always anyway so that in case
         * radio goes down/up it goes back to the intended channel.
         * This is done below.
         */
    }

    if (WARN_ON(!(d = opendir("/sys/class/net"))))
        return false;
    while ((p = readdir(d))) {
        if (strstr(p->d_name, phy) != p->d_name)
            continue;
        WARN_ON(!WL(p->d_name, "chanspec", chanspec));
    }
    closedir(d);

    LOGI("%s: %s to channel %s", move ? "moving" : "switching", phy, chanspec);
    return true;
}

const char* bcmwl_channel_state(enum bcmwl_chan_state state)
{
   /* key = channel number, value = { "state": "allowed" }
    * channel states:
    *     "allowed" - no dfs/always available
    *     "nop_finished" - dfs/CAC required before beaconing
    *     "nop_started" - dfs/channel disabled, don't start CAC
    *     "cac_started" - dfs/CAC started
    *     "cac_completed" - dfs/pass CAC beaconing
    */
    switch (state) {
        case BCMWL_CHAN_STATE_ALLOWED:
            return "{\"state\":\"allowed\"}";
        case BCMWL_CHAN_STATE_CAC_STARTED:
            return "{\"state\": \"cac_started\"}";
        case BCMWL_CHAN_STATE_CAC_COMPLETED:
            return "{\"state\": \"cac_completed\"}";
        case BCMWL_CHAN_STATE_NOP_STARTED:
            return "{\"state\": \"nop_started\"}";
        case BCMWL_CHAN_STATE_NOP_FINISHED:
            return "{\"state\": \"nop_finished\"}";
        default:
            break;
    }

    return "{\"state\": \"nop_started\"}";
}

int bcmwl_get_current_channels(const char *phyname, int *chan, int size)
{
    const int *chans;
    int c;
    int cc;
    int w;
    int n;

    if (!bcmwl_radio_get_chanspec(phyname, &c, &cc, &w))
        return 0;

    chans = unii_5g_chan2list(c, w);
    if (!chans)
        return 0;

    for (n = 0; *chans && size; n++, size--)
        *chan++ = *chans++;

    return n;
}

static bool
bcmwl_radio_get_bcn_int(const char *phy_name, int *bcn_int)
{
    const struct bcmwl_ioctl_num_conv *conv;
    struct dirent *p;
    bool consistent = true;
    DIR *d;

    if (WARN_ON(!(conv = bcmwl_ioctl_lookup_num_conv(phy_name))))
        return false;

    *bcn_int = 0;

    /* As far as reporting goes, each AP can operate at a
     * different interval. Even if that isn't matching with
     * actual period of beacons sent OTA, the Beacon IE
     * report is still per BSS until re-started. To
     * facilitate config/state operation on a phy-attribute
     * (config) and vif-attribute (state), merge
     * vif-attributes into a single value.
     */

    for (d = opendir("/sys/class/net"); d && (p = readdir(d)); ) {
        const char *vif_name = p->d_name;

        const bool other_phy = (strstr(vif_name, phy_name) != vif_name);
        if (other_phy)
            continue;

        const bool not_ap = (bcmwl_vap_is_ap(vif_name) != true);
        if (not_ap)
            continue;

        const bool not_up = (strcmp(WL(vif_name, "bss") ?: "", "up") != 0);
        if (not_up)
            continue;

        struct ether_addr bssid;
        if (!bcmwl_GIOC(vif_name, WLC_GET_BSSID, NULL, &bssid))
            continue;

        union {
            char buf[WLC_IOCTL_MAXLEN];
            struct {
                uint32_t len; /* ignore */
                wl_bss_info_107_t info;
            };
        } bss;
        MEMZERO(bss);
        const uint32_t max_len = conv->dtoh32(sizeof(bss));
        if (WARN_ON(!bcmwl_GIOC(vif_name, WLC_GET_BSS_INFO, &max_len, &bss)))
            continue;

        const int beacon_period = conv->dtoh32(bss.info.beacon_period);
        LOGT("%s: %s has bcn_int = %d, previous = %d",
             phy_name, vif_name, beacon_period, *bcn_int);

        if (beacon_period == 0)
            continue;

        if (*bcn_int == 0) {
            *bcn_int = beacon_period;
            continue;
        }

        if (*bcn_int != beacon_period) {
            consistent = false;
            break;
        }
    }
    if (!WARN_ON(!d))
        closedir(d);

    const bool non_zero = (*bcn_int != 0);

    LOGT("%s: has bcn_int = %d consistent %d non_zero %d",
         phy_name, *bcn_int, consistent, non_zero);

    return consistent && non_zero;
}

static char *
bcmwl_radio_get_any_ap_vap(const char *phy_name)
{
    struct dirent *p;
    DIR *d;

    for (d = opendir("/sys/class/net"); d && (p = readdir(d)); ) {
        const char *vif_name = p->d_name;
        const bool other_phy = (strstr(vif_name, phy_name) != vif_name);
        if (other_phy) continue;

        const bool not_ap = (bcmwl_vap_is_ap(vif_name) != true);
        if (not_ap) continue;

        closedir(d);
        return STRDUP(vif_name);
    }
    if (!WARN_ON(!d))
        closedir(d);

    return NULL;
}

static void
bcmwl_radio_downup_ap_vaps(const char *phy_name)
{
    struct dirent *p;
    DIR *d;

    for (d = opendir("/sys/class/net"); d && (p = readdir(d)); ) {
        const char *vif_name = p->d_name;
        const bool other_phy = (strstr(vif_name, phy_name) != vif_name);
        if (other_phy) continue;

        const bool not_ap = (bcmwl_vap_is_ap(vif_name) != true);
        if (not_ap) continue;

        const bool not_up = (strcmp(WL(vif_name, "bss") ?: "", "up") != 0);
        if (not_up) continue;

        WARN_ON(WL(vif_name, "bss", "down") == NULL);
        WARN_ON(WL(vif_name, "bss", "up") == NULL);
    }
    if (!WARN_ON(!d))
        closedir(d);
}

static void
bcmwl_radio_set_bcn_int(const char *phy_name, const int bcn_int)
{
    char *ap_vif_name = bcmwl_radio_get_any_ap_vap(phy_name);

    LOGD("%s: setting bcn_int on %s to %d",
         phy_name, ap_vif_name ?: "", bcn_int);

    /* Eg. if wl0 is an APSTA(STA) interface, then
     * if it's down, the "bi" will refer to _any_
     * of the AP configuration, but if it's up,
     * then it refers to the associated
     * (parent/link) BSS. Therefore always find
     * _any_ AP BSS and set "bi" on that. And then
     * reload all BSSes. Just setting "bi" won't
     * reload config.
     */

    WARN_ON(ap_vif_name == NULL);
    if (ap_vif_name != NULL) {
        const char *arg = strfmta("%d", bcn_int);
        const char *result = WL(ap_vif_name, "bi", arg);
        WARN_ON(result == NULL);
        WARN_ON(result != NULL && strlen(result) > 0);

        bcmwl_radio_downup_ap_vaps(phy_name);
    }

    FREE(ap_vif_name);
}

bool bcmwl_radio_state(const char *phyname,
                       struct schema_Wifi_Radio_State *rstate)
{
    const char *p;
    char *q;
    int bcn_int;
    int channel = 0;
    int center = 0;
    int ht_mode = 0;
    char    band[32];

    memset(rstate, 0, sizeof(*rstate));
    schema_Wifi_Radio_State_mark_all_present(rstate);
    rstate->vif_states_present = false;
    rstate->radio_config_present = false;
    rstate->channel_sync_present = false;
    rstate->channel_mode_present = false;
    rstate->_partial_update = true;

    TRACE("%s", phyname ?: "");

    if (WARN_ON(!phyname || !*phyname))
        return false;

    // Common
    SCHEMA_SET_STR(rstate->if_name, phyname);

    if (!bcmwl_radio_adapter_is_operational(phyname)) {
        SCHEMA_SET_INT(rstate->enabled, 0);
        return false;
    }

    if (bcmwl_radio_get_chanspec(phyname, &channel, &center, &ht_mode)) {
        if (atoi(WL(phyname, "obss_coex") ?: "0") == 1)
            ht_mode = 2040;
        SCHEMA_SET_INT(rstate->channel, channel);
        SCHEMA_SET_INT(rstate->center_freq0_chan, center);
        SCHEMA_SET_STR(rstate->ht_mode, bcmwl_radio_ht_mode_to_str(ht_mode));
    }
    if ((p = bcmwl_radio_get_hwmode(phyname)))
        SCHEMA_SET_STR(rstate->hw_mode, p);
    if ((p = bcmwl_radio_get_hwname(phyname)))
        SCHEMA_SET_STR(rstate->hw_type, p);
    /* Some platforms configure mac addresses after drivers are probed
     * so `perm_etheraddr` can't be trusted. Using cur_etheraddr instead.
     */
    if ((q = WL(phyname, "cur_etheraddr")) && WL_VAL(q))
        SCHEMA_SET_STR(rstate->mac, q);
    if ((p = WL(phyname, "isup")))
        SCHEMA_SET_INT(rstate->enabled, atoi(p) != 0);
    if ((q = WL(phyname, "country")) && (q = strsep(&q, " ")))
        SCHEMA_SET_STR(rstate->country, q);
    if (bcmwl_radio_get_bcn_int(phyname, &bcn_int))
        SCHEMA_SET_INT(rstate->bcn_int, bcn_int);
    if ((q = WL(phyname, "txchain")) && (q = strsep(&q, " ")))
        SCHEMA_SET_INT(rstate->tx_chainmask, atoi(q));
    if ((q = WL(phyname, "txpwr")) && (q = strsep(&q, " ")))
        SCHEMA_SET_INT(rstate->tx_power, atoi(q));

    if ((q = WL(phyname, "radar")) && (p = WL(phyname, "dfs_preism"))) {
        if (atoi(q) == 1 && atoi(p) == -1)
            SCHEMA_SET_INT(rstate->dfs_demo, 0);
        if (atoi(q) == 0 && atoi(p) == 0)
            SCHEMA_SET_INT(rstate->dfs_demo, 1);
    }

    // Frequency band
    if (bcmwl_radio_band_get(phyname, band, sizeof(band)))
    {
        SCHEMA_SET_STR(rstate->freq_band, bcmwl_radio_band_type_str(phyname, band));
    }

    // Channels
    if ((q = WL(phyname, "channels")))
    {
        while ((p = strsep(&q, " ")))
        {
            SCHEMA_VAL_APPEND_INT(rstate->allowed_channels, atoi(p));
        }
    }

    bcmwl_radio_fallback_parents_get(phyname, rstate);
    bcmwl_radio_radar_get(phyname, rstate);
    bcmwl_radio_channels_get(phyname, rstate);

    if ((p = NVG(phyname, "zero_wait_dfs")) && strlen(p))
        SCHEMA_SET_STR(rstate->zero_wait_dfs, p);

    return true;
}

void bcmwl_radio_state_report(const char *ifname)
{
    struct schema_Wifi_Radio_State rstate;

    if (!bcmwl_ops.op_rstate)
        return;
    LOGD("phy: %s: updating", ifname);
    if (bcmwl_radio_state(ifname, &rstate))
        bcmwl_ops.op_rstate(&rstate);
}

static bool bcmwl_cap_is_supported(const char *phy, const char *cap)
{
    char *i, *p;

    p = WL(phy, "cap");
    if (!p)
        return false;

    while ((i = strsep(&p, " ")))
        if (!strcmp(i, cap))
            return true;

    return false;
}

/* FIXME: The following is intended to deprecate and
 * eventually replace bcmwl_radio_update().
 */
bool bcmwl_radio_update2(const struct schema_Wifi_Radio_Config *rconf,
                         const struct schema_Wifi_Radio_Config_flags *rchanged)
{
    const char *phy = rconf->if_name;
    const struct {
        const char *mode;
        const char *ht;
        const char *vht;
        const char *he;
        const char *eht;
        const char *he_features;
        const char *eht_features;
    } modes[] = {
        { "11be", "-1", "1", "1", "1", CONFIG_BCMWL_HE_FEATURES, CONFIG_BCMWL_EHT_FEATURES },
        { "11ax", "-1", "1", "1", "0", CONFIG_BCMWL_HE_FEATURES, "0" },
        { "11ac", "-1", "1", "0", "0", "0", "0" },
        { "11n",  "-1", "0", "0", "0", "0", "0" },
        { "11g",  "0",  "0", "0", "0", "0", "0" },
        { "11b",  "0",  "0", "0", "0", "0", "0" },
        { "11a",  "0",  "0", "0", "0", "0", "0" },
    };
    size_t i;
    char *p;

    TRACE("%s", phy ?: "");

    if (WARN_ON(!phy || !*phy))
        return false;
    if (WARN_ON(strstr(phy, CONFIG_BCMWL_VAP_DELIMITER)))
        return false;
    if (!bcmwl_radio_adapter_is_operational(rconf->if_name))
        return false;

    if (rchanged->hw_mode) {
        WL(phy, "down");

        for (i = 0; i < ARRAY_SIZE(modes); i++)
            if (!strcmp(modes[i].mode, rconf->hw_mode))
                break;

        if (i < ARRAY_SIZE(modes)) {
            WARN_ON(!WL(phy, "nmode", modes[i].ht));
            WARN_ON(!WL(phy, "vhtmode", modes[i].vht));
            if (WL(phy, "he", "enab") != NULL) {
                WARN_ON(!WL(phy, "he", "enab", modes[i].he));
                WARN_ON(!WL(phy, "he", "features", modes[i].he_features));
            }
            if (WL(phy, "eht", "enab") != NULL) {
                WARN_ON(!WL(phy, "eht", "enab", modes[i].eht));
                WARN_ON(!WL(phy, "eht", "features", modes[i].eht_features));
            }
        }

        /* If rchanged->enabled is true then the radio will
         * be possibly "up"-ed down below.
         */
        if (!rchanged->enabled && rconf->enabled)
            WL(phy, "up");
    }

    if (rchanged->enabled) {
        if ((p = WL(phy, "isup")) && atoi(p) == 0) {
            if (strstr(rconf->freq_band, "2.4G"))
                WARN_ON(!WL(phy, "bw_cap", "2g", "0xff"));
            if (strstr(rconf->freq_band, "5G"))
                WARN_ON(!WL(phy, "bw_cap", "5g", "0xff"));
            if (strstr(rconf->freq_band, "6G"))
                WARN_ON(!WL(phy, "bw_cap", "6g", "0xff"));
            if (bcmwl_cap_is_supported(phy, "dyn160")) {
                LOGI("%s: disabling extnssbw", phy);
                WARN_ON(!WL(phy, "dyn160", "0"));
            }
        }
        if ((p = WL(phy, "chanspec")) && (p = strsep(&p, " ")))
            WARN_ON(!WL(phy, "chanspec", p));
        WARN_ON(!WL(phy, "radio", rconf->enabled ? "on" : "off"));
        WARN_ON(!WL(phy, rconf->enabled ? "up" : "down"));
    }

    if (rchanged->ht_mode)
        WARN_ON(!WL(phy, "obss_coex", !strcmp(rconf->ht_mode, "HT2040") ? "1" : "0"));

    if ((rchanged->channel || rchanged->center_freq0_chan || rchanged->ht_mode) &&
            rconf->channel_exists && rconf->ht_mode_exists)
        WARN_ON(!bcmwl_radio_channel_set(phy,
                                         rconf->channel,
                                         rconf->center_freq0_chan_exists ? rconf->center_freq0_chan : 0,
                                         rconf->ht_mode));

    if (rchanged->bcn_int) {
        bcmwl_radio_set_bcn_int(phy, rconf->bcn_int);
    }

    if (rchanged->country) {
        WARN_ON(!WL(phy, "down"));
        WARN_ON(!WL(phy, "country", rconf->country));
        if (rconf->enabled)
            WARN_ON(!WL(phy, "up"));
    }

    if (rchanged->fallback_parents)
        bcmwl_radio_fallback_parents_set(phy, rconf);

    if (rchanged->dfs_demo) {
        WARN_ON(!WL(phy, "radar", rconf->dfs_demo ? "0" : "1"));
        WARN_ON(!WL(phy, "dfs_preism", rconf->dfs_demo ? "0" : "-1"));
    }

    if (rchanged->zero_wait_dfs && strlen(rconf->zero_wait_dfs))
        NVS(phy, "zero_wait_dfs", rconf->zero_wait_dfs);

    if (rchanged->tx_chainmask)
        WARN_ON(!WL(phy, "txchain", strfmta("%d", rconf->tx_chainmask)));

    if (rchanged->tx_power)
        WARN_ON(!WL(phy, "txpwr1", strfmta("%d", rconf->tx_power ?: -1)));

    evx_debounce_call(bcmwl_radio_state_report, rconf->if_name);
    return true;
}

int bcmwl_radio_max_vifs(const char *phy)
{
    return atoi(WL(phy, "bssmax") ?: "1");
}

int bcmwl_radio_count(void)
{
    glob_t g;
    size_t i;
    int n = 0;

    if (WARN_ON(glob("/sys/class/net/wl*", 0, NULL, &g)))
        return -1;
    for (i=0; i<g.gl_pathc; i++)
        if (bcmwl_is_phy(basename(g.gl_pathv[i])))
            n++;
    return n;
}

#define BCMWL_RADIO_DONGLE_NOT_OPERATIONAL "wl driver adapter not found"

bool bcmwl_radio_adapter_is_operational(const char *radio)
{
    const char *q;
    if (WARN_ON(!(q = WL(radio, "status"))))
        return false;
    if (strstr(q, BCMWL_RADIO_DONGLE_NOT_OPERATIONAL))
        return false;
    return true;
}
