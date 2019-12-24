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

#include "target.h"
#include "log.h"
#include "schema.h"
#include "const.h"
#include "util.h"
#include "evx_debounce_call.h"
#include "bcmwl.h"
#include "bcmwl_nvram.h"
#include "bcmwl_debounce.h"

#include "bcmutil.h"


#define PLUME_CSA_MODE        0     // Does not block Tx during CSA
#define PLUME_CSA_COUNT       15    // General value used by Plume

/**
 * Data maps
 */

static c_item_t g_map_band[] = {
    C_ITEM_STR_STR("a",     "5G"),
    C_ITEM_STR_STR("b",     "2.4G")
};

static c_item_t g_map_ht_mode[] = {
    C_ITEM_STR(20,          "HT40"),
    C_ITEM_STR(2040,        "HT2040"),
    C_ITEM_STR(40,          "HT40"),
    C_ITEM_STR(80,          "HT80")
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
    return "2.4G";
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

bool bcmwl_radio_is_dhd(const char *ifname)
{
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

static const char* bcmwl_radio_get_hwmode(const char *dphy)
{
    const char *p;
    switch (((p = strexa("wlctl", "-i", dphy, "bands")) ?: "")[0]) {
        case 'a': return "11ac";
        case 'b': return "11n";
    }
    LOGW("%s: unknown band '%s'", dphy, p);
    return NULL;
}

static const char* bcmwl_radio_get_hwname(const char *dphy)
{
    static const char *hwnames[] = {
        "0xaa52", "bcm4360",
        "0xaa90", "bcm4366",
        "0xd145", "bcm47189",
        "0x6362", "bcm2057",
        "0x4360", "bcm4360",
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

// FIXME: Remove the following function. It was made obsolete with bcmwl_radio_get_bands().
bool bcmwl_radio_band_get(const char *phyname, char *band, ssize_t band_len)
{
    FILE *fp;
    char cmd[512];
    char buf[512];
    bool success = false;

    snprintf(cmd, sizeof(cmd), "wlctl -i %s bands", phyname);

    fp = popen(cmd, "r");
    if (fp && fgets(buf, sizeof(buf), fp))
    {
        /* If board is misconfigured it might return "b a".
         * Pick the first entry only. The subsequent
         * strscpy() will copy just 1 letter.  This should
         * work for 99% boards because we almost never see
         * dual-band radios in consumer wifi routers. If we
         * do, we can fix that later.
         */
        buf[1] = 0;
        if (buf[0] == 'a' || buf[0] == 'b')
        {
            // Valid bands: a = 5G, b = 2.4G
            success = strscpy(band, strchomp(buf, " \t\r\n"), band_len) > 0;
        }
    }

    if (fp)
        pclose(fp);

    return success;
}

void bcmwl_radio_chanspec_extract(const char *chanspec, int *chan, int *width)
{
    /* Example chanspecs:
     * 1 (0x1801)
     * 1l (0x1803)
     * 11u (0x1909)
     * 44/80 (0xe22a)
     */
    char *buf = strdupa(chanspec);
    char *str = strsep(&buf, " ");
    const char *c, *w;;
    if (strstr(str, "l") || strstr(str, "u")) {
        *chan = atoi(str);
        *width = 40;
    }
    else if ((c = strsep(&str, "/")) && (w = strsep(&str, ""))) {
        *chan = atoi(c);
        *width = atoi(w);
    }
    else {
        *chan = atoi(chanspec);
        *width = 20;
        WARN_ON(*chan == 0);
    }
}

bool bcmwl_radio_channel_get(const char *phyname, int *channel)
{
    char *buf;
    char *line;
    const char *magic = "target channel";

    // Example output of "wlctl -i wlX channel":
    //  > No scan in progress.
    //  > current mac channel     42
    //  > target channel  42
    if ((buf = WL(phyname, "channel")))
    {
        while ((line = strsep(&buf, "\r\n")))
        {
            if (strstr(line, magic) == line)
            {
                *channel = atoi(line + strlen(magic));
                return true;
            }
        }
    }

    return false;
}

bool bcmwl_radio_chanspec_get(const char *phyname,
                              int *channel,
                              int *ht_mode)
{
    char *buf;
    char *tok;

    // Example output of "wlctl -i wlx chanspec":
    //  > 1 (0x1001)
    //  > 44/80 (0xe22a)
    if ((buf = WL(phyname, "chanspec")) && (tok = strsep(&buf, " ")))
    {
        if (strstr(tok, "/"))
        {
            *channel = atoi(strsep(&tok, "/"));
            *ht_mode = atoi(tok);
        }
        else
        {
            *channel = atoi(tok);
            *ht_mode = 20;
        }
        return true;
    }

    return false;
}

bool bcmwl_radio_csa(const char *phyname,
                     int csa_mode,
                     int csa_count,
                     int channel,
                     const char *ht_mode)
{
    bool success = true;

    // Before doing CSA we are also changing channel spec. So that
    // channel change is presistent over interface restarts.
    success = success && util_wlctl_fmt("-i %s chanspec %d/%d",
                                        phyname,
                                        channel,
                                        bcmwl_radio_ht_mode_to_int(ht_mode));

    // Do the CSA
    success = success && util_wlctl_fmt("-i %s csa %d %d %d/%d",
                                        phyname,
                                        csa_mode,
                                        csa_count,
                                        channel,
                                        bcmwl_radio_ht_mode_to_int(ht_mode));
    return success;
}

bool bcmwl_radio_create(const struct schema_Wifi_Radio_Config *rconfig)
{
    // Currently not supported
    return false;
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

bool bcmwl_radio_get_chanspec(const char *phy, int *chan, int *width)
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
    bcmwl_radio_chanspec_extract(q, chan, width);
    return true;
}

static char* bcmwl_radio_chanspec_prep(const char *phy, int channel, const char *ht_mode)
{
    int bw = atoi(strpbrk(ht_mode, "1234567890") ?: "");
    char *i, *p;

    switch (bw) {
        default:
            /* fall through */
        case 20:
            return strfmt("%d", channel);
        case 2040:
            /*
             * This is a special case where obss_coex is enabled to
             * juggle between HT20 and HT40 so the upper limit of the
             * bandwidth should be used here.
             */
            bw = 40;
            /* fall through */
        case 40:
            for (p = WL(phy, "chanspecs"); (i = strsep(&p, "\r\n")); )
                if ((i = strsep(&i, " ")))
                    if (strstr(i, "l") || strstr(i, "u"))
                        if (atoi(i) == channel)
                            return strdup(i);
            return NULL;
        case 80:
            return strfmt("%d/%d", channel, bw);
    }
    return NULL;
}

/**
 * Returns a malloc()-ed string with space-separated
 * interfaces names that are AP interfaces.
 */
static char* bcmwl_radio_get_vifs(const char *phy)
{
    struct dirent *p;
    char *vifs = strdupa("");
    DIR *d;

    if (WARN_ON(!(d = opendir("/sys/class/net"))))
        return vifs;

    while ((p = readdir(d)))
        if (strstr(p->d_name, phy) == p->d_name)
            if (!bcmwl_vap_is_sta(p->d_name))
                vifs = strchomp(strfmta("%s %s", p->d_name, vifs), " ");

    closedir(d);
    return strdup(vifs);
}

bool bcmwl_radio_channel_set(const char *phy, int channel, const char *ht_mode)
{
    const char *chanspec = strdupafree(bcmwl_radio_chanspec_prep(phy, channel, ht_mode)) ?: "";
    const char *current;
    struct dirent *p;
    char *apvifs = strdupafree(bcmwl_radio_get_vifs(phy));
    char *apvif;
    int c, cw;
    DIR *d;

    if (WARN_ON(!chanspec))
        return false;

    if (channel) {
        WARN_ON(!NVS(phy, "chanspec", chanspec));
        WARN_ON(!NVS(phy, "channel", strfmta("%d", channel)));
    }

    if (!channel)
        return true;
    if (!strlen(ht_mode))
        return true;
    if (!bcmwl_radio_get_chanspec(phy, &c, &cw))
        return true;
    current = strdupafree(bcmwl_radio_chanspec_prep(phy, c, strfmta("HT%d", cw)) ?: "x");
    if (!strcmp(chanspec, current))
        return true;
    if (WARN_ON(strlen(chanspec) == 0))
        return false;
    if ((apvif = strdupa(apvifs ?: "")) &&
        (apvif = strsep(&apvif, " ")) &&
        (strlen(apvif) > 0)) {
        if (WARN_ON(!WL(apvif, "csa", "0", "15", chanspec)))
            return false;
    } else {
        LOGI("%s: no ap vifs: skipping csa, will set chanspec only", phy);
    }
    if (WARN_ON(!(d = opendir("/sys/class/net"))))
        return false;
    while ((p = readdir(d))) {
        if (strstr(p->d_name, phy) != p->d_name)
            continue;
        WARN_ON(!WL(p->d_name, "chanspec", chanspec));
    }
    closedir(d);

    LOGI("%s: switching to channel %s", phy, chanspec);
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
    int allowed_40[] = { 36, 44, 52, 60, 100, 108, 116, 124, 132, 149, 157, 184, 192 };
    int allowed_80[] = { 36, 52, 100, 116, 132, 149 };
    unsigned int i;
    int c, cw;
    char band[32];
    int num_channels = 0;

    if (!bcmwl_radio_band_get(phyname, band, sizeof(band)))
        return num_channels;

    /* Currently this is specyfic only for 5GHz */
    if (band[0] != 'a')
        return num_channels;

    if (!bcmwl_radio_get_chanspec(phyname, &c, &cw))
        return num_channels;

    if (size < (cw/20))
        return num_channels;

    switch (cw) {
        case 20:
            chan[0] = c;
            num_channels = 1;
            break;
        case 40:
            if (c < 36 || c > 196)
                return num_channels;

            for (i = 0; i < ARRAY_SIZE(allowed_40); i++) {
                if (c <= allowed_40[i] + 4)
                    break;
            }

            chan[0] = allowed_40[i];
            chan[1] = allowed_40[i] + 4;
            num_channels = 2;
            break;
        case 80:
            if (c < 36 || c > 161)
                return num_channels;

            for (i = 0; i < ARRAY_SIZE(allowed_80); i++) {
                if (c <= allowed_80[i] + 12)
                    break;
            }

            chan[0] = allowed_80[i];
            chan[1] = allowed_80[i] + 4;
            chan[2] = allowed_80[i] + 8;
            chan[3] = allowed_80[i] + 12;
            num_channels = 4;
            break;
        default:
            break;
    }

    return num_channels;
}

bool bcmwl_radio_state(const char *phyname,
                       struct schema_Wifi_Radio_State *rstate)
{
    const char *p;
    char *q;
    int channel = 0;
    int ht_mode = 0;
    char    band[32];

    memset(rstate, 0, sizeof(*rstate));
    schema_Wifi_Radio_State_mark_all_present(rstate);
    rstate->vif_states_present = false;
    rstate->radio_config_present = false;
    rstate->channel_sync_present = false;
    rstate->channel_mode_present = false;
    rstate->_partial_update = true;

    // Common
    SCHEMA_SET_STR(rstate->if_name,         phyname);

    if (bcmwl_radio_get_chanspec(phyname, &channel, &ht_mode)) {
        if (atoi(WL(phyname, "obss_coex") ?: "0") == 1)
            ht_mode = 2040;
        SCHEMA_SET_INT(rstate->channel, channel);
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
    if ((p = WL(phyname, "bi")))
        SCHEMA_SET_INT(rstate->bcn_int, atoi(p));
    if ((q = WL(phyname, "txchain")) && (q = strsep(&q, " ")))
        SCHEMA_SET_INT(rstate->tx_chainmask, atoi(q));
    if ((q = WL(phyname, "txpwr")) && (q = strsep(&q, " ")))
        SCHEMA_SET_INT(rstate->tx_power, atoi(q));

    // Frequency band
    if (bcmwl_radio_band_get(phyname, band, sizeof(band)))
    {
        SCHEMA_SET_STR(rstate->freq_band,   bcmwl_radio_band_to_str(band));
    }

    // Channels
    if ((q = WL(phyname, "channels")))
    {
        while ((p = strsep(&q, " ")))
        {
            SCHEMA_VAL_APPEND_INT(rstate->allowed_channels, atoi(p));
        }
    }

    bcmwl_radio_dfs_demo_get(phyname, rstate);
    bcmwl_radio_fallback_parents_get(phyname, rstate);
    bcmwl_radio_radar_get(phyname, rstate);
    bcmwl_radio_channels_get(phyname, rstate);

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

bool bcmwl_radio_update(const struct schema_Wifi_Radio_Config *rconfig,
                        const struct schema_Wifi_Radio_Config_flags *rchanged)
{
    bool success = true;

    // Note that currently we only support channel and ht_mode changes.
    // Funtionality needs to be extended in the future.

    if (rchanged->channel || rchanged->ht_mode)
    {
        // Do CSA
        if (false == bcmwl_radio_csa(rconfig->if_name,
                                     PLUME_CSA_MODE,
                                     PLUME_CSA_COUNT,
                                     rconfig->channel,
                                     rconfig->ht_mode))
        {
            success = false;
            LOGE("Radio CSA failed :: radio=%s channel=%d ht_mode=%s",
                 rconfig->if_name, rconfig->channel, rconfig->ht_mode);
        } else {
            LOGI("Radio CSA success :: radio=%s channel=%d ht_mode=%s",
                 rconfig->if_name, rconfig->channel, rconfig->ht_mode);
        }
    }

    return success;
}

/* FIXME: The following is intended to deprecate and
 * eventually replace bcmwl_radio_update().
 */
bool bcmwl_radio_update2(const struct schema_Wifi_Radio_Config *rconf,
                         const struct schema_Wifi_Radio_Config_flags *rchanged)
{
    const char *phy = rconf->if_name;
    char *p;

    if (WARN_ON(strstr(phy, ".")))
        return false;

    if (rchanged->enabled) {
        if ((p = WL(phy, "isup")) && atoi(p) == 0) {
            if (strstr(rconf->freq_band, "2.4G"))
                WARN_ON(!WL(phy, "bw_cap", "2g", "0x1"));
            if (strstr(rconf->freq_band, "5G"))
                WARN_ON(!WL(phy, "bw_cap", "5g", "0xff"));
        }
        if ((p = WL(phy, "chanspec")) && (p = strsep(&p, " ")))
            WARN_ON(!WL(phy, "chanspec", p));
        WARN_ON(!WL(phy, "radio", rconf->enabled ? "on" : "off"));
        WARN_ON(!WL(phy, rconf->enabled ? "up" : "down"));
    }

    if (rchanged->ht_mode)
        WARN_ON(!WL(phy, "obss_coex", !strcmp(rconf->ht_mode, "HT2040") ? "1" : "0"));

    if ((rchanged->channel || rchanged->ht_mode) && rconf->channel_exists && rconf->ht_mode_exists) {
        if (WARN_ON(!bcmwl_radio_channel_set(phy, rconf->channel, strstr(rconf->freq_band, "2.4G") ? "HT20" : rconf->ht_mode)))
            return false;
    }

    if (rchanged->bcn_int)
        if (!(p = WL(phy, "bi", strfmta("%d", rconf->bcn_int))) || strlen(p))
            LOGW("%s: failed to set beacn interval: %s", phy, p ?: strerror(errno));

    if (rchanged->country)
        WARN_ON(!WL(phy, "country", rconf->country));

    if (rchanged->fallback_parents)
        bcmwl_radio_fallback_parents_set(phy, rconf);

    if (rchanged->dfs_demo)
        bcmwl_radio_dfs_demo_set(phy, rconf);

    if (rchanged->tx_chainmask)
        WARN_ON(!WL(phy, "txchain", strfmta("%d", rconf->tx_chainmask)));

    if (rchanged->tx_power)
        WARN_ON(!WL(phy, "txpwr1", strfmta("%d", rconf->tx_power ?: -1)));

    bcmwl_radio_state_report(rconf->if_name);
    return true;
}

int bcmwl_radio_max_vifs(const char *phy)
{
    const char *p;
    size_t i;
    int n = 16;
    glob_t g;

    (void)phy;

    if (WARN_ON(glob("/sys/class/net/wl*", 0, NULL, &g)))
        return 1;

    for (i=0; i<g.gl_pathc; i++)
        if ((p = WL(basename(g.gl_pathv[i]), "bssmax")))
            if (atoi(p) < n)
                n = atoi(p);

    globfree(&g);
    return n;
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
