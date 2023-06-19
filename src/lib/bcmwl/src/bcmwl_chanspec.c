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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>

#include "log.h"
#include "memutil.h"
#include "os.h"
#include "bcmwl.h"
#include "bcmwl_priv.h"
#include <wlioctl.h>
#include <dhdioctl.h>
#include "bcmwl_ioctl.h"

#define MODULE_ID LOG_MODULE_ID_WL

#define BCMWL_CHANSPEC_MAX_RADIOS 4
#define BCMWL_CHANSPEC_IFNAME_LEN 16

typedef struct
{
    char ifname[BCMWL_CHANSPEC_IFNAME_LEN];
    int num;
    bcmwl_chanspec_t *cs_table;
} bcmwl_chanspec_table_t;

static bcmwl_chanspec_table_t bcmwl_chanspec_table[BCMWL_CHANSPEC_MAX_RADIOS];
static int bcmwl_chanspec_num;

/* sample chanspecs:
36 (0xd024)
36/80 (0xe02a)
36l (0xd826)
40 (0xd028)
40/80 (0xe12a)
40u (0xd926)
*/

bool bcmwl_chanspec_parse(char *str, bcmwl_chanspec_t *cs)
{
    int r;
    int n;
    char *p;

    r = sscanf(str, "%d%n", &cs->channel, &n);
    if (r != 1) return false;
    p = strchr(str, '(');
    if (!p) return false;
    r = sscanf(p+1, "%i", &cs->chanspec);
    if (r != 1) return false;
    if (!cs->channel || !cs->chanspec) return false;
    switch (str[n]) {
        case ' ':
            cs->bandwidth = 20;
            cs->sideband = 0;
            break;
        case 'l':
            cs->bandwidth = 40;
            cs->sideband = -1;
            break;
        case 'u':
            cs->bandwidth = 40;
            cs->sideband = 1;
            break;
        case '/': // "/80"
            cs->bandwidth = atoi(str+n+1);
            cs->sideband = 0;
            break;
        default:
            // unknown format
            return false;
    }
    //TRACE("Parsed '%s' %x %d %d %d", str, cs->chanspec, cs->channel, cs->sideband, cs->bandwidth);
    return true;
}

bool bcmwl_chanspec_load(char *ifname, bcmwl_chanspec_table_t *t)
{
    char *buf = NULL;
    bool result;
    int count;
    char *p, *nl;
    bcmwl_chanspec_t *cs;
    int i;

    result = os_cmd_exec(&buf, "wl -i %s chanspecs", ifname);
    if (!result) {
        if (buf) FREE(buf);
        return false;
    }

    // count number of lines
    count = 0;
    p = buf;
    while ((nl = strchr(p, '\n'))) {
        p = nl + 1;
        count++;
    }
    // alloc table
    cs = CALLOC(count, sizeof(*cs));
    // parse lines
    i = 0;
    p = buf;
    while ((nl = strchr(p, '\n'))) {
        *nl = 0;
        if (!bcmwl_chanspec_parse(p, &cs[i])) {
            break;
        }
        p = nl + 1;
        i++;
    }
    FREE(buf);
    if (i == 0) {
        FREE(cs);
        return false;
    }
    t->cs_table = cs;
    t->num = i;
    STRSCPY(t->ifname, ifname);
    TRACE("chanspecs %s: %d", ifname, t->num);

    return true;
}

bcmwl_chanspec_table_t* bcmwl_chanspec_get_table(char *ifname)
{
    bcmwl_chanspec_table_t *t;
    int i;
    if (!bcmwl_is_phy(ifname)) {
        LOGE("%s: not a phy: %s", __func__, ifname);
        return NULL;
    }
    for (i = 0; i < bcmwl_chanspec_num; i++) {
        t = &bcmwl_chanspec_table[i];
        if (!strcmp(ifname, t->ifname)) {
            return t;
        }
    }
    if (bcmwl_chanspec_num >= BCMWL_CHANSPEC_MAX_RADIOS) {
        return NULL;
    }
    t = &bcmwl_chanspec_table[bcmwl_chanspec_num];
    if (!bcmwl_chanspec_load(ifname, t)) {
        return NULL;
    }
    bcmwl_chanspec_num++;
    return t;
}

/* get chanspec info
 * input:
 *   ifname (wl0, wl1)
 *   chanspec (eg 0x1803)
 * output:
 *   channel (1-14, 36-216)
 *   bandwidth (20,40,80)
 *   sideband (for 40bw: -1=lower 0=none 1=upper)
 */
bcmwl_chanspec_t* bcmwl_chanspec_get(char *ifname, int chanspec)
{
    bcmwl_chanspec_table_t *t;
    bcmwl_chanspec_t *cs;
    int i;
    t = bcmwl_chanspec_get_table(ifname);
    if (WARN_ON(!t))
        return NULL;
    for (i = 0; i < t->num; i++) {
        cs = &t->cs_table[i];
        if (chanspec == cs->chanspec) {
            return cs;
        }
    }
    return NULL;
}

int bcmwl_chanspec_get_primary(const int cs)
{
    int chan = CHSPEC_CHANNEL(cs);
    int bw = CHSPEC_BW(cs);
    int sb = CHSPEC_CTL_SB(cs);

    switch (bw) {
        case WL_CHANSPEC_BW_20: return chan;
        case WL_CHANSPEC_BW_40:
            switch (sb) {
                case WL_CHANSPEC_CTL_SB_L: return chan - 2;
                case WL_CHANSPEC_CTL_SB_U: return chan + 2;
            }
            return -1;
        case WL_CHANSPEC_BW_80:
            switch (sb) {
                case WL_CHANSPEC_CTL_SB_LL: return chan - 6;
                case WL_CHANSPEC_CTL_SB_LU: return chan - 2;
                case WL_CHANSPEC_CTL_SB_UL: return chan + 2;
                case WL_CHANSPEC_CTL_SB_UU: return chan + 6;
            }
            return -1;
        case WL_CHANSPEC_BW_160:
            switch (sb) {
                case WL_CHANSPEC_CTL_SB_LLL: return chan - 14;
                case WL_CHANSPEC_CTL_SB_LLU: return chan - 10;
                case WL_CHANSPEC_CTL_SB_LUL: return chan - 6;
                case WL_CHANSPEC_CTL_SB_LUU: return chan - 2;
                case WL_CHANSPEC_CTL_SB_ULL: return chan + 2;
                case WL_CHANSPEC_CTL_SB_ULU: return chan + 6;
                case WL_CHANSPEC_CTL_SB_UUL: return chan + 10;
                case WL_CHANSPEC_CTL_SB_UUU: return chan + 14;
            }
            return -1;
#ifdef WL_CHANSPEC_BW_320
        case WL_CHANSPEC_BW_320:
            switch (sb) {
                case WL_CHANSPEC_CTL_SB_LLLLL: return chan - 30;
                case WL_CHANSPEC_CTL_SB_LLLLU: return chan - 26;
                case WL_CHANSPEC_CTL_SB_LLLUL: return chan - 22;
                case WL_CHANSPEC_CTL_SB_LLLUU: return chan - 18;
                case WL_CHANSPEC_CTL_SB_LLULL: return chan - 14;
                case WL_CHANSPEC_CTL_SB_LLULU: return chan - 10;
                case WL_CHANSPEC_CTL_SB_LLUUL: return chan - 6;
                case WL_CHANSPEC_CTL_SB_LLUUU: return chan - 2;
                case WL_CHANSPEC_CTL_SB_LULLL: return chan + 2;
                case WL_CHANSPEC_CTL_SB_LULLU: return chan + 6;
                case WL_CHANSPEC_CTL_SB_LULUL: return chan + 10;
                case WL_CHANSPEC_CTL_SB_LULUU: return chan + 14;
                case WL_CHANSPEC_CTL_SB_LUULL: return chan + 18;
                case WL_CHANSPEC_CTL_SB_LUULU: return chan + 22;
                case WL_CHANSPEC_CTL_SB_LUUUL: return chan + 26;
                case WL_CHANSPEC_CTL_SB_LUUUU: return chan + 30;
            }
            return -1;
#endif
    }

    return -1;
}

int bcmwl_chanspec_get_bw_mhz(const int cs)
{
    switch (CHSPEC_BW(cs)) {
        case WL_CHANSPEC_BW_20: return 20;
        case WL_CHANSPEC_BW_40: return 40;
        case WL_CHANSPEC_BW_80: return 80;
        case WL_CHANSPEC_BW_160: return 160;
#ifdef WL_CHANSPEC_BW_320
        case WL_CHANSPEC_BW_320: return 320;
#endif
    }

    return 0;
}

int bcmwl_chanspec_get_center_freq(const int cs)
{
    int c = CHSPEC_CHANNEL(cs);
    switch (CHSPEC_BAND(cs)) {
        case WL_CHANSPEC_BAND_2G:
            if (c >= 1 && c <= 14)
                return 2407 + (5 * c);
            break;
        case WL_CHANSPEC_BAND_5G:
            if (c >= 36 && c <= 181)
                return 5000 + (5 * c);
            break;
#ifdef WL_CHANSPEC_BAND_6G
        case WL_CHANSPEC_BAND_6G:
            if (c >= 1 && c <= 233)
                return 5950 + (5 * c);
#endif
    }
    return 0;
}

bool bcmwl_chanspec_is_valid(const char *phy, const int chanspec)
{
    const struct bcmwl_ioctl_num_conv *conv;
    chanspec_t cs;
    int i;
    struct {
        int chanspec;
        char cc_abbrev[4];
        int count;
    } __attribute__((packed)) in = {0};
    struct {
        int count;
        int list[512];
    } __attribute__((packed)) out = {0};
    const int max = ARRAY_SIZE(out.list);

    LOGT("%s: chanspec %x validation", phy, chanspec);

    if (WARN_ON(!(conv = bcmwl_ioctl_lookup_num_conv(phy))))
        return false;

    in.count = conv->dtoh32(max);

    if (WARN_ON(!bcmwl_GIOV(phy, "chanspecs", &in, &out)))
        return false;

    out.count = conv->dtoh32(out.count);

    if (WARN_ON(out.count > max))
        out.count = max;

    for (i = 0; i < out.count; i++) {
        cs = (chanspec_t ) conv->dtoh32(out.list[i]);
        if (cs == chanspec)
            return true;
    }
    return false;
}
