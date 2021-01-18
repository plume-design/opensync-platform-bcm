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

#include "log.h"
#include "bcmwl.h"
#include "bcmwl_ioctl.h"
#include "bcmwl_cim.h"
#include <bcmutils.h>

static struct bcmwl_cim *
bcmwl_cim_lookup(struct bcmwl_cim *arr,
                 size_t len,
                 int channel)
{
    size_t i;

    for (i = 0; i < len; i++)
        if (arr[i].channel == channel)
            return &arr[i];

    for (i = 0; i < len; i++)
        if (arr[i].channel == 0)
            return &arr[i];

    return NULL;
}

static bool
bcmwl_cim_parse_v3_us_v2(struct bcmwl_cim *arr,
                         size_t len,
                         const void *iovbuf,
                         int version,
                         const struct bcmwl_ioctl_num_conv *conv)
{
#ifdef WL_CHANIM_STATS_US_VERSION_2
    const wl_chanim_stats_us_v2_t *v2 = iovbuf;
    const chanim_stats_us_v2_t *sample;
    struct bcmwl_cim *cim;
    int chan;
    int ver;
    int cnt;
    int i;

    if (WARN_ON(!conv)) return false;
    if (version != 3) return false;

    ver = conv->dtoh32(v2->version);
    cnt = conv->dtoh32(v2->count);

    if (ver != 2) return false;

    for (i = 0; i < cnt; i++) {
        sample = &v2->stats_us_v2[i];

        chan = bcmwl_chanspec_get_primary(conv->dtoh16(sample->chanspec));
        if (WARN_ON(chan < 0)) continue;

        cim = bcmwl_cim_lookup(arr, len, chan);
        if (WARN_ON(!cim)) continue;

        cim->channel = chan;
        cim->usec.total = conv->dtoh64(sample->total_tm);
        cim->usec.tx = conv->dtoh64(sample->ccastats_us[CCASTATS_TXDUR]);
        cim->usec.rx = conv->dtoh64(sample->ccastats_us[CCASTATS_OBSS])
                     + conv->dtoh64(sample->ccastats_us[CCASTATS_INBSS]);
        cim->usec.rx_self = conv->dtoh64(sample->ccastats_us[CCASTATS_INBSS]);
        cim->usec.busy = conv->dtoh64(sample->busy_tm)
                       + conv->dtoh64(sample->ccastats_us[CCASTATS_TXDUR]);

        LOGT("%s: %d: usec 64bit: total=%lu tx=%lu rx=%lu self=%lu busy=%lu",
             __func__,
             cim->channel,
             cim->usec.total,
             cim->usec.tx,
             cim->usec.rx,
             cim->usec.rx_self,
             cim->usec.busy);
    }

    return true;
#else
    return false;
#endif
}

static bool
bcmwl_cim_parse_v3_us_v1(struct bcmwl_cim *arr,
                         size_t len,
                         const void *iovbuf,
                         int version,
                         const struct bcmwl_ioctl_num_conv *conv)
{
#ifdef WL_CHANIM_STATS_US_VERSION_1
    const wl_chanim_stats_us_v1_t *v1 = iovbuf;
    const chanim_stats_us_v1_t *sample;
    struct bcmwl_cim *cim;
    int chan;
    int ver;
    int cnt;
    int i;

    if (WARN_ON(!conv)) return false;
    if (version != 3) return false;

    ver = conv->dtoh32(v1->version);
    cnt = conv->dtoh32(v1->count);

    if (ver != 1) return false;

    for (i = 0; i < cnt; i++) {
        sample = &v1->stats_us_v1[i];

        chan = bcmwl_chanspec_get_primary(conv->dtoh16(sample->chanspec));
        if (WARN_ON(chan < 0)) continue;

        cim = bcmwl_cim_lookup(arr, len, chan);
        if (WARN_ON(!cim)) continue;

        cim->channel = chan;
        cim->usec.total = conv->dtoh32(sample->total_tm);
        cim->usec.tx = conv->dtoh32(sample->ccastats_us[CCASTATS_TXDUR]);
        cim->usec.rx = conv->dtoh32(sample->ccastats_us[CCASTATS_OBSS])
                     + conv->dtoh32(sample->ccastats_us[CCASTATS_INBSS]);
        cim->usec.rx_self = conv->dtoh32(sample->ccastats_us[CCASTATS_INBSS]);
        cim->usec.busy = conv->dtoh32(sample->busy_tm)
                       + conv->dtoh32(sample->ccastats_us[CCASTATS_TXDUR]);

        LOGT("%s: %d: usec 32bit cca: total=%lu tx=%lu rx=%lu self=%lu busy=%lu",
             __func__,
             cim->channel,
             cim->usec.total,
             cim->usec.tx,
             cim->usec.rx,
             cim->usec.rx_self,
             cim->usec.busy);
    }

    return true;
#elif WL_CHANIM_STATS_US_VERSION == 1
    /* Older driver doesn't define WL_CHANIM_STATS_US_VERSION_1 but
     * otherwise supports this ABI. However it does that through
     * slightly different naming (ie. before v2 was introduced at
     * which point the non-v2 was renamed to explicit v1).
     *
     * This could've been avoided if wlioctl.h was bundled with
     * opensync. However the code assumes it comes through sdk staging
     * include dir.
     */
    const wl_chanim_stats_us_t *v1 = iovbuf;
    const chanim_stats_us_t *sample;
    struct bcmwl_cim *cim;
    int chan;
    int ver;
    int cnt;
    int i;

    if (WARN_ON(!conv)) return false;
    if (version != 3) return false;

    ver = conv->dtoh32(v1->version);
    cnt = conv->dtoh32(v1->count);

    if (ver != 1) return false;

    for (i = 0; i < cnt; i++) {
        sample = &v1->stats_us[i];

        chan = bcmwl_chanspec_get_primary(conv->dtoh16(sample->chanspec));
        if (WARN_ON(chan < 0)) continue;

        cim = bcmwl_cim_lookup(arr, len, chan);
        if (WARN_ON(!cim)) continue;

        cim->channel = chan;
        cim->usec.total = conv->dtoh32(sample->total_tm);
        cim->usec.tx = conv->dtoh32(sample->ccastats_us[CCASTATS_TXDUR]);
        cim->usec.rx = conv->dtoh32(sample->ccastats_us[CCASTATS_OBSS])
                     + conv->dtoh32(sample->ccastats_us[CCASTATS_INBSS]);
        cim->usec.rx_self = conv->dtoh32(sample->ccastats_us[CCASTATS_INBSS]);
        cim->usec.busy = conv->dtoh32(sample->busy_tm)
                       + conv->dtoh32(sample->ccastats_us[CCASTATS_TXDUR]);

        LOGT("%s: %d: usec 32bit cca old: total=%lu tx=%lu rx=%lu self=%lu busy=%lu",
             __func__,
             cim->channel,
             cim->usec.total,
             cim->usec.tx,
             cim->usec.rx,
             cim->usec.rx_self,
             cim->usec.busy);
    }

    return true;
#else
    return false;
#endif
}

static bool
bcmwl_cim_parse_v2_us(struct bcmwl_cim *arr,
                      size_t len,
                      const void *iovbuf,
                      int version,
                      const struct bcmwl_ioctl_num_conv *conv)
{
#ifdef WL_CHANIM_STATS_VERSION_2
    const wl_chanim_stats_us_t *stats = iovbuf;
    const chanim_stats_us_t *sample;
    struct bcmwl_cim *cim;
    int chan;
    int cnt;
    int i;

    if (WARN_ON(!conv)) return false;
    if (version != 2) return false;

    cnt = conv->dtoh32(stats->count);

    for (i = 0; i < cnt; i++) {
        sample = &stats->stats_us[i];

        chan = bcmwl_chanspec_get_primary(conv->dtoh16(sample->chanspec));
        if (WARN_ON(chan < 0)) continue;

        cim = bcmwl_cim_lookup(arr, len, chan);
        if (WARN_ON(!cim)) continue;

        cim->channel = chan;
        cim->usec.total = conv->dtoh32(sample->total_tm);
        cim->usec.tx = conv->dtoh32(sample->tx_tm);
        cim->usec.rx = conv->dtoh32(sample->rx_obss)
                     + conv->dtoh32(sample->rx_bss);
        cim->usec.rx_self = conv->dtoh32(sample->rx_bss);
        cim->usec.busy = conv->dtoh32(sample->busy_tm)
                       + conv->dtoh32(sample->tx_tm);

        LOGT("%s: %d: usec 32bit: total=%lu tx=%lu rx=%lu self=%lu busy=%lu",
             __func__,
             cim->channel,
             cim->usec.total,
             cim->usec.tx,
             cim->usec.rx,
             cim->usec.rx_self,
             cim->usec.busy);
    }

    return true;
#else
    return false;
#endif
}

static bool
bcmwl_cim_parse(struct bcmwl_cim *arr,
                size_t len,
                const void *iovbuf,
                int version,
                const struct bcmwl_ioctl_num_conv *conv)
{
    const wl_chanim_stats_t *stats = iovbuf;
    const chanim_stats_t *sample;
    struct bcmwl_cim *cim;
    int chan;
    int ver;
    int cnt;
    int i;

    if (WARN_ON(!conv)) return false;

    ver = conv->dtoh32(stats->version);
    cnt = conv->dtoh32(stats->count);

    if (WARN_ON(ver != 2 && ver != 3)) return false;

    for (i = 0; i < cnt; i++) {
        sample = &stats->stats[i];

        chan = bcmwl_chanspec_get_primary(conv->dtoh16(sample->chanspec));
        if (WARN_ON(chan < 0)) continue;

        cim = bcmwl_cim_lookup(arr, len, chan);
        if (WARN_ON(!cim)) continue;

        cim->channel = chan;
        cim->nf = sample->bgnoise;
        cim->glitch = conv->dtoh32(sample->glitchcnt);
        cim->percent.timestamp = conv->dtoh32(sample->timestamp);
        cim->percent.tx = sample->ccastats[CCASTATS_TXDUR];
        cim->percent.rx = sample->ccastats[CCASTATS_OBSS]
                        + sample->ccastats[CCASTATS_INBSS];
        cim->percent.rx_self = sample->ccastats[CCASTATS_INBSS];
        cim->percent.busy = 100 - sample->ccastats[CCASTATS_TXOP];

        LOGT("%s: %d: percent: nf=%d glitch=%d ts=%lu tx=%lu rx=%lu self=%lu busy=%lu",
             __func__,
             cim->channel,
             cim->nf,
             cim->glitch,
             cim->percent.timestamp,
             cim->percent.tx,
             cim->percent.rx,
             cim->percent.rx_self,
             cim->percent.busy);
    }

    return true;
}

bool bcmwl_cim_get(const char *phy,
                   struct bcmwl_cim *arr,
                   const size_t len)
{
    const struct bcmwl_ioctl_num_conv *conv;
    const wl_chanim_stats_t *stats;
    wl_chanim_stats_t arg;
    char buf[WLC_IOCTL_MAXLEN];
    int ver;

    if (WARN_ON(!(conv = bcmwl_ioctl_lookup_num_conv(phy))))
        return false;

    memset(&arg, 0, sizeof(arg));
    arg.count = conv->dtoh32(WL_CHANIM_READ_VERSION);
    arg.buflen = conv->dtoh32(sizeof(arg));

    if (WARN_ON(!bcmwl_GIOV(phy, "chanim_stats", &arg, &buf)))
        return false;

    stats = (void *)buf;
    ver = conv->dtoh32(stats->version);

    LOGT("%s: %s: ver=%d", __func__, phy, ver);

    memset(&arg, 0, sizeof(arg));
    arg.count = conv->dtoh32(WL_CHANIM_COUNT_ALL);
    arg.buflen = sizeof(buf);
    arg.buflen -= WL_CHANIM_STATS_FIXED_LEN;
    arg.buflen = conv->dtoh32(arg.buflen);

    if (WARN_ON(!bcmwl_GIOV(phy, "chanim_stats", &arg, &buf)))
        return false;

    if (WARN_ON(!(bcmwl_cim_parse(arr, len, buf, ver, conv))))
        return false;

    memset(&arg, 0, sizeof(arg));
    arg.count = conv->dtoh32(WL_CHANIM_COUNT_ONE);
    arg.buflen = sizeof(buf);
    arg.buflen -= WL_CHANIM_STATS_FIXED_LEN;
    arg.buflen = conv->dtoh32(arg.buflen);

    if (WARN_ON(!bcmwl_GIOV(phy, "chanim_stats", &arg, &buf)))
        return false;

    if (WARN_ON(!(bcmwl_cim_parse(arr, len, buf, ver, conv))))
        return false;

    memset(&arg, 0, sizeof(arg));
    arg.count = conv->dtoh32(WL_CHANIM_COUNT_US_ALL);
    arg.buflen = sizeof(buf);
    arg.buflen -= WL_CHANIM_STATS_US_FIXED_LEN;
    arg.buflen = conv->dtoh32(arg.buflen);

    if (WARN_ON(!bcmwl_GIOV(phy, "chanim_stats", &arg, &buf)))
        return false;

    if (WARN_ON(!(bcmwl_cim_parse_v3_us_v2(arr, len, buf, ver, conv) ||
                  bcmwl_cim_parse_v3_us_v1(arr, len, buf, ver, conv) ||
                  bcmwl_cim_parse_v2_us(arr, len, buf, ver, conv))))
        return false;

    return true;
}
