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
#include <assert.h>
#include <ev.h>
#include <sys/types.h>
#include <dirent.h>

/* internal */
#include <log.h>
#include <ovsdb.h>
#include <target.h>

/* unit */
#include <bcmwl.h>
#include <wl80211_client.h>

#define UDP(mbps, time, psr) (psr * mbps * time / 100) * 90 / 100 /* roughly 10% mac overhead */
#define TCP(mbps, time, psr) (psr * mbps * time / 100) * 75 / 100 /* roughly 10% mac + 15% tcp-ack overhead */

struct ctx {
    unsigned long tx;
    unsigned long rx;
    unsigned long n;
};

static void
sta_cb(const char *ifname,
       const char *mac_octet,
       const struct bcmwl_sta_rate *rxrate,
       void *arg)
{
    struct ctx *ctx = arg;
    struct bcmwl_sta_rate txrate;
    char macaddr[18];

    snprintf(macaddr, sizeof(macaddr), "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
            mac_octet[0], mac_octet[1], mac_octet[2],
            mac_octet[3], mac_octet[4], mac_octet[5]);

    if (bcmwl_sta_get_tx_avg_rate(ifname, macaddr, &txrate) < 0)
        return;

    fprintf(stdout, "%8s %16s rx %4.0f/%4.0f tx %4.0f/%4.0f rxpsr %.2f txpsr %.2f txpkts %6.0f rxpkts %6.0f rxbusy %3lu%% txbusy %3lu%% -> rxudp %4.0f/%4.0f rxtcp %4.0f/%4.0f txudp %4.0f/%4.0f txtcp %4.0f/%4.0f\n",
            ifname, macaddr,
            rxrate->mbps_perceived,
            rxrate->mbps_capacity,
            txrate.mbps_perceived,
            txrate.mbps_capacity,
            rxrate->psr, txrate.psr,
            txrate.tried, rxrate->tried,
            ctx->rx, ctx->tx,
            UDP(rxrate->mbps_perceived, ctx->rx, rxrate->psr),
            UDP(rxrate->mbps_capacity, ctx->rx, rxrate->psr),
            TCP(rxrate->mbps_perceived, ctx->rx, rxrate->psr),
            TCP(rxrate->mbps_capacity, ctx->rx, rxrate->psr),
            UDP(txrate.mbps_perceived, ctx->tx, txrate.psr),
            UDP(txrate.mbps_capacity, ctx->tx, txrate.psr),
            TCP(txrate.mbps_perceived, ctx->tx, txrate.psr),
            TCP(txrate.mbps_capacity, ctx->tx, txrate.psr));

    ctx->n++;
}

const char *
mac2buf(const char *str)
{
    static char buf[6];
    sscanf(str, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
            &buf[0], &buf[1], &buf[2], &buf[3], &buf[4], &buf[5]);
    return buf;
}

int
main(int argc, const char **argv)
{
    const struct bcmwl_sta_rate zerorxrate = {0};
    struct ctx ctx;
    const char *macaddr;
    struct dirent *d;
    char *assoc;
    char *chan;
    DIR *dir;

    for (;;) {
        dir = opendir("/sys/class/net");
        assert(dir);
        ctx.n = 0;
        while ((d = readdir(dir))) {
            if (strstr(d->d_name, "wl") != d->d_name) /* naive but sufficient */
                continue;

            chan = WL(d->d_name, "chanim_stats");
            if (!chan)
                continue;

            chan = strstr(chan, "0x");
            if (!chan)
                continue;

            strtok(chan, "\t"); /* chanspec */
            ctx.tx = atoi(strtok(NULL, "\t") ?: "");
            ctx.rx = atoi(strtok(NULL, "\t") ?: "");

            if (bcmwl_sta_get_rx_avg_rate(d->d_name, sta_cb, &ctx) == 0)
                continue;

            /* rx_report is used implicitly to iterate over stations
             * but if it fails then fall back to manual iteration
             */

            assoc = WL(d->d_name, "assoclist");
            if (!assoc)
                continue;

            while ((macaddr = strsep(&assoc, "\r\n\t ")))
                if (strstr(macaddr, ":")) /* naive but sufficient */
                    sta_cb(d->d_name, mac2buf(macaddr), &zerorxrate, &ctx);
        }
        closedir(dir);
        sleep(1);
        if (ctx.n > 1)
            fprintf(stdout, "---\n");
    }

    return 0;
}
