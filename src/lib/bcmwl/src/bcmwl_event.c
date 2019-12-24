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

#include <arpa/inet.h>
#include <errno.h>
#include <ev.h>
#include <stdio.h>
#include <string.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <unistd.h>
#include <ctype.h>
#include <stdint.h>
#include <assert.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/file.h>
#include <linux/filter.h>

#include "os.h"

#include "ds.h"
#include "log.h"
#include "os_nif.h"
#include "os.h"
#include "target.h"
#include "evx_debounce_call.h"

#include "bcmwl.h"
#include "bcmwl_nvram.h"
#include "bcmwl_lan.h"
#include "bcmwl_roam.h"
#include "bcmwl_debounce.h"
#include "bcmutil.h"

struct bcmwl_event_watcher {
    ev_io                   io;
    bcmwl_event_cb_t        *cb;
    struct ds_dlist_node    list;
    char                    ifname[32];
    int                     was_down;
};

static ds_dlist_t g_watcher_list = DS_DLIST_INIT(struct bcmwl_event_watcher, list);
static bcmwl_event_cb_t *g_bcmwl_extra_cb;
static int g_bcmwl_discard_probereq;

/**
 * Private
 */

#define BCMWL_EVENT_SOCKBUF_LEN (4 * 1024 * 1024)

static bool bcmwl_event_sockbuf_resize(int fd)
{
    const int rcvbuf = BCMWL_EVENT_SOCKBUF_LEN;
    socklen_t buflen = sizeof(rcvbuf);
    int buf;

    if (WARN_ON(setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, buflen) < 0) ||
        WARN_ON(getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf, &buflen) < 0))
        return false;

    if (buf < rcvbuf) {
#ifdef CONFIG_BCMWL_EVENT_SOCK_FORCED_RESIZE
        LOGD("Forcing event socket RCVBUF resize! :: fd=%d buf=%d", fd, rcvbuf);

        /* This will work only if CAP_NET_ADMIN had been granted */
        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf, buflen) < 0 ||
            getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf, &buflen) < 0 ||
            buf < rcvbuf)
        {
            LOGW("bcmwl/event: failed to setup rcvbuf on fd %d: %d < %d, check /proc/sys/net/core/rmem_max",
                 fd, buf, rcvbuf);
            return false;
        }
#else
        LOGW("Forced event socket RCVBUF resize disabled! :: fd=%d buf=%d", fd, rcvbuf);
#endif
    }

    LOGI("Event socket RCVBUF fd=%d set=%d get=%d", fd, rcvbuf, buf);
    return true;
}

static void bcmwl_event_setup_bpf(const char *ifname, int fd)
{
    struct sock_filter ins[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(bcm_event_t, event.event_type)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, WLC_E_PROBREQ_MSG, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, WLC_E_PROBREQ_MSG_RX, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, 0),
        BPF_STMT(BPF_RET | BPF_K, 0xffff),
    };
    struct sock_fprog prog = {
        .len = ARRAY_SIZE(ins),
        .filter = ins,
    };

    if (!g_bcmwl_discard_probereq)
        return;

    LOGI("%s: setting up bpf filter to discard some events", ifname);
    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0) {
        LOGW("Failed to set up bpf filter :: ifname=%s errno=%d (%s)",
             ifname, errno, strerror(errno));
        return;
    }
}

static int bcmwl_event_get_dropped(int fd)
{
    struct tpacket_stats stats;
    socklen_t buflen = sizeof(stats);

    if (WARN_ON(getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &stats, &buflen) < 0))
        return 0;
    return stats.tp_drops;
}

static void bcmwl_event_overrun_recover_ifname(const char *ifname)
{
    if (!bcmwl_is_vif(ifname) && !bcmwl_is_phy(ifname))
        return;

    LOGI("%s: recovering from overrun", ifname);
    evx_debounce_call(bcmwl_vap_state_report, ifname);
    evx_debounce_call(bcmwl_sta_resync, ifname);
    if (bcmwl_is_phy(ifname))
        evx_debounce_call(bcmwl_radio_state_report, ifname);
}

static void bcmwl_event_overrun_recover_all(void)
{
    const char *ifname;
    struct dirent *p;
    DIR *d;

    if (!(d = WARN_ON(opendir("/sys/class/net"))))
        return;
    while ((p = readdir(d)) && (ifname = p->d_name))
        if (bcmwl_is_vif(ifname) || bcmwl_is_phy(ifname))
            bcmwl_event_overrun_recover_ifname(ifname);
    closedir(d);
}

static void bcmwl_event_overrun_recover(const char *bridge)
{
    const char *ifname;
    char *ifnames;
    int i;

    if (WARN_ON((i = bcmwl_lan_lookup(bridge)) < 0) ||
        WARN_ON(!(ifnames = NVG(bcmwl_lan(i), "ifnames")))) {
        bcmwl_event_overrun_recover_all();
        return;
    }

    while ((ifname = strsep(&ifnames, " ")))
        bcmwl_event_overrun_recover_ifname(ifname);
}

static void bcmwl_event_callback_raw(struct ev_loop *loop, ev_io *w, int revents)
{
    struct bcmwl_event_watcher  *ew = (struct bcmwl_event_watcher *) w;
    // TODO Figure out what's the maximum possible size of event
    // event size appears to be between 100-350 bytes
    uint8_t buf[512];
    int frame_size;
    os_macaddr_t  hwaddr;
    char ifname[IFNAMSIZ];
    bcm_event_t *bcm_event;
    int dropped;

again:
    frame_size = bcmwl_event_msg_read(w->fd, &buf, sizeof(buf));
    if (frame_size < 0)
    {
        /* We're using non-blocking recv so EAGAIN means no more packets */
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            goto done;
        }
        if (errno == ENETDOWN) {
            /* FIXME: If interface goes down we no longer can receive
             * events it produces. This means possible races when it
             * is re-enabled if it was poked at by 3rd party. This is
             * just playing it safe.
             */
            LOGI("%s: interface is down, scheduling force-update later", ew->ifname);
            ew->was_down = 1;
            return;
        }
        if (errno == ENOBUFS) {
            /* FIXME: Typically ENOBUFS is specific to netlink when
             * socket buffer runs out of space and events are dropped.
             * Even though this isn't netlink, it's better to check
             * for it than not.
             */
            LOGW("%s: socket overrun, lost some events, forcing update", ew->ifname);
            bcmwl_event_overrun_recover(ew->ifname);
            return;
        }
        /* EINTR has a slim chance of happening if process receives a
         * signal while read() is taking place.
         */
        if (errno == EINTR) {
            LOGI("%s: socket read interrupted (%d, %s), retrying",
                 ew->ifname, errno, strerror(errno));
            goto again;
        }
        LOGE("Failed to receive event on interface! :: ifname=%s errno=%s",
             ew->ifname, strerror(errno));
        goto error;
    }
    if (frame_size < (int) sizeof(bcm_event_t))
    {
        LOGE("Received to small data to process it as bcm_event_t! :: ifname=%s" \
            "data_size=%d", ew->ifname, frame_size);
        goto error;
    }
    if (ew->was_down)
    {
        LOGI("%s: interface was down, forcing updates", ew->ifname);
        bcmwl_event_overrun_recover(ew->ifname);
        ew->was_down = 0;
    }

    // Copy basic event data
    bcm_event = (bcm_event_t*) &buf;
    strscpy(ifname, bcm_event->event.ifname, sizeof(ifname));
    memcpy(&hwaddr, &bcm_event->event.addr, sizeof(hwaddr));

    if (ew->cb)
    {
        ew->cb(ifname, &hwaddr, (void*)bcm_event);
    }

    goto again;

done:

    if ((dropped = bcmwl_event_get_dropped(w->fd)))
    {
        LOGW("%s: socket overrun, lost %d events", ew->ifname, dropped);
        bcmwl_event_sockbuf_resize(w->fd);
        bcmwl_event_overrun_recover(ew->ifname);
    }

    return;

error:
    ev_io_stop(loop, &ew->io);
    ds_dlist_remove(&g_watcher_list, ew);
    free(w);
}

static bool bcmwl_event_mask_from_hex_str(const char *hex_str,
                                          bcmwl_event_mask_t *mask)
{
    size_t hex_str_len;
    int i; // Iterate over characters in hex_str
    int j; // Iterate over bytes in mask->bits
    int n; // First HEX digit (starting from the hex_str end)
    char byte_str[3];

    hex_str_len = strlen(hex_str);
    if (hex_str_len < 2)
    {
        return false;
    }

    if ((hex_str[0] != '0') || (hex_str[1] != 'x'))
    {
        return false;
    }

    // Skip '0x' at the beginning
    hex_str += 2;
    hex_str_len -= 2;

    if ((hex_str_len / 2) > sizeof(mask->bits))
    {
        LOGW("mask->bits is too small to store wlctl result");
        return false;
    }

    // Find first hex digit
    for (n = hex_str_len - 1; n >= 0; n--)
    {
        if (isxdigit(hex_str[n]))
        {
            break;
        }
    }

    if (n == 0)
    {
        return false;
    }

    memset(mask->bits, 0, sizeof(mask->bits));
    memset(byte_str, '\0', sizeof(byte_str));

    j = 0;
    for (i = n; i >= 1; i -= 2)
    {
        unsigned long val;

        byte_str[0] = hex_str[i-1];
        byte_str[1] = hex_str[i];
        val = strtoul(byte_str, NULL, 16);
        if (val > UINT8_MAX)
        {
            return false;
        }

        mask->bits[j] = val;

        j++;
    }

    return true;
}

static bool bcmwl_event_mask_to_hex_str(const bcmwl_event_mask_t *mask,
                                        char *buffer,
                                        size_t buffer_size)
{
    int i; // Iterate over bytes in mask->bits
    int j; // Iterate over characters in buffer
    int n; // First leftmost non-zero byte in mask->bits array

    // Find first non-zero byte
    for (n = sizeof(mask->bits) - 1; n >= 0; n--)
    {
        if (mask->bits[n])
        {
            break;
        }
    }

    // Print at least one byte
    n = n > 0 ? n : 1;

    // Required size: 2 * bytes + '0x' + '\0'
    if (buffer_size < (unsigned int) (n * 2 + 2 + 1))
    {
        return false;
    }

    memset(buffer, '\0', buffer_size);

    buffer[0]='0';
    buffer[1]='x';

    j = 2; // Start after "0x"
    for (i = n; i >= 0; i--)
    {
        sprintf(buffer + j, "%02x", mask->bits[i]);
        j +=2;
    }

    return true;
}

static bool wl_set_event_mask(const char *ifname,
                              const char *wl_opt,
                              const char *mask_hex_str)
{
    FILE *fp = NULL;
    char cmd[512];
    int return_code;

    snprintf(cmd, sizeof(cmd), "wlctl -i %s %s %s", ifname, wl_opt, mask_hex_str);
    fp = popen(cmd, "r");
    if (!fp)
    {
        LOGE("Failed to call \"wl\"! :: cmd=%s", cmd);
        goto error;
    }

    return_code = pclose(fp);
    if (return_code == -1)
    {
        LOGE("pclose() failed! :: errno=%s cmd=%s", strerror(errno), cmd);
        fp = NULL;
        goto error;
    }
    if (!WIFEXITED(return_code))
    {
        LOGE("\"wl\" failed! :: exit_code=%d cmd=%s", return_code, cmd);
        fp = NULL;
        goto error;
    }

    return true;

error:
    if (fp)
    {
        pclose(fp);
    }
    return false;
}

/**
 * Public functions
 */

int bcmwl_event_socket_open(const char *ifname)
{
    int                 fd;
    int                 ifindex;
    struct sockaddr_ll  ll;

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0)
    {
        LOGE("Unable to get interface index! :: ifname=%s errno=%s",
             ifname, strerror(errno));
        return -1;
    }

    if ((fd = socket(PF_PACKET, SOCK_RAW, htons(ETHER_TYPE_BRCM))) < 0)
    {
        LOGE("Unable to open event socket! :: ifname=%s errno=%s",
             ifname, strerror(errno));
        return -1;
    }

    memset(&ll, 0, sizeof(ll));
    ll.sll_family   = AF_PACKET;
    ll.sll_protocol = htons(ETHER_TYPE_BRCM);
    ll.sll_ifindex  = ifindex;
    if (bind(fd, (struct sockaddr *) &ll, sizeof(ll)) < 0)
    {
        LOGE("Unable to bind to event socket! :: ifname=%s ifindex=%d errno=%s",
             ifname, ifindex, strerror(errno));
        close(fd);
        return -1;
    }

    bcmwl_event_sockbuf_resize(fd);
    bcmwl_event_setup_bpf(ifname, fd);

    LOGI("Opened event socket :: ifname=%s ifindex=%d fd=%d", ifname, ifindex, fd);
    return fd;
}

int bcmwl_event_socket_close(int fd)
{
    return close(fd);
}

void bcmwl_event_discard_probereq(void)
{
    g_bcmwl_discard_probereq = 1;
}

ssize_t bcmwl_event_msg_read(int fd, void *msg, size_t msglen)
{
    return recv(fd, msg, msglen, MSG_DONTWAIT);  // non-blocking
}

static void bcmwl_event_register_h_sta_sync(const char *bridge)
{
    const char *ifname;
    char *ifnames;
    int i;

    if (WARN_ON((i = bcmwl_lan_lookup(bridge)) < 0))
        return;
    if (WARN_ON(!(ifnames = NVG(bcmwl_lan(i), "ifnames"))))
        return;
    while ((ifname = strsep(&ifnames, " ")))
        if (strlen(ifname) && strncmp(ifname, "wl", 2) == 0)
            evx_debounce_call(bcmwl_sta_resync, ifname);
}

bool bcmwl_event_register(struct ev_loop *loop,
                          const char *ifname,
                          bcmwl_event_cb_t callback)
{
    int fd;
    struct bcmwl_event_watcher *ew;

    ds_dlist_foreach(&g_watcher_list, ew)
        if (!strcmp(ew->ifname, ifname) && ew->cb == callback)
            break;

    if (ew)
    {
        LOGD("%s: already registered, skipping", ifname);
        return true;
    }

    ew = calloc(1, sizeof(*ew));
    if (!ew)
    {
        LOGE("Unable to allocate event watcher! :: ifname=%s", ifname);
        return false;
    }

    fd = bcmwl_event_socket_open(ifname);
    if (fd < 0)
    {
        LOGE("Unable to register event watcher! :: ifname=%s", ifname);
        return false;
    }

    ev_io_init(&ew->io, bcmwl_event_callback_raw, fd, EV_READ);
    ev_io_start(loop, &ew->io);

    STRSCPY(ew->ifname, ifname);
    ew->cb = callback;
    ds_dlist_insert_tail(&g_watcher_list, ew);
    bcmwl_event_register_h_sta_sync(ifname);

    LOGI("%s: registered event handler %p", ifname, callback);
    return true;
}

void bcmwl_event_unregister(struct ev_loop *loop,
                            const char *ifname,
                            bcmwl_event_cb_t callback)
{
    struct bcmwl_event_watcher *e;

    ds_dlist_foreach(&g_watcher_list, e)
        if (!strcmp(e->ifname, ifname) && e->cb == callback)
            break;
    if (!e)
        return;

    LOGI("%s: unregistering event handler %p", ifname, e->cb);
    ev_io_stop(loop, &e->io);
    ds_dlist_remove(&g_watcher_list, e);
    free(e);
}

static void bcmwl_event_handle_ap_sta_assoc(const char *ifname,
                                            const os_macaddr_t *hwaddr)
{
    const char *mac = strfmta(PRI(os_macaddr_t), FMT(os_macaddr_t, *hwaddr));
    bool assoc = bcmwl_sta_is_connected(ifname, mac);
    struct schema_Wifi_Associated_Clients client;

    if (bcmwl_vap_is_sta(ifname))
        return;

    bcmwl_sta_get_schema(ifname, mac, &client);
    if (!WARN_ON(!bcmwl_ops.op_client))
        bcmwl_ops.op_client(&client, ifname, assoc);
}

/* See util_csa_war_update_rconf_channel in target_qca.c
 * and CAES-600 for details */
static void bcmwl_event_war_csa(const char *ifname)
{
    const char *ovsh = strfmta("%s/../tools/ovsh", target_bin_dir());
    const char *chanspec = WL(ifname, "chanspec") ?: strdupa("");
    const char *phy = ifname;
    const char *result;
    const char *rchan;
    char *p;
    int c;
    int w;

    if (!bcmwl_is_phy(ifname))
        return;
    if (!bcmwl_vap_is_sta(ifname))
        return;
    if ((WARN_ON(!(p = WL(ifname, "bss"))) || strcmp(p, "up")))
        return;

    bcmwl_radio_chanspec_extract(chanspec, &c, &w);

    if ((rchan = strexa(ovsh, "-r", "s", "Wifi_Radio_Config", "channel",
                        "-w", strfmta("channel!=%d", c),
                        "-w", strfmta("if_name==%s", phy))) && atoi(rchan) == c)
        return;

    LOGI("%s: applying channel workaround on leaf: overriding radio config (%d -> %d) locally, see CAES-600",
         phy, rchan ? atoi(rchan) : -1, c);

    if (WARN_ON(!(result = strexa(ovsh, "-r", "u", "Wifi_Radio_Config",
                                  "-w", strfmta("if_name==%s", phy),
                                  strfmta("channel:=%d", c)))))
        return;
    WARN_ON(atoi(result) != 1);
    NVS(phy, "chanspec", chanspec);
}

static void bcmwl_event_handle_csa(const char *ifname)
{
    struct dirent *p;
    char *phy;
    DIR *d;

    LOGI("%s: csa completed (%s)", ifname, WL(ifname, "chanspec") ?: "");
    if (!(phy = strdupa(ifname)) || !(phy = strsep(&phy, ".")))
        return;

    bcmwl_event_war_csa(ifname);
    evx_debounce_call(bcmwl_radio_state_report, phy);

    if (WARN_ON(!(d = opendir("/sys/class/net"))))
        return;
    while ((p = readdir(d)))
        if (strstr(p->d_name, phy) == p->d_name)
            evx_debounce_call(bcmwl_vap_state_report, p->d_name);
    closedir(d);
}

static void bcmwl_event_handle_radio(const char *ifname)
{
    int isup = atoi(WL(ifname, "isup") ?: "-1");
    LOGI("%s: radio chip state changed: %d", ifname, isup);
    evx_debounce_call(bcmwl_radio_state_report, ifname);
}

static void bcmwl_event_print(const bcm_event_t *ev)
{
    const char *ifname = ev->event.ifname;
    const char *mac = strfmta("%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                              ev->event.addr.octet[0],
                              ev->event.addr.octet[1],
                              ev->event.addr.octet[2],
                              ev->event.addr.octet[3],
                              ev->event.addr.octet[4],
                              ev->event.addr.octet[5]);
    int reason = ntohl(ev->event.reason);
    int status = ntohl(ev->event.status);
    int e = ntohl(ev->event.event_type);

    if (e == WLC_E_DEAUTH_IND)
        LOGI("%s: %s: deauth indication status %d reason %d", ifname, mac, status, reason);
    if (e == WLC_E_DISASSOC_IND)
        LOGI("%s: %s: disassoc indication status %d reason %d", ifname, mac, status, reason);
    if (e == WLC_E_AUTH)
        LOGI("%s: %s: auth status %d reason %d", ifname, mac, status, reason);
    if (e == WLC_E_ASSOC)
        LOGI("%s: %s: assoc status %d reason %d", ifname, mac, status, reason);
    if (e == WLC_E_DEAUTH)
        LOGI("%s: %s: deauth status %d reason %d", ifname, mac, status, reason);
    if (e == WLC_E_DISASSOC)
        LOGI("%s: %s: disassoc status %d reason %d", ifname, mac, status, reason);
}

bool bcmwl_event_handler(const char *ifname,
                         os_macaddr_t *hwaddr,
                         void *event)
{
    bcm_event_t *ev = (bcm_event_t *)event;
    int e = ntohl(ev->event.event_type);

    if (g_bcmwl_extra_cb)
    {
        if (g_bcmwl_extra_cb(ifname, hwaddr, (void*)ev) == BCMWL_EVENT_HANDLED)
            return BCMWL_EVENT_HANDLED;
    }

    switch (e) {
        case WLC_E_PROBREQ_MSG_RX:
        case WLC_E_PROBREQ_MSG:
            /* These are spammed a lot. They'd waste
             * traceback buffer so don't log them at all.
             */
            return BCMWL_EVENT_HANDLED;
        default:
            LOGT("%s: event_type=%d", ev->event.ifname, e);
            break;
    }

    bcmwl_roam_event_handler(ev);
    bcmwl_event_print(ev);

    switch (e) {
        case WLC_E_RADIO:
            bcmwl_event_handle_radio(ifname);
            return BCMWL_EVENT_HANDLED;
        case WLC_E_AUTHORIZED:
        case WLC_E_DEAUTH:
        case WLC_E_DEAUTH_IND:
        case WLC_E_DISASSOC:
        case WLC_E_DISASSOC_IND:
            bcmwl_event_handle_ap_sta_assoc(ifname, hwaddr);
            return BCMWL_EVENT_HANDLED;
        case WLC_E_CSA_COMPLETE_IND:
            bcmwl_event_handle_csa(ifname);
            return BCMWL_EVENT_HANDLED;
        case WLC_E_RADAR_DETECTED:
            bcmwl_event_handle_radar(ifname);
            return BCMWL_EVENT_HANDLED;
    }

    return BCMWL_EVENT_CONTINUE;
}

void bcmwl_event_setup(struct ev_loop *loop)
{
    struct bcmwl_event_watcher *e;
    char *i, *k, *v, *p;
    int idx;

    bcmwl_nvram_for_each(i, k, v, p)
        if ((idx = bcmwl_lan_get_idx(k)) >= 0)
            if (!bcmwl_event_register(loop, v, bcmwl_event_handler))
                LOGW("%s: failed to register events for %s=%s", __func__, k, v);

again:
    ds_dlist_foreach(&g_watcher_list, e)
    {
        bcmwl_nvram_for_each(i, k, v, p)
            if (bcmwl_lan_get_idx(k) >= 0 && !strcmp(v, e->ifname))
                break;
        if (!v)
        {
            bcmwl_event_unregister(loop, e->ifname, bcmwl_event_handler);
            /* dlist can't handle removal during iteration
             * so jump outside and re-do it from scratch
             */
            goto again;
        }
    }
}

void bcmwl_event_setup_extra_cb(bcmwl_event_cb_t cb)
{
    g_bcmwl_extra_cb = cb;
}

bool bcmwl_event_mask_get(const char *ifname, bcmwl_event_mask_t *mask)
{
    FILE *fp = NULL;
    char  cmd[512];
    char  buf[512];
    int return_code;

    /*
     * "event_msgs_ext" command gets whole bit vector.
     */
    snprintf(cmd, sizeof(cmd), "wlctl -i %s event_msgs_ext", ifname);
    fp = popen(cmd, "r");
    if (!fp)
    {
        LOGE("Failed to call \"wl\"! :: cmd=%s", cmd);
        goto error;
    }

    if (!fgets(buf, sizeof(buf), fp))
    {
        LOGE("\"wl\" did not produce any output! :: cmd=%s", cmd);
        goto error;
    }

    if (!bcmwl_event_mask_from_hex_str(buf, mask))
    {
        LOGE("Failed to parse \"wl\" output! :: cmd=%s output=\"%s\"", cmd, buf);
        goto error;
    }

    return_code = pclose(fp);
    if (return_code == -1)
    {
        LOGE("pclose() failed! :: errno=%s cmd=%s", strerror(errno), cmd);
        fp = NULL;
        goto error;
    }
    if (!WIFEXITED(return_code))
    {
        LOGE("\"wl\" failed! :: exit_code=%d cmd=%s", return_code, cmd);
        fp = NULL;
        goto error;
    }

    return true;

error:
    if (fp)
    {
        pclose(fp);
    }
    return false;
}

bool bcmwl_event_mask_set(const char *ifname,
                          const bcmwl_event_mask_t *mask)
{

    char  hex_str[512];

    if (!bcmwl_event_mask_to_hex_str(mask, hex_str, sizeof(hex_str)))
    {
        LOGE("Failed to convert \"wl\" events mask to HEX string!");
        return false;
    }

    /*
     * There are two wl commands for getting/setting event mask: "event_msgs"
     * and "event_msgs_ext". They handle lower and upper part of bit vector
     * respectively.
     */
    if (!wl_set_event_mask(ifname, "event_msgs", hex_str))
    {
        return false;
    }

    if (!wl_set_event_mask(ifname, "event_msgs_ext", hex_str))
    {
        return false;
    }

    return true;
}

void bcmwl_event_mask_bit_set(bcmwl_event_mask_t *mask, unsigned int bit)
{
    const int i = (bit) / 8;
    assert (i < BCMWL_EVENT_MASK_BITS_SIZE);
    ((uint8_t *) mask->bits)[i] |= 1 << ((bit) % 8);
}

void bcmwl_event_mask_bit_unset(bcmwl_event_mask_t *mask, unsigned int bit)
{
    const int i = (bit) / 8;
    assert (i < BCMWL_EVENT_MASK_BITS_SIZE);
    ((uint8_t *) mask->bits)[i] &= ~(1 << ((bit) % 8));
}

bool bcmwl_event_mask_bit_isset(bcmwl_event_mask_t *mask, unsigned int bit)
{
    const int i = (bit) / 8;
    assert (i < BCMWL_EVENT_MASK_BITS_SIZE);
    return ((uint8_t *) mask->bits)[i] & (1 << ((bit) % 8));
}

#define BCMWL_EVENT_LOCK_PATH "/tmp/.bcmwl.event.lock"

bool bcmwl_event_enable(const char *ifname, unsigned int bit)
{
    bcmwl_event_mask_t mask;
    bool ok = false;
    int fd;

    if (WARN_ON((fd = open(BCMWL_EVENT_LOCK_PATH, O_TRUNC | O_CREAT | O_CLOEXEC)) < 0))
        return false;
    if (WARN_ON(flock(fd, LOCK_EX) < 0))
        goto out;
    if (!bcmwl_event_mask_get(ifname, &mask))
        goto out;
    if (!bcmwl_event_mask_bit_isset(&mask, bit))
        LOGI("%s: enabling event bit %d", ifname, bit);
    else
        LOGD("%s: event bit %d already enabled", ifname, bit);
    bcmwl_event_mask_bit_set(&mask, bit);
    if (!bcmwl_event_mask_set(ifname, &mask))
        goto out;
    ok = true;
out:
    if (WARN_ON(flock(fd, LOCK_UN) < 0))
        ok = false;
    close(fd);
    return ok;
}
