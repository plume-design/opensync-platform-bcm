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
#include <linux/rtnetlink.h>
#include <linux/socket.h>
#include <linux/netlink.h>

#include "os.h"

#include "ds.h"
#include "log.h"
#include "os_nif.h"
#include "os.h"
#include "target.h"
#include "evx_debounce_call.h"
#include "kconfig.h"

/* This clearly violates the abstraction separation but it's
 * better than do that than to slowness of calling fork+exec
 * for ovs-vsctl.
 */
#include "ovsdb.h"
#include "ovsdb_update.h"
#include "ovsdb_sync.h"
#include "ovsdb_table.h"
#include "ovsdb_cache.h"

#include "bcmwl.h"
#include "bcmwl_nvram.h"
#include "bcmwl_roam.h"
#include "bcmwl_debounce.h"
#include "bcmwl_event.h"
#include "bcmwl_ioctl.h"

struct bcmwl_event_watcher {
    ev_io                   io;
    bcmwl_event_cb_t        *cb;
    struct ds_dlist_node    list;
    char                    ifname[32];
    int                     was_down;
    bool                    removing;
};

static ds_dlist_t g_watcher_list = DS_DLIST_INIT(struct bcmwl_event_watcher, list);
static bcmwl_event_cb_t *g_bcmwl_extra_cb;
static int g_bcmwl_discard_probereq;
static ev_async g_nl_async;
static ev_io g_nl_io;

#define util_nl_each_msg(buf, len, hdr, hdrlen) \
    for (hdr = buf, hdrlen = len; NLMSG_OK(hdr, hdrlen); hdr = NLMSG_NEXT(hdr, hdrlen))

#define util_nl_each_msg_type(buf, len, hdr, hdrlen, type) \
    util_nl_each_msg(buf, len, hdr, hdrlen) \
        if (hdr->nlmsg_type == type)

#define util_nl_each_attr(hdr, attr, attrlen) \
    for (attr = IFLA_RTA(NLMSG_DATA(hdr)), attrlen = IFLA_PAYLOAD(hdr); \
         RTA_OK(attr, attrlen); \
         attr = RTA_NEXT(attr, attrlen))

#define util_nl_each_attr_type(hdr, attr, attrlen, type) \
    util_nl_each_attr(hdr, attr, attrlen) \
        if (attr->rta_type == type)

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
        LOGD("Forced event socket RCVBUF resize disabled! :: fd=%d buf=%d", fd, rcvbuf);
#endif
    }

    LOGD("Event socket RCVBUF fd=%d set=%d get=%d", fd, rcvbuf, buf);
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

    LOGD("%s: setting up bpf filter to discard some events", ifname);
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

/* `buf` gets filled with space-separated ifnames, w/ possibly trailing space */
static bool bcmwl_event_br_get_if_ovs(const char *brname, char *buf, size_t len)
{
    struct schema_Bridge bridge;
    struct schema_Port *ports;
    struct schema_Port *port;
    ovsdb_table_t table_Bridge;
    ovsdb_table_t table_Port;
    int n_ports;
    int i;

    OVSDB_TABLE_INIT(Bridge, name);
    OVSDB_TABLE_INIT(Port, name);

    if (!ovsdb_table_select_one(&table_Bridge, "name", brname, &bridge))
        return false;

    ports = ovsdb_table_select_where(&table_Port, NULL, &n_ports);
    if (!ports)
        return false;

    for (port = ports; n_ports; n_ports--, port++)
        for (i = 0; i < bridge.ports_len; i++)
            if (!strcmp(port->_uuid.uuid, bridge.ports[i].uuid))
                csnprintf(&buf, &len, "%s ", port->name);


    free(ports);
    return true;
}

/* `buf` gets filled with space-separated ifnames, w/ possibly trailing space */
static bool bcmwl_event_br_get_if_linux(const char *brname, char *buf, size_t len)
{
    char path[128];
    struct dirent *d;
    DIR *dir;

    snprintf(path, sizeof(path), "/sys/class/net/%s/brif", brname);
    if (!(dir = opendir(path)))
        return false;

    while ((d = readdir(dir)))
        if (strcmp(d->d_name, ".") && strcmp(d->d_name, ".."))
            csnprintf(&buf, &len, "%s ", d->d_name);

    closedir(dir);
    return true;
}

static char* bcmwl_event_br_get_if(const char *brname)
{
    char ports[1024];

    memset(ports, 0, sizeof(ports));

    if (bcmwl_event_br_get_if_linux(brname, ports, sizeof(ports)))
        return strdup(ports);

    if (bcmwl_event_br_get_if_ovs(brname, ports, sizeof(ports)))
        return strdup(ports);

    return NULL;
}

static void bcmwl_event_verify_vht_oper(const char *ifname, const char *chanspec)
{
    /* Example snippet:
     *
     * Tag:191 Len:12 - Unsupported tag
     * 35 68 8b 0f aa ff 00 00 aa ff 00 20
     * Tag:192 Len:5 - Unsupported tag
     * 01 2a 00 00 00
     */
    const char *info = WL(ifname, "beacon_info");
    const char *vht_oper_tag = strstr(info ?: "", "Tag:192");
    const char *vht_oper_val = strstr(vht_oper_tag ?: "\n00", "\n") + 1;
    const char *is80mhz = strstr(chanspec ?: "", "/80");
    const char *is160mhz = strstr(chanspec ?: "", "/160");
    long int width = strtol(vht_oper_val, NULL, 16);

    if (!info)
        return;

    if (strlen(info) == 0)
        return;

    if ((is80mhz || is160mhz) == !!width)
        return;

    /* Some drivers are known to mishandle bandwidth changes
     * by not properly updating their VHT Operation IE. As a
     * result stations associating will use incorrect
     * bandwidth causing further issues.
     *
     * Toggling radio makes sure beacon and probe resp
     * buffers are properly recalculated.
     */
    LOGN("%s: beacon info width %ld mismatch with chanspec %s, toggling radio\n",
         ifname, width, chanspec);

    WARN_ON(!WL(ifname, "down"));
    WARN_ON(!WL(ifname, "chanspec", chanspec));
    WARN_ON(!WL(ifname, "up"));
}

static void bcmwl_event_refresh_chanspec(const char *ifname)
{
    char *chanspec;

    if (WARN_ON(!(chanspec = WL(ifname, "chanspec"))))
        return;
    if (WARN_ON(!(chanspec = strsep(&chanspec, " "))))
        return;

    bcmwl_event_verify_vht_oper(ifname, chanspec);
    WARN_ON(!WL(ifname, "chanspec", chanspec));
}

static void bcmwl_event_overrun_recover_ifname(const char *ifname)
{
    if (!bcmwl_is_vif(ifname) && !bcmwl_is_phy(ifname))
        return;

    LOGI("%s: recovering from overrun", ifname);
    bcmwl_event_refresh_chanspec(ifname);
    evx_debounce_call(bcmwl_vap_state_report, ifname);
    evx_debounce_call(bcmwl_sta_resync, ifname);
    if (bcmwl_is_phy(ifname))
        evx_debounce_call(bcmwl_radio_state_report, ifname);
}

static void bcmwl_event_overrun_recover(const char *bridge)
{
    const char *ifname;
    char *ifnames;

    ifnames = strdupafree(bcmwl_event_br_get_if(bridge));
    if (!ifnames)
        ifnames = strdupa(bridge);
    while ((ifname = strsep(&ifnames, " \n")))
        bcmwl_event_overrun_recover_ifname(ifname);
}

static void bcmwl_event_unregister_watcher(struct ev_loop *loop, struct bcmwl_event_watcher *e)
{
    LOGI("%s: unregistering event handler %p", e->ifname, e->cb);
    bcmwl_event_socket_close(e->io.fd);
    ev_io_stop(loop, &e->io);
    ds_dlist_remove(&g_watcher_list, e);
    free(e);
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
            LOGD("%s: interface is down, scheduling force-update later", ew->ifname);
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
        LOGD("%s: interface was down, forcing updates", ew->ifname);
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
    bcmwl_event_unregister_watcher(loop, ew);
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

    LOGD("Opened event socket :: ifname=%s ifindex=%d fd=%d", ifname, ifindex, fd);
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

    ifnames = strdupafree(bcmwl_event_br_get_if(bridge));
    if (!ifnames)
        ifnames = strdupa(bridge);
    while ((ifname = strsep(&ifnames, " \n")))
        if (strlen(ifname) && strncmp(ifname, "wl", 2) == 0)
            evx_debounce_call(bcmwl_sta_resync, ifname);
}

bool bcmwl_event_register(struct ev_loop *loop,
                          const char *ifname,
                          bcmwl_event_cb_t callback)
{
    int fd;
    struct bcmwl_event_watcher *ew;

    LOGT("%s: registering event handler %p", ifname, callback);

    ds_dlist_foreach(&g_watcher_list, ew)
        if (!strcmp(ew->ifname, ifname) && ew->cb == callback)
            break;

    if (ew)
    {
        ew->removing = false;
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
        free(ew);
        return false;
    }

    ev_io_init(&ew->io, bcmwl_event_callback_raw, fd, EV_READ);
    ev_io_start(loop, &ew->io);

    STRSCPY(ew->ifname, ifname);
    ew->cb = callback;
    ds_dlist_insert_tail(&g_watcher_list, ew);
    bcmwl_event_register_h_sta_sync(ifname);
    if (bcmwl_is_phy(ifname))
        evx_debounce_call(bcmwl_radio_state_report, ifname);
    if (bcmwl_is_netdev(ifname))
        evx_debounce_call(bcmwl_vap_state_report, ifname);

    if (strstr(ifname, "wds") == ifname) {
        LOGI("%s: forcing netdev up", ifname);
        strexa("ip", "link", "set", ifname, "up");
    }

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

    bcmwl_event_unregister_watcher(loop, e);
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

    /* FIXME: This is a deficiency in the API which is bound to ovsdb
     * and the ambiguity of Wifi_Radio_Config channel with regard to
     * possible STA uplink.
     */
    LOGI("%s: applying channel workaround on leaf: overriding radio config (%d -> %d) locally",
         phy, rchan ? atoi(rchan) : -1, c);

    if (WARN_ON(!(result = strexa(ovsh, "-r", "u", "Wifi_Radio_Config",
                                  "-w", strfmta("if_name==%s", phy),
                                  strfmta("channel:=%d", c)))))
        return;
    WARN_ON(atoi(result) != 1);
    NVS(phy, "chanspec", chanspec);
}

static void bcmwl_event_report_channel(const char *ifname)
{
    struct dirent *p;
    char *phy;
    DIR *d;

    if (!(phy = strdupa(ifname)) || !(phy = strsep(&phy, CONFIG_BCMWL_VAP_DELIMITER)))
        return;

    evx_debounce_call(bcmwl_radio_state_report, phy);

    if (WARN_ON(!(d = opendir("/sys/class/net"))))
        return;
    while ((p = readdir(d)))
        if (strstr(p->d_name, phy) == p->d_name)
            evx_debounce_call(bcmwl_vap_state_report, p->d_name);
    closedir(d);
}

static void bcmwl_event_handle_csa(const char *ifname)
{
    LOGI("%s: csa completed (%s)", ifname, WL(ifname, "chanspec") ?: "");

    bcmwl_event_refresh_chanspec(ifname);
    bcmwl_event_war_csa(ifname);
    bcmwl_event_report_channel(ifname);
}

static void bcmwl_event_handle_radio(const char *ifname)
{
    int isup = atoi(WL(ifname, "isup") ?: "-1");
    LOGI("%s: radio chip state changed: %d", ifname, isup);
    evx_debounce_call(bcmwl_radio_state_report, ifname);
}

static void bcmwl_event_handle_if(const bcm_event_t *ev)
{
    const void *data = ev + 1;
    const struct wl_event_data_if *eif = data;
    const char *ifname = ev->event.ifname;
    const char *str;

    switch (eif->opcode) {
        case WLC_E_IF_ADD: str = "add"; break;
        case WLC_E_IF_DEL: str = "del"; break;
        case WLC_E_IF_CHANGE: str = "change"; break;
        case WLC_E_IF_BSSCFG_UP: str = "bsscfg-up"; break;
        case WLC_E_IF_BSSCFG_DOWN: str = "bsscfg-down"; break;
        default: str = "unknown"; break;
    }

    LOGI("%s: vif state changed: %s (%hhu)", ifname, str, eif->opcode);
    evx_debounce_call(bcmwl_vap_state_report, ifname);
}

static void bcmwl_event_print(const bcm_event_t *ev)
{
    int e = ntohl(ev->event.event_type);
    const char *evname;

#define CASE2STR(x, msg) case x: evname = msg; break

    switch(e)
    {
    CASE2STR(WLC_E_AUTH, "auth");
    CASE2STR(WLC_E_AUTH_IND, "auth indication");
    CASE2STR(WLC_E_AUTHORIZED, "authorized");
    CASE2STR(WLC_E_DEAUTH, "deauth");
    CASE2STR(WLC_E_DEAUTH_IND, "deauth indication");
    CASE2STR(WLC_E_ASSOC, "assoc");
    CASE2STR(WLC_E_ASSOC_IND, "assoc indication");
    CASE2STR(WLC_E_DISASSOC, "disassoc");
    CASE2STR(WLC_E_DISASSOC_IND, "disassoc indication");
    default: /* too verbose */ return;
    }

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

    LOGI("%s: %s: %s status %d reason %d", ifname, mac, evname, status, reason);
}

static void bcmwl_event_handle_link(const bcm_event_t *ev)
{
    const char *ifname = ev->event.ifname;
    const char *reason_str;
    int reason = ntohl(ev->event.reason);
    int flags = ntohs(ev->event.flags);

    reason_str = (reason == WLC_E_LINK_DISASSOC ? "disassoc" :
                  reason == WLC_E_LINK_BCN_LOSS ? "beacon loss" :
                  reason == WLC_E_LINK_ASSOC_REC ? "assoc recreation failure" :
                  reason == WLC_E_LINK_BSSCFG_DIS ? "bss down request" :
                  "some other reason");

    LOGI("%s: link state changed to %s due to %s (%d)",
         ifname,
         (flags == WLC_EVENT_MSG_LINK) ? "up" : "down",
         reason_str,
         reason);
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
        case WLC_E_IF:
            bcmwl_event_handle_if(ev);
            return BCMWL_EVENT_HANDLED;
        case WLC_E_RADIO:
            bcmwl_event_handle_radio(ifname);
            return BCMWL_EVENT_HANDLED;
        case WLC_E_ASSOC:
            bcmwl_event_refresh_chanspec(ifname);
            /* FALLTHROUGH */
        case WLC_E_ASSOC_IND:
        case WLC_E_AUTH:
        case WLC_E_AUTH_IND:
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
        case WLC_E_AP_CHAN_CHANGE:
            bcmwl_event_handle_ap_chan_change(ifname, ev);
            return BCMWL_EVENT_HANDLED;
        case WLC_E_JOIN:
            /* If sta interface moves to a different channel than
             * the one which was used prior to `wl join` by local ap
             * interfaces then the entire radio implicitly switches
             * over to the new channel. This is performed without
             * csa on the ap side and therefore doesn't result in
             * csa completion events.
             *
             * Hence this needs extra attention and any sta
             * interface connectivity event should be considered as
             * a trigger to re-read and report ap bss states to the
             * upper (WM) layer to avoid channel desync in
             * state tables.
             */
            bcmwl_event_report_channel(ifname);
            return BCMWL_EVENT_HANDLED;
        case WLC_E_LINK:
            bcmwl_event_handle_link(ev);
            return BCMWL_EVENT_HANDLED;
    }

    return BCMWL_EVENT_CONTINUE;
}

static void bcmwl_event_setup(struct ev_loop *loop)
{
    struct bcmwl_event_watcher *e;
    struct dirent *p;
    DIR *d;

    ds_dlist_foreach(&g_watcher_list, e)
        if (e->cb == bcmwl_event_handler)
            e->removing = true;

    for (d = opendir("/sys/class/net"); d && (p = readdir(d)); ) {
        if (!strcmp(p->d_name, "")) continue;
        if (!strcmp(p->d_name, ".")) continue;
        if (!strcmp(p->d_name, "..")) continue;
        WARN_ON(!bcmwl_event_register(loop, p->d_name, bcmwl_event_handler));
    }

    closedir(d);

again:
    ds_dlist_foreach(&g_watcher_list, e) {
        if (e->cb == bcmwl_event_handler && e->removing) {
            bcmwl_event_unregister(loop, e->ifname, bcmwl_event_handler);
            /* dlist can't handle removal during iteration
             * so jump outside and re-do it from scratch
             */
            goto again;
        }
    }
}

static void bcmwl_event_nl_handle(const void *const buf, unsigned int len)
{
    const struct nlmsghdr *hdr;
    const struct rtattr *attr;
    int attrlen;
    int hdrlen;

    util_nl_each_msg_type(buf, len, hdr, hdrlen, RTM_NEWLINK)
        util_nl_each_attr_type(hdr, attr, attrlen, IFLA_IFNAME)
            WARN_ON(!bcmwl_event_register(EV_DEFAULT_ RTA_DATA(attr), bcmwl_event_handler));

    util_nl_each_msg_type(buf, len, hdr, hdrlen, RTM_DELLINK)
        util_nl_each_attr_type(hdr, attr, attrlen, IFLA_IFNAME)
            bcmwl_event_unregister(EV_DEFAULT_ RTA_DATA(attr), bcmwl_event_handler);
}

static void bcmwl_event_nl_cb(EV_P_ ev_io *io, int events)
{
    char buf[4096];
    ssize_t n;

    n = recv(io->fd, buf, sizeof(buf), MSG_DONTWAIT);
    LOGD("netlink buffer recv %zd bytes errno %d", n, errno);
    if (n < 0) {
        if (errno == EAGAIN)
            return;
        LOGN("netlink socket error, re-opening");
        ev_io_stop(EV_DEFAULT_ &g_nl_io);
        close(g_nl_io.fd);
        g_nl_io.fd = 0;
        ev_async_send(EV_DEFAULT_ &g_nl_async);
        return;
    }

    bcmwl_event_nl_handle(buf, n);
}

static void bcmwl_event_nl_async_cb(EV_P_ ev_async *async, int events)
{
    struct sockaddr_nl addr = {
        .nl_family = AF_NETLINK,
        .nl_groups = RTMGRP_LINK,
    };
    int fd;

    if (WARN_ON(g_nl_io.fd))
        return;
    if (WARN_ON((fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0))
        return;
    if (WARN_ON(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0))
        return;
    if (WARN_ON(setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (int []) { 2*1024*1024 }, sizeof(int)) < 0))
        return;

    ev_io_init(&g_nl_io, bcmwl_event_nl_cb, fd, EV_READ);
    ev_io_start(EV_DEFAULT_ &g_nl_io);
    bcmwl_event_setup(EV_DEFAULT);
    LOGI("netlink socket opened");
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

static bool bcmwl_event_enable_exec(const char *ifname, unsigned int bit)
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

static bool bcmwl_event_enable_iov(const char *ifname, unsigned int bit)
{
    struct {
        /* eventmsgs_ext_t is variable length and needs to
         * be stretched for iovar declaration to figure out
         * the input parameter length
         */
        eventmsgs_ext_t ext;
        char buf[(WLC_E_LAST + 7) / 8];
    } arg;

    LOGD("%s: enabling event bit %d", ifname, bit);
    memset(&arg, 0, sizeof(arg));
    arg.ext.ver = EVENTMSGS_VER;
    arg.ext.len = sizeof(arg.buf);
    arg.ext.command = EVENTMSGS_SET_BIT;
    arg.ext.mask[bit / 8] |= 1 << (bit % 8);
    if (WARN_ON(!bcmwl_SIOV(ifname, "event_msgs_ext", &arg)))
        return false;

    return true;
}

bool bcmwl_event_enable(const char *ifname, unsigned int bit)
{
    if (kconfig_enabled(CONFIG_BCM_PREFER_IOV))
        return bcmwl_event_enable_iov(ifname, bit);
    else
        return bcmwl_event_enable_exec(ifname, bit);
}

void bcmwl_event_enable_all(unsigned int bit)
{
    struct dirent *p;
    DIR *d;

    for (d = opendir("/sys/class/net"); d && (p = readdir(d)); )
        if (bcmwl_is_phy(p->d_name))
            WARN_ON(!bcmwl_event_enable(p->d_name, bit));
    if (!WARN_ON(!d))
        closedir(d);
}

void bcmwl_event_init(void)
{
    ev_async_init(&g_nl_async, bcmwl_event_nl_async_cb);
    ev_async_start(EV_DEFAULT_ &g_nl_async);
    ev_async_send(EV_DEFAULT_ &g_nl_async);
}
