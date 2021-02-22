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
#include <string.h>
#include <errno.h>
#include <byteswap.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <dirent.h>

#include <typedefs.h> /* defines, eg. uint32 */
#include <bcmutils.h>
#include "bcmwl.h"
#include "bcmwl_ioctl.h"
#include "kconfig.h"

/*
 * Private
 */

#define NUM_CONV_SIZE 6

static struct bcmwl_ioctl_num_conv num_convs[NUM_CONV_SIZE];

static uint16_t swap16(uint16_t val)
{
    return bswap_16(val);
}

static uint32_t swap32(uint32_t val)
{
    return bswap_32(val);
}

static uint64_t swap64(uint64_t val)
{
    return bswap_64(val);
}

static uint16_t pass16(uint16_t val)
{
    return val;
}

static uint32_t pass32(uint32_t val)
{
    return val;
}

static uint64_t pass64(uint64_t val)
{
    return val;
}

static bool bcmwl_detect_radio_endianness(const char *ifname,
                                          struct bcmwl_ioctl_num_conv *num_conv)
{
    uint32_t magic;
    uint32_t version;

    if (WARN_ON(!bcmwl_GIOC(ifname, WLC_GET_MAGIC, NULL, &magic)))
        return false;

    if (magic == WLC_IOCTL_MAGIC)
    {
        num_conv->dtoh16 = &pass16;
        num_conv->dtoh32 = &pass32;
        num_conv->dtoh64 = &pass64;
    }
    else if (bswap_32(magic) == WLC_IOCTL_MAGIC)
    {
        num_conv->dtoh16 = &swap16;
        num_conv->dtoh32 = &swap32;
        num_conv->dtoh64 = &swap64;
    }
    else
    {
        LOGE("Invalid \"magic\" value read with ioctl! :: ifname=%s driver_magic0x%x header_magic=0x%x",
             ifname, magic, WLC_IOCTL_MAGIC);
        return false;
    }

    if (WARN_ON(!bcmwl_GIOC(ifname, WLC_GET_VERSION, NULL, &version)))
        return false;

    version = num_conv->dtoh32(version);
    if (version != WLC_IOCTL_VERSION)
    {
        LOGE("Version mismatch of ioctl interfaces! :: ifname=%s driver_ver%u header_ver=%u",
             ifname, version, WLC_IOCTL_VERSION);
        return false;
    }

    return true;
}

/*
 * Public
 */
bool bcmwl_ioctl_init(void)
{
    DIR *dir = NULL;
    bool result = false;
    struct dirent *entry;
    static int init;
    size_t i;

    if (init) return true;

    if (WARN_ON(!(dir = opendir("/sys/class/net/"))))
        goto leave;

    for (i = 0; i < ARRAY_SIZE(num_convs); i++) {
        num_convs[i].dtoh16 = &pass16;
        num_convs[i].dtoh32 = &pass32;
        num_convs[i].dtoh64 = &pass64;
    }

    while ((entry = readdir(dir)))
    {
        int wl_i;

        if (!bcmwl_is_phy(entry->d_name))
            continue;

        wl_i = atoi(entry->d_name + 2);
        if (WARN_ON(wl_i >= NUM_CONV_SIZE))
            goto leave;

        if (WARN_ON(!bcmwl_detect_radio_endianness(entry->d_name, &num_convs[wl_i])))
            goto leave;
    }

    result = true;
    init = true;

leave:
    closedir(dir);

    return result;
}

const struct bcmwl_ioctl_num_conv* bcmwl_ioctl_lookup_num_conv(const char *ifname)
{
    int ri;
    int vi;

    bcmwl_ioctl_init();

    if (WARN_ON(!bcmwl_parse_vap(ifname, &ri, &vi)))
        return NULL;

    if (WARN_ON(ri >= NUM_CONV_SIZE))
        return NULL;

    return &num_convs[ri];
}

static bool bcmwl_ioc(struct bcmwl_ioctl_arg *arg, void *buf)
{
    if (WARN_ON(arg->plen > WLC_IOCTL_MAXLEN))
        return false;
    if (arg->param)
        memcpy(buf, arg->param, arg->plen);

    return true;
}

static bool bcmwl_iov(struct bcmwl_ioctl_arg *arg, void *buf)
{
    size_t len;

    len = strlen(arg->iovar) + 1;
    if (WARN_ON(len > WLC_IOCTL_MAXLEN))
        return false;
    if (WARN_ON((len + arg->plen) > WLC_IOCTL_MAXLEN))
        return false;

    strcpy(buf, arg->iovar);
    if (arg->param)
        memcpy(buf + len, arg->param, arg->plen);

    return true;
}

static bool bcmwl_iovbss(struct bcmwl_ioctl_arg *arg, void *buf)
{
    const struct bcmwl_ioctl_num_conv *conv;
    const char *prefix = "bsscfg:";
    size_t len;
    int *idx;

    len = 0 ;
    len += strlen(prefix);
    len += strlen(arg->iovar) + 1;
    idx = (int *)(buf + len);
    len += sizeof(*idx);

    if (WARN_ON(!(conv = bcmwl_ioctl_lookup_num_conv(arg->ifname))))
        return false;
    if (WARN_ON(len > WLC_IOCTL_MAXLEN))
        return false;
    if (WARN_ON((len + arg->plen) > WLC_IOCTL_MAXLEN))
        return false;

    strcpy(buf, prefix);
    strcat(buf, arg->iovar);
    *idx = conv->dtoh32(arg->bsscfgidx);
    if (arg->param)
        memcpy(buf + len, arg->param, arg->plen);

    return true;
}

bool bcmwl_ioctl(struct bcmwl_ioctl_arg *arg)
{
    char buf[WLC_IOCTL_MAXLEN];
    struct ifreq ifr;
    dhd_ioctl_t ioc;
    bool ok = true;
    int sock;
    int err;

    if (arg->len > sizeof(buf))
        return false;

    memset(&ioc, 0, sizeof(ioc));
    memset(buf, 0, sizeof(buf));

    ioc.cmd = arg->cmd;
    ioc.buf = buf;
    ioc.len = sizeof(buf);
    ioc.set = arg->set;
    ioc.driver = arg->dongle ? DHD_IOCTL_MAGIC : 0;

    if (arg->iovar && arg->bsscfg)
        ok &= bcmwl_iovbss(arg, buf);
    else if (arg->iovar)
        ok &= bcmwl_iov(arg, buf);
    else if (!arg->iovar)
        ok &= bcmwl_ioc(arg, buf);

    if (WARN_ON(!ok))
        return false;

    memset(&ifr, 0, sizeof(ifr));
    STRSCPY(ifr.ifr_name, arg->ifname);
    ifr.ifr_data = (void *)&ioc;

    if (WARN_ON((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0))
        return false;

    err = ioctl(sock, SIOCDEVPRIVATE, &ifr);
    LOGT("%s: %s: iovar=%s cmd=%d set=%d dongle=%d plen=%zd len=%d err=%d",
         __func__,
         arg->ifname,
         arg->iovar ?: "",
         arg->cmd,
         arg->set,
         arg->dongle,
         arg->plen,
         ioc.len,
         err);

    close(sock);

    if (arg->buf)
        memcpy(arg->buf, buf, arg->len);

    return err == 0;
}

char *
bcmwl_wl_exec(const char *ifname,
              const char *prog,
              const char *name,
              const char *args[])
{
    const char *argv[32];
    const char **last = argv + ARRAY_SIZE(argv) - 1;
    const char **arg = argv;
    char *buf;

    *arg++ = prog;
    *arg++ = "-i";
    *arg++ = ifname;
    *arg++ = name;

    while (*args && arg < last)
        *arg++ = *args++;

    WARN_ON(*args && arg == last);
    *arg++ = NULL;

    buf = strexread(prog, argv);
    LOGT("%s: iovar '%s' slowpath result '%s'", ifname, name, buf ?: "(nil)");
    return buf;
}

struct bcmwl_wl {
    const char *name;
    bool dongle;
    int get;
    int set;
    char *(*fn)(const char *ifname, const struct bcmwl_wl *wl, const char *argv[]);
    char *(*postproc)(const char *ifname, const struct bcmwl_wl *wl, const char *argv[], char *);
};

static char *
bcmwl_wl_int(const char *ifname, const struct bcmwl_wl *wl, const char *argv[])
{
    const struct bcmwl_ioctl_num_conv *conv;
    const char *set = *argv++;
    unsigned int magic;
    bool is_dongle = false;
    bool bitmask;
    int ri;
    int vi;
    int val;
    int seti;

    if (WARN_ON(!bcmwl_parse_vap(ifname, &ri, &vi)))
        return NULL;

    if (WARN_ON(!(conv = bcmwl_ioctl_lookup_num_conv(ifname))))
        return NULL;

    if (wl->dongle && bcmwl_DHDGIOC(ifname, DHD_GET_MAGIC, NULL, &magic)) {
        is_dongle = magic == DHD_IOCTL_MAGIC ||
                    magic == bswap_32(DHD_IOCTL_MAGIC);
    }

    /* The minus (-) sign conflicts with signed integer
     * parsing. Only some iovars in wlctl seem to be
     * bitmask aware so make them an exception.
     */
    bitmask = !strcmp(wl->name, "rrm")
           || !strcmp(wl->name, "wnm");

    if (set || wl->get == -1) {
        if (set) {
            if (bitmask && (set[0] == '+' || set[0] == '-')) {
                if (WARN_ON(sscanf(set+1, "%i", &seti) != 1) &&
                    WARN_ON(sscanf(set+1, "%d", &seti) != 1))
                    return NULL;

                if (wl->get == WLC_GET_VAR) {
                    if (is_dongle) {
                        if (!bcmwl_DHDGIOVBSS(ifname, wl->name, vi, NULL, &val))
                            return NULL;
                    } else {
                        if (!bcmwl_GIOV(ifname, wl->name, NULL, &val))
                            return NULL;
                    }
                } else {
                    if (is_dongle) {
                        WARN_ON(1);
                        return NULL;
                    } else {
                        if (!bcmwl_GIOC(ifname, wl->get, NULL, &val))
                            return NULL;
                    }
                }

                if (set[0] == '+')
                    val |= seti;
                if (set[0] == '-')
                    val &= ~seti;
            } else {
                if (WARN_ON(sscanf(set, "%i", &seti) != 1) &&
                    WARN_ON(sscanf(set, "%d", &seti) != 1))
                    return NULL;

                val = seti;
            }
        } else {
            val = 0;
        }

        val = conv->dtoh32(val);
        if (wl->set == WLC_SET_VAR) {
            if (is_dongle)  {
                if (!bcmwl_DHDSIOVBSS(ifname, wl->name, vi, &val))
                    return NULL;
            } else {
                if (!bcmwl_SIOV(ifname, wl->name, &val))
                    return NULL;
            }
        } else {
            if (!bcmwl_SIOC(ifname, wl->set, &val))
                return NULL;
        }

        return strdup("");
    } else {
        if (wl->get == WLC_GET_VAR) {
            if (is_dongle)  {
                if (!bcmwl_DHDGIOVBSS(ifname, wl->name, vi, NULL, &val))
                    return NULL;
            } else {
                if (!bcmwl_GIOV(ifname, wl->name, NULL, &val))
                    return NULL;
            }
        } else {
            if (!bcmwl_GIOC(ifname, wl->get, NULL, &val))
                return NULL;
        }

        val = conv->dtoh32(val);
        return strdup(strfmta("%d", val));
    }
}

static char *
bcmwl_wl_bss(const char *ifname, const struct bcmwl_wl *wl, const char *argv[])
{
    const struct bcmwl_ioctl_num_conv *conv;
    const char *set = *argv++;
    unsigned int val[2];

    if (WARN_ON(!(conv = bcmwl_ioctl_lookup_num_conv(ifname))))
        return NULL;

    if (set) {
        if (!strcmp(set, "up"))
            val[1] = 1;
        else if (!strcmp(set, "down"))
            val[1] = 0;
        else if (WARN_ON(1))
            return NULL;

        val[0] = conv->dtoh32(-1);
        val[1] = conv->dtoh32(val[1]);
        if (!bcmwl_SIOV(ifname, wl->name, &val))
            return NULL;

        return strdup("");
    } else {
        val[0] = conv->dtoh32(-1);

        if (!bcmwl_GIOV(ifname, wl->name, &val, &val))
            return NULL;

        val[0] = conv->dtoh32(val[0]);
        return strdup(strfmta("%s", val[0] ? "up" : "down"));
    }
}

static char *
bcmwl_wl_mac(const char *ifname, const struct bcmwl_wl *wl, const char *argv[])
{
    const struct bcmwl_ioctl_num_conv *conv;
    const char *set = *argv++;
    struct ether_addr ea;
    char macstr[18];

    if (WARN_ON(!(conv = bcmwl_ioctl_lookup_num_conv(ifname))))
        return NULL;

    if (set) {
        if (WARN_ON(sscanf(set, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                           &ea.octet[0], &ea.octet[1], &ea.octet[2],
                           &ea.octet[3], &ea.octet[4], &ea.octet[5]) != 6))
            return NULL;

        if (wl->set == WLC_SET_VAR) {
            if (!bcmwl_SIOV(ifname, wl->name, &ea))
                return NULL;
        } else {
            if (!bcmwl_SIOC(ifname, wl->set, &ea))
                return NULL;
        }

        return strdup("");
    } else {
        if (wl->get == WLC_GET_VAR) {
            if (!bcmwl_GIOV(ifname, wl->name, NULL, &ea))
                return NULL;
        } else {
            if (!bcmwl_GIOC(ifname, wl->get, NULL, &ea))
                return NULL;
        }

        snprintf(macstr, sizeof(macstr),
                "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                ea.octet[0], ea.octet[1], ea.octet[2],
                ea.octet[3], ea.octet[4], ea.octet[5]);

        return strdup(strfmta("%s", macstr));
    }
}

static char *
bcmwl_wl_maclist(const char *ifname, const struct bcmwl_wl *wl, const char *argv[])
{
    const struct bcmwl_ioctl_num_conv *conv;
    const char *set = *argv++;
    const char *macstr;
    struct {
        unsigned int count;
        struct ether_addr mac[256];
    } maclist;
    char buf[8192];
    unsigned int i;

    if (WARN_ON(!(conv = bcmwl_ioctl_lookup_num_conv(ifname))))
        return NULL;

    if (set) {
        WARN_ON(1);
        return NULL;
    } else {
        maclist.count = ARRAY_SIZE(maclist.mac);

        if (!bcmwl_GIOV(ifname, wl->name, &maclist, &maclist))
            return NULL;

        maclist.count = conv->dtoh32(maclist.count);
        buf[0] = 0;
        for (i = 0; i < maclist.count; i++) {
            macstr = strfmta("%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n",
                             maclist.mac[i].octet[0], maclist.mac[i].octet[1],
                             maclist.mac[i].octet[2], maclist.mac[i].octet[3],
                             maclist.mac[i].octet[4], maclist.mac[i].octet[5]);
            WARN_ON(strscat(buf, macstr, sizeof(buf)) < 0);
        }

        return strdup(buf);
    }
}

struct bcmwl_wl_he {
    const char *name;
    int cmd; /* WL_HE_CMD_* from wlioctl.h */
    int type; /* IOVT_* from bcmutils.h */
    char *(*fn)(const char *ifname,
                const struct bcmwl_wl *wl,
                const struct bcmwl_wl_he *cmd,
                const char *argv[]);
};

static char *
bcmwl_wl_he_int(const char *ifname,
                const struct bcmwl_wl *wl,
                const struct bcmwl_wl_he *cmd,
                const char *argv[])
{
    const struct bcmwl_ioctl_num_conv *conv;
    struct {
        uint16 id;
        uint16 len;
        union {
            uint8 u8;
            uint32 u32;
        } __attribute__((packed)) u;
    } __attribute__((packed)) req;
    union {
        uint8 u8;
        uint32 u32;
    } __attribute__((packed)) resp;
    const char *set = *argv++;
    size_t len;

    if (WARN_ON(!(conv = bcmwl_ioctl_lookup_num_conv(ifname))))
        return NULL;

    if (set) {
        memset(&req, 0, sizeof(req));

        switch (cmd->type) {
        case IOVT_UINT8:
            req.u.u8 = atoi(set);
            len = sizeof(req.u.u8);
            break;
        case IOVT_UINT32:
            req.u.u32 = conv->dtoh32(atoi(set));
            len = sizeof(req.u.u32);
            break;
        default:
            WARN_ON(1);
            return NULL;
        }

        req.id = conv->dtoh16(cmd->cmd);
        req.len = conv->dtoh16(len);

        if (!bcmwl_SIOV(ifname, wl->name, &req))
            return NULL;

        return strdup("");
    } else {
        req.id = conv->dtoh16(cmd->cmd);
        req.len = 0;

        if (!bcmwl_GIOV(ifname, wl->name, &req, &resp))
            return NULL;

        switch (cmd->type) {
            case IOVT_UINT8:
                return strfmt("%hhu", resp.u8);
            case IOVT_UINT32:
                resp.u32 = conv->dtoh32(resp.u32);
                return strfmt("%u", resp.u32);
            default:
                WARN_ON(1);
                return NULL;
        }
    }
}

#define WL_HE_CMD_INVALID -1
#ifndef WL_HE_VER_1
/* Defining as invalid so that the entries below don't need
 * to be ifdef-ed and to avoid compiler complaints on unused
 * static functions.
 */
#define WL_HE_CMD_ENAB WL_HE_CMD_INVALID
#define WL_HE_CMD_FEATURES WL_HE_CMD_INVALID
#endif

static const struct bcmwl_wl_he g_bcmwl_wl_he[] = {
    { "enab", WL_HE_CMD_ENAB, IOVT_UINT8, bcmwl_wl_he_int },
    { "features", WL_HE_CMD_FEATURES, IOVT_UINT32, bcmwl_wl_he_int },
    {}, /* guard, keep last */
};

static char *
bcmwl_wl_he(const char *ifname, const struct bcmwl_wl *wl, const char *argv[])
{
    const struct bcmwl_wl_he *cmd;
    const char *name = *argv ?: "enab";

    for (cmd = g_bcmwl_wl_he; cmd->name; cmd++)
        if (!strcmp(cmd->name, name) && cmd->cmd != WL_HE_CMD_INVALID)
            break;

    if (!cmd->name)
        return bcmwl_wl_exec(ifname, "wlctl", wl->name, argv);

    /* this was consumed by `name` but wasn't advanced until
     * now so that it could be passed to the fallback above
     */
    argv++;

    return cmd->fn(ifname, wl, cmd, argv);
}

static char *
bcmwl_wl_cmd_prefix(const char *ifname, const struct bcmwl_wl *wl, const char *argv[], char *const in)
{
    char tmp[8192];
    char *lines = in;
    char *line;
    char *p = tmp;
    size_t len = sizeof(tmp);

    tmp[0] = 0;
    while ((line = strsep(&lines, "\r\n")))
        if (strlen(line) > 0)
            csnprintf(&p, &len, "%s %s\n", wl->name, line);

    free(in);
    return strdup(tmp);
}

static char *
bcmwl_wl_cmd_wpa(const char *ifname, const struct bcmwl_wl *wl, const char *argv[], char *const in)
{
    char tmp[8192];
    char *p = tmp;
    size_t len = sizeof(tmp);

    csnprintf(&p, &len, "0x%02x", atoi(in));
    if (atoi(in) & 4)
        csnprintf(&p, &len, " WPA-PSK");
    if (atoi(in) & 128)
        csnprintf(&p, &len, " WPA2-PSK");
    if (atoi(in) & 2)
        csnprintf(&p, &len, " WPA-802.1x");
    if (atoi(in) & 64)
        csnprintf(&p, &len, " WPA2-802.1x");

    free(in);
    return strdup(tmp);
}

static const struct bcmwl_wl g_bcmwl_wl[] = {
    { "apsta", false, WLC_GET_VAR, WLC_SET_VAR, bcmwl_wl_int, NULL },
    { "bss", false, WLC_GET_VAR, WLC_SET_VAR, bcmwl_wl_bss, NULL },
    { "wme_apsd", false, WLC_GET_VAR, WLC_SET_VAR, bcmwl_wl_int, NULL },
    { "closednet", false, WLC_GET_VAR, WLC_SET_VAR, bcmwl_wl_int, NULL },
    { "map", false, WLC_GET_VAR, WLC_SET_VAR, bcmwl_wl_int, NULL },
    { "dynbcn", false, WLC_GET_VAR, WLC_SET_VAR, bcmwl_wl_int, NULL },
    { "fbt", false, WLC_GET_VAR, WLC_SET_VAR, bcmwl_wl_int, NULL },
    { "mbss", false, WLC_GET_VAR, WLC_SET_VAR, bcmwl_wl_int, NULL },
    { "ap", false, WLC_GET_AP, WLC_SET_AP, bcmwl_wl_int, NULL },
    /* The "ap" iovar works only if "apsta" is enabled, but
     * that can't be easily done automatically because it
     * would break AP-only platforms. It would need a
     * kconfig and a rework anyway.
     *
     * { "ap", false, WLC_GET_VAR, WLC_SET_VAR, bcmwl_wl_int },
     */
    { "rrm", false, WLC_GET_VAR, WLC_SET_VAR, bcmwl_wl_int, NULL },
    { "wnm", false, WLC_GET_VAR, WLC_SET_VAR, bcmwl_wl_int, NULL },
    { "probresp_mac_filter", false, WLC_GET_VAR, WLC_SET_VAR, bcmwl_wl_int, NULL },
    { "authresp_mac_filter", false, WLC_GET_VAR, WLC_SET_VAR, bcmwl_wl_int, NULL },
    { "probresp_sw", false, WLC_GET_VAR, WLC_SET_VAR, bcmwl_wl_int, NULL },
    { "obss_coex", false, WLC_GET_VAR, WLC_SET_VAR, bcmwl_wl_int, NULL },
    { "wds_type", false, WLC_GET_VAR, WLC_SET_VAR, bcmwl_wl_int, NULL },
    { "vhtmode", false, WLC_GET_VAR, WLC_SET_VAR, bcmwl_wl_int, NULL },
    { "he", false, WLC_GET_VAR, WLC_SET_VAR, bcmwl_wl_he, NULL },
    { "nmode", false, WLC_GET_VAR, WLC_SET_VAR, bcmwl_wl_int, NULL },
    { "mpc", false, WLC_GET_VAR, WLC_SET_VAR, bcmwl_wl_int, NULL },
    { "dfs_preism", false, WLC_GET_VAR, WLC_SET_VAR, bcmwl_wl_int, NULL },
    { "wpa_auth", false, WLC_GET_VAR, WLC_SET_VAR, bcmwl_wl_int, bcmwl_wl_cmd_wpa },
    { "keep_ap_up", false, WLC_GET_VAR, WLC_SET_VAR, bcmwl_wl_int, NULL },
    { "rssi", false, WLC_GET_RSSI, -1, bcmwl_wl_int, NULL },
    { "macmode", false, WLC_GET_MACMODE, WLC_SET_MACMODE, bcmwl_wl_int, NULL },
    { "radar", false, WLC_GET_RADAR, WLC_SET_RADAR, bcmwl_wl_int, NULL },
    { "up", false, -1, WLC_UP, bcmwl_wl_int, NULL },
    { "down", false, -1, WLC_DOWN, bcmwl_wl_int, NULL },
    { "isup", false, WLC_GET_UP, -1, bcmwl_wl_int, NULL },
    { "bi", false, WLC_GET_BCNPRD, WLC_SET_BCNPRD, bcmwl_wl_int, NULL },
    { "eap", false, WLC_GET_EAP_RESTRICT, WLC_SET_EAP_RESTRICT, bcmwl_wl_int, NULL },
    { "eap_restrict", false, WLC_GET_VAR, WLC_SET_VAR, bcmwl_wl_int, NULL },
    { "wsec", false, WLC_GET_WSEC, WLC_SET_WSEC, bcmwl_wl_int, NULL },
    { "wsec_restrict", false, WLC_GET_VAR, WLC_SET_VAR, bcmwl_wl_int, NULL },
    { "wmf_bss_enable", true, WLC_GET_VAR, WLC_SET_VAR, bcmwl_wl_int, NULL },
    { "ap_isolate", true, WLC_GET_VAR, WLC_SET_VAR, bcmwl_wl_int, NULL },
    { "cur_etheraddr", false, WLC_GET_VAR, WLC_SET_VAR, bcmwl_wl_mac, bcmwl_wl_cmd_prefix },
    { "bssid", false, WLC_GET_BSSID, -1, bcmwl_wl_mac, NULL },
    { "wds_remote_mac", false, WLC_WDS_GET_REMOTE_HWADDR, WLC_WDS_GET_REMOTE_HWADDR, bcmwl_wl_mac, NULL },
    { "autho_sta_list", false, WLC_GET_VAR, WLC_SET_VAR, bcmwl_wl_maclist, bcmwl_wl_cmd_prefix },
    { "phy_tempsense", false, WLC_GET_VAR, -1, bcmwl_wl_int, NULL },
    { "txchain", false, WLC_GET_VAR, WLC_SET_VAR, bcmwl_wl_int, NULL },
    { NULL },
};

static bool
bcmwl_wl_fastpath_is_enabled(void)
{
    if (!kconfig_enabled(CONFIG_BCM_PREFER_IOV))
        return false;

    if (!strcmp(getenv("FASTPATH_DISABLED") ?: "", "y"))
        return false;

    return true;
}

/* returns heap allocated memory, the caller must free() it */
char *
bcmwl_wl(const char *ifname, const char *prog, const char *args[])
{
    const struct bcmwl_wl *wl = g_bcmwl_wl;
    const char *name = *args++;
    char *buf;

    bcmwl_ioctl_init();

    if (WARN_ON(!name))
        return NULL;

    if (bcmwl_wl_fastpath_is_enabled()) {
        for (; wl->name; wl++) {
            if (!strcmp(wl->name, name)) {
                buf = wl->fn(ifname, wl, args);
                if (buf && wl->postproc)
                    buf = wl->postproc(ifname, wl, args, buf);
                LOGT("%s: iovar '%s' fastpath result '%s'",
                     ifname, wl->name, buf ?: "(nil)");
                return buf;
            }
        }
    }

    return bcmwl_wl_exec(ifname, prog, name, args);
}
