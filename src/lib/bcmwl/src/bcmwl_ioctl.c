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

#include "bcmwl.h"
#include "bcmwl_ioctl.h"

/*
 * Private
 */

#define NUM_CONV_SIZE 6

#define BCMWL_IOCTL_QUERY 0
#define BCMWL_IOCTL_SET 1

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

static bool wl_ioctl_wrapper(const char *ifname,
                             unsigned int ioctl_cmd,
                             unsigned int ioctl_set,
                             void *buf,
                             size_t buf_size)
{
    bool result = false;
    int wl_ioctl_sock = -1;
    wl_ioctl_t ioc;
    struct ifreq ifr;

    memset(&ioc, 0, sizeof(ioc));
    ioc.cmd = ioctl_cmd;
    ioc.buf = buf;
    ioc.len = buf_size;
    ioc.set = ioctl_set;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

    ifr.ifr_data = (char*) &ioc;

    if (WARN_ON((wl_ioctl_sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1))
        goto leave;

    if (ioctl(wl_ioctl_sock, SIOCDEVPRIVATE, &ifr) == -1)
        goto leave;

    result = true;

leave:
    close(wl_ioctl_sock);

    return result;
}

static bool bcmwl_detect_radio_endianness(const char *ifname,
                                          struct bcmwl_ioctl_num_conv *num_conv)
{
    uint32_t magic;
    uint32_t version;

    if (WARN_ON(!bcmwl_ioctl_get(ifname, WLC_GET_MAGIC, &magic, sizeof(magic))))
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

    if (WARN_ON(!bcmwl_ioctl_get(ifname, WLC_GET_VERSION, &version, sizeof(version))))
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

    if (WARN_ON(!(dir = opendir("/sys/class/net/"))))
        goto leave;

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

leave:
    closedir(dir);

    return result;
}

const struct bcmwl_ioctl_num_conv* bcmwl_ioctl_lookup_num_conv(const char *ifname)
{
    int wl_i;

    /* accept both PHY and VIF */
    if (!bcmwl_is_phy(ifname) && !bcmwl_is_vif(ifname))
        return NULL;

    wl_i = atoi(ifname + 2);
    if (WARN_ON(wl_i >= NUM_CONV_SIZE))
        return NULL;

    return &num_convs[wl_i];
}

bool bcmwl_ioctl_prepare_args_with_addr(void *buf,
                                        size_t buf_size,
                                        const char *wl_cmd,
                                        const os_macaddr_t *hwaddr)
{
    char *bytes = buf;
    const size_t wl_cmd_len = strlen(wl_cmd) + 1; // Include '\0'

    if (WARN_ON(wl_cmd_len + sizeof(hwaddr->addr) > buf_size))
        return false;

    memset(bytes, 0, buf_size);
    strncpy(bytes, wl_cmd, buf_size);
    memcpy(bytes + wl_cmd_len, hwaddr->addr, sizeof(hwaddr->addr));

    return true;
}

bool bcmwl_ioctl_set(const char *ifname,
                     unsigned int ioctl_cmd,
                     const void *buf,
                     size_t buf_size)
{
    void *tmp_buf = alloca(buf_size);
    memcpy(tmp_buf, buf, buf_size);
    return wl_ioctl_wrapper(ifname, ioctl_cmd, BCMWL_IOCTL_SET, tmp_buf, buf_size);
}

bool bcmwl_ioctl_get(const char *ifname,
                     unsigned int ioctl_cmd,
                     void *buf,
                     size_t buf_size)
{
    return wl_ioctl_wrapper(ifname, ioctl_cmd, BCMWL_IOCTL_QUERY, buf, buf_size);
}
