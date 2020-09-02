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
#include <string.h>

#include "log.h"
#include "util.h"
#include "bcmwl.h"
#include "bcmwl_ioctl.h"

bool bcmwl_misc_send_action_frame(const char *ifname,
                                  const os_macaddr_t *hwaddr,
                                  const char *frame_hex)
{
    return strexpect("", "wl", "-i", ifname, "actframe",
                     strfmta(PRI(os_macaddr_t), FMT(os_macaddr_t, *hwaddr)),
                     frame_hex);
}

bool bcmwl_misc_is_valid_mac(const char *mac)
{
    unsigned int l[6];

    if (!mac || (strlen(mac) != strlen("xx:xx:xx:xx:xx:xx")))
        return false;

    if (6 != sscanf(mac, "%02x:%02x:%02x:%02x:%02x:%02x",
                    &l[0], &l[1], &l[2], &l[3], &l[4], &l[5]))
        return false;

    return true;
}

bool bcmwl_misc_is_rrm_enabled(const char *ifname,
                               bool *is_enabled)
{
    const char *output;

    if (WARN_ON(!(output = strexa("wl", "-i", ifname, "rrm"))))
    {
        return false;
    }

    if (strncmp(output, "0x1", 3) == 0)
    {
        *is_enabled = true;
        return true;
    }
    else if (strncmp(output, "0x0", 3) == 0)
    {
        *is_enabled = false;
        return true;
    }
    else
    {
        LOGE("Failed to check RRM support status! :: ifname=%s output='%s",
             ifname, output);
        return false;
    }
}

bool bcmwl_misc_is_wnm_enabled(const char*ifname,
                               bool *is_enabled)
{
    const char *output;

    if (WARN_ON(!(output = strexa("wl", "-i", ifname, "wnm"))))
    {
        return false;
    }

    if (strncmp(output, "0x1", 3) == 0)
    {
        *is_enabled = true;
        return true;
    }
    else if (strncmp(output, "0x0", 3) == 0)
    {
        *is_enabled = false;
        return true;
    }
    else
    {
        LOGE("Failed to check WNM support status! :: ifname=%s output='%s",
             ifname, output);
        return false;
    }
}

bool bcmwl_get_noise(const char *ifname, int *noise)
{
    const struct bcmwl_ioctl_num_conv *conv;
    if (WARN_ON(!(conv = bcmwl_ioctl_lookup_num_conv(ifname))))
        return false;
    if (WARN_ON(!bcmwl_GIOC(ifname, WLC_GET_PHY_NOISE, NULL, noise)))
        return false;
    *noise = conv->dtoh32(*noise);
    if (*noise >= 0)
        return false;
    return true;
}

bool
bcmwl_misc_set_neighbor(const char *ifname, const char *bssid, const char *bssid_info,
                        const char *regulatory, const char *channel, const char *phytype,
                        const char *prefer, const char *ssid)
{
    bcmwl_wlc_ver_t wlc_ver;
    const char *output;

    if (!bcmwl_wlc_ver(ifname, &wlc_ver))
    {
        /* Cyrus is known to lack "wl wlc_ver" support */
        output = WL(ifname, "rrm_nbr_add_nbr", bssid, bssid_info, regulatory, channel, phytype, prefer);
        WARN_ON(!output);
        return true;
    }

    if (wlc_ver.wlc_ver_major == 9)
    {
        /* Augustus */
        const char *chanspec = "0";
        output = WL(ifname, "rrm_nbr_add_nbr", bssid, bssid_info, regulatory, channel, phytype, ssid,
                    chanspec, prefer);
        WARN_ON(!output);
    }
    else
    {
        LOGW("Failed to add Neigbor due to unknown wlc version: %d.%d",
             wlc_ver.wlc_ver_major, wlc_ver.wlc_ver_minor);
        return false;
    }

    return !!output;
}

bool
bcmwl_misc_remove_neighbor(const char *ifname, const char *bssid)
{
    const char *output;

    output = WL(ifname, "rrm_nbr_del_nbr", bssid);
    WARN_ON(!output);

    return !!output;
}

bool
bcmwl_wlc_ver(const char *ifname, bcmwl_wlc_ver_t *ver)
{
    const struct bcmwl_ioctl_num_conv *conv;
    wl_wlc_version_t val;

    if (WARN_ON(!(conv = bcmwl_ioctl_lookup_num_conv(ifname))))
        return false;

    memset(&val, 0, sizeof(val));
    if (!bcmwl_GIOV(ifname, "wlc_ver", NULL, &val))
        return false;

    ver->wlc_ver_major = conv->dtoh16(val.wlc_ver_major);
    ver->wlc_ver_minor = conv->dtoh16(val.wlc_ver_minor);

    return true;
}
