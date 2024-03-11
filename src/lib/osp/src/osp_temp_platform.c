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

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>

#include "log.h"
#include "ovsdb.h"
#include "const.h"
#include "memutil.h"
#include "osp_temp.h"
#include "wl80211_device.h"

#define BCM_CPU_TEMP_FILE "/sys/class/thermal/thermal_zone0/temp"


int osp_temp_get_temperature_cpu(const char *if_name, int *temp)
{
    int rv = -1;
    int fd = -1;
    char buf[128] = { 0 };

    fd = open(BCM_CPU_TEMP_FILE, O_RDONLY);
    if (fd < 0)
    {
        LOGE("Could not open cpu temperature file: %s", BCM_CPU_TEMP_FILE);
        goto err;
    }

    rv = read(fd, buf, sizeof(buf));
    if (rv < 0)
    {
        LOGE("Could not read cpu temperature: %d", rv);
        goto err;
    }

    rv = sscanf(buf, "%d\n", temp);
    if (rv != 1)
    {
        LOGE("Could not parse cpu temperature: %d", rv);
        goto err;
    }

    *temp /= 1000;
    rv = 0;

err:
    if (fd >= 0)
    {
        close(fd);
    }
    return rv;
}

int osp_temp_get_temperature_wl(const char *if_name, int *temp)
{
    bool rv;

    rv = wl80211_device_temp_results_get(if_name, temp);

    return rv ? 0 : 1;
}
