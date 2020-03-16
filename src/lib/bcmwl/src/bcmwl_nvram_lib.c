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

/* std libc */
#include <string.h>

/* internal */
#include <log.h>

/* bcm */
#include <wlcsm_lib_api.h>

char *bcmwl_nvram_getall(void)
{
    char buf[256*1024];
    char *line = buf;
    int err;

    buf[sizeof(buf) - 1] = 0;
    err = wlcsm_nvram_getall(buf, sizeof(buf) - 1);
    if (WARN_ON(err)) /* buf is too small? bump it up */
        return NULL;

    for (; *line; line += strlen(line) + 1)
        if (line != buf)
            line[-1] = '\n';

    LOGT("%s: (len=%d) '%s'", __func__, strlen(buf), buf);
    return strdup(buf);
}

char *bcmwl_nvram_get(const char *ifname,
                      const char *name)
{
    char key[256];
    char *value;

    snprintf(key, sizeof(key), "%s_%s", ifname, name);
    value = wlcsm_nvram_get(key);
    LOGT("%s: '%s' = '%s'", __func__, key, value ?: "(none)");
    if (!value)
        return NULL;

    return strdup(value);
}

bool bcmwl_nvram_set(const char *ifname,
                     const char *name,
                     const char *value)
{
    char key[256];
    char *copy = value ? strdup(value) : NULL;
    int err;

    snprintf(key, sizeof(key), "%s_%s", ifname, name);
    err = wlcsm_nvram_set(key, copy);
    free(copy);
    LOGT("%s: (err=%d) '%s' = '%s'", __func__, err, key, value ?: "(none)");
    if (err)
        return false;

    return true;
}
