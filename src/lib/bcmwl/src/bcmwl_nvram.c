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

/**
 * bcmwl_nvram
 *
 * Helpers to deal with nvram word list based entries, such as:
 *  - wl%d_vifs,
 *  - wl%d_maclist
 *  - lan_ifnames
 *  - lan%d_ifnames
 */
#define _GNU_SOURCE

/* std libc */
#include <string.h>
#include <errno.h>

/* internal */
#include <log.h>
#include <util.h>
#include <bcmwl_nvram.h>

int bcmwl_nvram_append(const char *ifname, const char *prop, const char *needle,
                       int (*strcmp_fun) (const char*, const char*))
{
    const char *o = NVG(ifname, prop) ?: "";
    const char *v;
    char *m;

    m = strdupa(o);
    while ((v = strsep(&m, " "))) {
        if (strcmp_fun(v, needle) == 0) {
            return 0;
        }
    }

    v = strchomp(strfmta("%s %s", needle, o), " ");
    if (!NVS(ifname, prop, v)) {
        LOGW("%s: failed to set '%s' to '%s' to remove '%s'",
             ifname, prop, v, needle);
        return -1;
    }
    return strlen(v);
}

int bcmwl_nvram_remove(const char *ifname, const char *prop, const char *needle,
                       int (*strcmp_fun) (const char*, const char*))
{
    const char *v = strchomp(strdel(NVG(ifname, prop) ?: strdupa(""), needle, strcmp_fun), " ");
    if (!NVS(ifname, prop, v)) {
        LOGW("%s: failed to set '%s' to '%s' to remove '%s'",
             ifname, prop, v, needle);
        return -1;
    }
    return strlen(v);
}
