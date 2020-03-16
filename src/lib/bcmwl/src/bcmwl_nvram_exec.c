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
#include <string.h>

/* internal */
#include <util.h>
#define DUP(buf) bcmwl_nvram_dup(buf)
#define NVRAM CONFIG_BCM_NVRAM_EXEC_PATH

static char *bcmwl_nvram_dup(const char *buf)
{
    return buf ? strdup(buf) : NULL;
}

char *bcmwl_nvram_getall(void)
{
    return DUP(strexa(NVRAM, "getall"));
}

char *bcmwl_nvram_get(const char *ifname,
                      const char *name)
{
    return DUP(strexa(NVRAM, "get", strfmta("%s_%s", ifname, name)));
}

bool bcmwl_nvram_set(const char *ifname,
                     const char *name,
                     const char *value)
{
    const char *p;
    if (value)
        p = strexa(NVRAM, "set", strfmta("%s_%s=%s", ifname, name, value));
    else
        p = strexa(NVRAM, "unset", strfmta("%s_%s", ifname, name));
    return p && strlen(p) == 0 ? true : false;
}
