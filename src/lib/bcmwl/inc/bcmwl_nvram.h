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

#ifndef BCMWL_NVRAM_H_INCLUDED
#define BCMWL_NVRAM_H_INCLUDED

int bcmwl_nvram_append(const char *ifname, const char *prop, const char *needle,
                       int (*strcmp_fun) (const char*, const char*));

int bcmwl_nvram_remove(const char *ifname, const char *prop, const char *needle,
                       int (*strcmp_fun) (const char*, const char*));

#define bcmwl_nvram_set(ifname, prop, value) \
    strexa("nvram", "set", strfmta("%s_%s=%s", ifname, prop, value))
#define bcmwl_nvram_unset(ifname, prop) \
    strexa("nvram", "unset", strfmta("%s_%s", ifname, prop))
#define bcmwl_nvram_get(ifname, prop) \
    strexa("nvram", "get", strfmta("%s_%s", ifname, prop))

#define bcmwl_nvram_get_kv(k, v, i) \
    ((k = strsep(&i, "=")) && (v = strsep(&i, "")))
#define bcmwl_nvram_for_each(i, k, v, p) \
    for (k=v=0, p = strexa("nvram", "getall"); \
         p && (i = strsep(&p, "\r\n")) && bcmwl_nvram_get_kv(k, v, i); \
         k=v=0)

#define NVG(ifname, prop) bcmwl_nvram_get(ifname, prop)
#define NVS(ifname, prop, value) ((value) ? bcmwl_nvram_set(ifname, prop, value) : bcmwl_nvram_unset(ifname, prop))
#define NVU(ifname, prop) bcmwl_nvram_unset(ifname, prop)

#endif /* BCMWL_NVRAM_H_INCLUDED */
