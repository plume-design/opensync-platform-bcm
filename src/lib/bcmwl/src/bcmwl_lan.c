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
 * bcmwl_lan
 *
 * Helpers to deal with:
 *  - lan_ifname
 *  - lan_ifnames
 *  - lan%d_ifname
 *  - lan%d_ifnames
 *
 * These nvram entries are used by nas/eapd for
 * authentication and supplicant purposes.
 */
#define _GNU_SOURCE

/* std libc */
#include <string.h>
#include <errno.h>
#include <dlfcn.h>

/* internal */
#include <log.h>
#include <util.h>
#include <bcmwl_nvram.h>
#include <bcmwl_lan.h>

#define DUMMY_WL_IFNAME "wl9"

int
bcmwl_lan_get_idx(const char *name)
{
    static const char *prefix = "lan";
    static const char *suffix = "ifname";
    char *buf = strdupa(name);
    char *i;
    int idx;

    if (!(i = strsep(&buf, "_")))
        return -1;
    if (strstr(i, prefix) != i)
        return -1;
    idx = atoi(i + strlen(prefix));
    if (!(i = strsep(&buf, "")))
        return -1;
    if (strcmp(i, suffix))
        return -1;
    return idx;
}

int
bcmwl_lan_validate(int idx)
{
    static char *(*get_ifname_by_wlmac)(unsigned char *mac, char *name);
    static void *lib1;
    static void *lib2;
    const char *br;

    if (!get_ifname_by_wlmac) {
        if (WARN_ON(!(lib1 = dlopen("libnvram.so", RTLD_LAZY | RTLD_GLOBAL))))
            return -1;
        if (!(lib2 = dlopen("libwlbcmshared.so", RTLD_LAZY | RTLD_GLOBAL)))
            if (WARN_ON(!(lib2 = dlopen("libshared.so", RTLD_LAZY | RTLD_GLOBAL))))
                return -1;
        if (WARN_ON(!(get_ifname_by_wlmac = dlsym(lib2, "get_ifname_by_wlmac"))))
            return -1;
    }

    NVS(DUMMY_WL_IFNAME, "ifname", DUMMY_WL_IFNAME);
    NVS(bcmwl_lan(idx), "ifname", DUMMY_WL_IFNAME);
    NVS(bcmwl_lan(idx), "ifnames", DUMMY_WL_IFNAME);
    br = get_ifname_by_wlmac(NULL, strdup(DUMMY_WL_IFNAME));
    NVU(DUMMY_WL_IFNAME, "ifname");
    NVU(bcmwl_lan(idx), "ifname");
    NVU(bcmwl_lan(idx), "ifnames");

    if (!br)
        LOGW("lan: failed to allocate lan%d, is WLIFU_MAX_NO_BRIDGE in wl too small?", idx);

    return br ? idx : -1;
}

int
bcmwl_lan_alloc(void)
{
    char *i, *k, *v, *p;
    unsigned used = 0;
    int idx;
    bcmwl_nvram_for_each(i, k, v, p)
        if ((idx = bcmwl_lan_get_idx(k)) >= 0)
            used |= 1 << idx;
    for (idx = 0; idx < 32; idx++)
        if (!(used & (1 << idx)))
            return bcmwl_lan_validate(idx);
    return -1;
}

int
bcmwl_lan_lookup(const char *bridge)
{
    char *i, *k, *v, *p;
    int idx;
    bcmwl_nvram_for_each(i, k, v, p)
        if ((idx = bcmwl_lan_get_idx(k)) >= 0)
            if (!strcmp(v, bridge))
                return idx;
    return -1;
}

char *
bcmwl_lan_search(const char *ifname)
{
    char *i, *k, *v, *p, *names, *name;
    int idx;
    bcmwl_nvram_for_each(i, k, v, p)
        if ((idx = bcmwl_lan_get_idx(k)) >= 0)
            if ((names = NVG(bcmwl_lan(idx), "ifnames")))
                while ((name = strsep(&names, " ")))
                    if (!strcmp(ifname, name))
                        return strdup(v); /* must be free()d! */
    return NULL;
}

void
bcmwl_lan_unset(const char *ifname)
{
    char *i, *k, *v, *p;
    int idx;
    bcmwl_nvram_for_each(i, k, v, p)
        if ((idx = bcmwl_lan_get_idx(k)) >= 0)
            if (bcmwl_nvram_remove(bcmwl_lan(idx), "ifnames", ifname, strcmp) == 0) {
                bcmwl_nvram_unset(bcmwl_lan(idx), "ifname");
                bcmwl_nvram_unset(bcmwl_lan(idx), "ifnames");
            }
}

bool
bcmwl_lan_set(const char *ifname, const char *bridge)
{
    int i;
    if (!strcmp(bridge, strdupafree(bcmwl_lan_search(ifname)) ?: "")) {
        LOGD("%s: already in %s", ifname, bridge);
        return true;
    }
    bcmwl_lan_unset(ifname);
    if ((i = bcmwl_lan_lookup(bridge)) < 0) {
        if ((i = bcmwl_lan_alloc()) < 0)
            return false;
        LOGI("%s: allocated lan %d for %s", ifname, i, bridge);
        if (!NVS(bcmwl_lan(i), "ifname", bridge)) {
            LOGW("%s: failed to set lan %d ifname to %s",
                 ifname, i, bridge);
            return false;
        }
    }
    if (bcmwl_nvram_append(bcmwl_lan(i), "ifnames", ifname, strcmp) < 0) {
        LOGW("%s: failed to append to lan %d ifnames", ifname, i);
        return false;
    }
    return true;
}

void
bcmwl_lan_reset(void)
{
    char *i, *k, *v, *p;
    int idx;
    bcmwl_nvram_for_each(i, k, v, p)
        if ((idx = bcmwl_lan_get_idx(k)) >= 0) {
            bcmwl_nvram_unset(bcmwl_lan(idx), "ifname");
            bcmwl_nvram_unset(bcmwl_lan(idx), "ifnames");
        }
}
