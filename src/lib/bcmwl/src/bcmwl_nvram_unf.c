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
#include <dlfcn.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/* internal */
#include "bcmwl_nvram.h"
#include "util.h"
#include <log.h>

struct bcmwl_nvram_unf
{
    void *handle;
    char *(*nvram_unf_get)(const char *name);
    char *(*nvram_unf_kget)(const char *name);
    char *(*nvram_get)(const char *name);
    int (*nvram_set)(const char *name, const char *value);
    int (*nvram_unset)(const char *name);
    int (*nvram_getall)(char *buf, int count);
    int (*nvram_set_bitflag)(const char *name, const int bit, const int value);
};

static struct bcmwl_nvram_unf g_bcmwl_nvram_unf;

void bcmwl_nvram_init(void)
{
    const bool already_initialized = (g_bcmwl_nvram_unf.handle != NULL);
    if (already_initialized) return;

    g_bcmwl_nvram_unf.handle = dlopen("libnvram.so", RTLD_LAZY);
    if (!g_bcmwl_nvram_unf.handle)
    {
        LOGW("%s: dlopen(libnvram.so): %s", __func__, dlerror());
        return;
    }

    g_bcmwl_nvram_unf.nvram_unf_get = dlsym(g_bcmwl_nvram_unf.handle, "nvram_unf_get");
    g_bcmwl_nvram_unf.nvram_unf_kget = dlsym(g_bcmwl_nvram_unf.handle, "nvram_unf_kget");
    g_bcmwl_nvram_unf.nvram_get = dlsym(g_bcmwl_nvram_unf.handle, "nvram_get");
    g_bcmwl_nvram_unf.nvram_set = dlsym(g_bcmwl_nvram_unf.handle, "nvram_set");
    g_bcmwl_nvram_unf.nvram_unset = dlsym(g_bcmwl_nvram_unf.handle, "nvram_unset");
    g_bcmwl_nvram_unf.nvram_getall = dlsym(g_bcmwl_nvram_unf.handle, "nvram_getall");
    g_bcmwl_nvram_unf.nvram_set_bitflag = dlsym(g_bcmwl_nvram_unf.handle, "nvram_set_bitflag");
}

char *bcmwl_nvram_getall(void)
{
    char buf[256 * 1024];
    char *line = buf;
    int err;

    if (WARN_ON(g_bcmwl_nvram_unf.nvram_getall == NULL)) return NULL;

    buf[sizeof(buf) - 1] = 0;
    err = g_bcmwl_nvram_unf.nvram_getall(buf, sizeof(buf) - 1);
    if (WARN_ON(err)) return NULL;

    for (; *line; line += strlen(line) + 1)
        if (line != buf) line[-1] = '\n';

    LOGT("%s: (len=%zu) '%s'", __func__, strlen(buf), buf);
    return strdup(buf);
}

char *bcmwl_nvram_get_key(const char *name)
{
    if (WARN_ON(g_bcmwl_nvram_unf.nvram_unf_get == NULL)) return NULL;

    char *value = g_bcmwl_nvram_unf.nvram_unf_get(name);
    LOGT("%s: '%s' = '%s'", __func__, name, value ?: "(none)");
    return value;
}

char *bcmwl_nvram_kget_key(const char *name)
{
    if (WARN_ON(g_bcmwl_nvram_unf.nvram_unf_kget == NULL)) return NULL;

    char *value = g_bcmwl_nvram_unf.nvram_unf_kget(name);
    LOGT("%s: '%s' = '%s'", __func__, name, value ?: "(none)");
    return value;
}

char *bcmwl_nvram_get(const char *ifname, const char *name)
{
    const char *key = strfmta("%s_%s", ifname, name);
    char *value;

    if (WARN_ON(g_bcmwl_nvram_unf.nvram_get == NULL)) return NULL;

    value = g_bcmwl_nvram_unf.nvram_get(key);
    LOGT("%s: '%s' = '%s'", __func__, key, value ?: "(none)");
    if (!value) return NULL;
    return strdup(value);
}

bool bcmwl_nvram_set(const char *ifname, const char *name, const char *value)
{
    const char *key = strfmta("%s_%s", ifname, name);
    int err;

    if (WARN_ON(g_bcmwl_nvram_unf.nvram_set == NULL)) return false;
    if (WARN_ON(g_bcmwl_nvram_unf.nvram_unset == NULL)) return false;

    if (value)
        err = g_bcmwl_nvram_unf.nvram_set(key, value);
    else
        err = g_bcmwl_nvram_unf.nvram_unset(key);

    LOGT("%s: (err=%d) '%s' = '%s'", __func__, err, key, value ?: "(none)");
    return err == 0;
}

bool bcmwl_nvram_set_flag(const char *ifname, const char *name, const int bit, const bool value)
{
    const char *key = strfmta("%s_%s", ifname, name);
    int err;

    if (WARN_ON(g_bcmwl_nvram_unf.nvram_set_bitflag == NULL)) return false;

    err = g_bcmwl_nvram_unf.nvram_set_bitflag(key, bit, value ? 1 : 0);
    LOGT("%s: (err=%d) '%s' bit=%d val=%d", __func__, err, key, bit, value ? 1 : 0);
    return err == 0;
}
