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
 * General BCM utils
 *
 * TODO:
 * - use exectils instead of system, popen, etc...
 */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>


#include "log.h"
#include "bcmutil.h"
#include "util.h"


#define UTIL_NVRAM_PATH_SYS     "/bin/nvram"
#define UTIL_NVRAM_PATH_PLUME   "/usr/plume/tools/nvram"

#define UTIL_NVRAM_INIT()                   \
    do {                                    \
        if (g_util_nvram_init == false) {   \
            util_nvram_init();              \
        }                                   \
    } while (0)

/**
 * Globals
 */

static bool  g_util_nvram_init = false;
static char *g_util_nvram_path = NULL;

/**
 * Private
 */

static void util_nvram_init(void)
{
    // Find nvram tool path
    if (access(UTIL_NVRAM_PATH_SYS, X_OK) == 0)
    {
        g_util_nvram_path = UTIL_NVRAM_PATH_SYS;
    }
    else if (access(UTIL_NVRAM_PATH_PLUME, X_OK) == 0)
    {
        g_util_nvram_path = UTIL_NVRAM_PATH_PLUME;
    }
    else
    {
        LOGE("CLI tool 'nvram' not found!");
        return;
    }

    LOGN("%s: using %s", __func__, g_util_nvram_path);
    g_util_nvram_init = true;
}

/**
 * Public
 */

bool util_nvram_set(const char *name, const char *value)
{
    char cmd[512];

    UTIL_NVRAM_INIT();

    snprintf(cmd, sizeof(cmd), "%s set %s=%s",
             g_util_nvram_path,
             name,
             value);

    return !system(cmd);
}

bool util_nvram_get(const char *name, char *value, ssize_t len)
{
    char cmd[512];
    char buf[512];
    FILE *fp;
    bool success = false;

    UTIL_NVRAM_INIT();

    snprintf(cmd, sizeof(cmd), "%s get %s",
             g_util_nvram_path,
             name);

    fp = popen(cmd, "r");
    if (fp && fgets(buf, sizeof(buf), fp))
    {
        int len = strlen(buf);

        if (buf[len-1] == '\n')
            buf[len-1] = '\0';

        strscpy(value, buf, len);
        success = true;
    }

    if (fp)
        pclose(fp);

    return success;
}

bool util_nvram_unset(const char *name)
{
    char cmd[512];

    UTIL_NVRAM_INIT();

    snprintf(cmd, sizeof(cmd), "%s unset %s",
             g_util_nvram_path,
             name);

    return !system(cmd);
}

bool util_nvram_set_fmt(const char *fmt, ...)
{
    char        *name;
    char        *value;
    va_list     args;
    char        buf[512];

    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    // Get name and value
    value = strchr(buf, '=');
    if (value == NULL)
    {
        LOGE("Unexpected fmt string, must be in form of \"name=value\"");
        return -1;
    }

    name    = buf;
    *value  = 0;
    value  += 1;

    return util_nvram_set(name, value);
}

bool util_nvram_get_fmt(char *value, ssize_t len, const char *fmt, ...)
{
    char        *name;
    va_list     args;
    char        buf[512];

    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    name = buf;

    return util_nvram_get(name, value, len);
}

bool util_nvram_unset_fmt(const char *fmt, ...)
{
    char        *name;
    va_list     args;
    char        buf[512];

    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    name = buf;

    return util_nvram_unset(name);
}

bool util_wlctl_fmt(const char *fmt, ...)
{
    va_list     args;
    int         len;
    char        cmd[1024];

    len = 0;
    len = snprintf(cmd + len, sizeof(cmd) - len, "%s", "wlctl ");

    va_start(args, fmt);
    vsnprintf(cmd + len, sizeof(cmd) - len, fmt, args);
    va_end(args);

    LOGD("running wlctl command :: cmd=%s", cmd);

    return !system(cmd);
}
