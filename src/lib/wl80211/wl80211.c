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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <stdarg.h>
#include <errno.h>

#include "log.h"

#include "wl80211.h"

#define MODULE_ID LOG_MODULE_ID_WL

#define CR                          13
#define LF                          10

#define chop_str(buffer) \
{ \
    int i; \
    for (i = strlen(buffer) - 1; \
            ((i >= 0) && ((buffer[i] == CR) || (buffer[i] == LF))); i--) \
    { \
        buffer[i] = 0; \
    } \
}

#define split_str(str, delim, sub_str)      \
{                                           \
    sub_str = index(str, delim);            \
    *sub_str = '\0';                        \
    sub_str++;                              \
}

#define replace_char_in_str(str, c, r)                      \
{                                                           \
    acla_uint32_t loop_cnt;                                 \
    for (loop_cnt = 0; str[loop_cnt] != '\0'; loop_cnt++)   \
    if (str[loop_cnt] == c)                                 \
    str[loop_cnt] = r;                                      \
}

/******************************************************************************
 *  GLOBALS
 *****************************************************************************/

static bool g_wl80211_have_wl_escanresults = false;


/******************************************************************************
 *  PUBLIC definitions
 *****************************************************************************/

bool wl80211_init(void)
{
    static bool                     inited;
    FILE                           *fp;
    char                           *ptr;
    char                            buf[WL80211_CMD_BUFF_SIZE];

    if (inited) return true;

    // NOTE: we may have to consider detecting escanresults per radio in
    // the future. Also "wl -h" may not be reliable for detection and will
    // need to be replaced.
    fp = popen("wlctl -h | grep -ce '^escanresults'", "r");
    if (fp)
    {
        if (fgets(buf, sizeof(buf), fp)
            && (strtol(buf, &ptr, 10) != 0))
        {
            g_wl80211_have_wl_escanresults = true;
        }

        pclose(fp);
    }

    // Report capabilities
    LOGN("Using \"wl %s\" for neighbor scans...",
         g_wl80211_have_wl_escanresults ? "escanresults" : "scanresults");

    inited = true;
    return true;
}

bool wl80211_have_wl_escanresults(void)
{
    wl80211_init();
    return g_wl80211_have_wl_escanresults;
}

void wl80211_cmd_exec(char *buffer, int buffer_size, char *fmt, ...)
{
    va_list                         args;
    char                            cmd[WL80211_CMD_BUFF_SIZE];
    FILE                           *fp;
    int32_t                         ret = 0;
    char                           *tmp = NULL;

    if (NULL == buffer || buffer_size < 1) {
        return;
    }
    *buffer = 0;
    tmp = buffer;

    va_start(args, fmt);
    vsnprintf(cmd, sizeof(cmd) - 1, fmt, args);
    va_end(args);

    LOG(TRACE, "Processing: '%s'", cmd);

    fp = popen(cmd, "r");
    if (fp == NULL)
    {
        return;
    }

    /* Zero terminate max string */
    buffer_size--;

    /* Prevent failures due to signals (SIGCHLD) */
    while (!feof(fp) && buffer_size > 0)
    {
        ret = fread(tmp, 1, buffer_size, fp);
        if (ret < 0)
        {
            break;
        }
        tmp += ret;
        buffer_size -= ret;
    }
    pclose(fp);

    // zero terminate
    *tmp = 0;

    if (strlen(buffer) > 0)
    {
        chop_str(buffer);
    }

    LOG(TRACE, "Processed: '%s'", buffer);
}
