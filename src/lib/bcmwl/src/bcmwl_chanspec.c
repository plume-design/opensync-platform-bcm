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
#include <stdbool.h>
#include <unistd.h>
#include <string.h>

#include "log.h"
#include "os.h"
#include "bcmwl.h"

#define MODULE_ID LOG_MODULE_ID_WL

#define BCMWL_CHANSPEC_MAX_RADIOS 4
#define BCMWL_CHANSPEC_IFNAME_LEN 16

typedef struct
{
    char ifname[BCMWL_CHANSPEC_IFNAME_LEN];
    int num;
    bcmwl_chanspec_t *cs_table;
} bcmwl_chanspec_table_t;

static bcmwl_chanspec_table_t bcmwl_chanspec_table[BCMWL_CHANSPEC_MAX_RADIOS];
static int bcmwl_chanspec_num;

/* sample chanspecs:
36 (0xd024)
36/80 (0xe02a)
36l (0xd826)
40 (0xd028)
40/80 (0xe12a)
40u (0xd926)
*/

bool bcmwl_chanspec_parse(char *str, bcmwl_chanspec_t *cs)
{
    int r;
    int n;
    char *p;

    r = sscanf(str, "%d%n", &cs->channel, &n);
    if (r != 1) return false;
    p = strchr(str, '(');
    if (!p) return false;
    r = sscanf(p+1, "%i", &cs->chanspec);
    if (r != 1) return false;
    if (!cs->channel || !cs->chanspec) return false;
    switch (str[n]) {
        case ' ':
            cs->bandwidth = 20;
            cs->sideband = 0;
        case 'l':
            cs->bandwidth = 40;
            cs->sideband = -1;
            break;
        case 'u':
            cs->bandwidth = 40;
            cs->sideband = 1;
            break;
        case '/': // "/80"
            cs->bandwidth = atoi(str+n+1);
            cs->sideband = 0;
            break;
        default:
            // unknown format
            return false;
    }
    //TRACE("Parsed '%s' %x %d %d %d", str, cs->chanspec, cs->channel, cs->sideband, cs->bandwidth);
    return true;
}

bool bcmwl_chanspec_load(char *ifname, bcmwl_chanspec_table_t *t)
{
    char *buf = NULL;
    bool result;
    int count;
    char *p, *nl;
    bcmwl_chanspec_t *cs;
    int i;

    result = os_cmd_exec(&buf, "wl -i %s chanspecs", ifname);
    if (!result) {
        if (buf) free(buf);
        return false;
    }

    // count number of lines
    count = 0;
    p = buf;
    while ((nl = strchr(p, '\n'))) {
        p = nl + 1;
        count++;
    }
    // alloc table
    cs = calloc(count, sizeof(*cs));
    if (!cs)
        return NULL;
    // parse lines
    i = 0;
    p = buf;
    while ((nl = strchr(p, '\n'))) {
        *nl = 0;
        if (!bcmwl_chanspec_parse(p, &cs[i])) {
            break;
        }
        p = nl + 1;
        i++;
    }
    free(buf);
    if (i == 0) {
        free(cs);
        return false;
    }
    t->cs_table = cs;
    t->num = i;
    STRSCPY(t->ifname, ifname);
    TRACE("chanspecs %s: %d", ifname, t->num);

    return true;
}

bcmwl_chanspec_table_t* bcmwl_chanspec_get_table(char *ifname)
{
    bcmwl_chanspec_table_t *t;
    int i;
    for (i = 0; i < bcmwl_chanspec_num; i++) {
        t = &bcmwl_chanspec_table[i];
        if (!strcmp(ifname, t->ifname)) {
            return t;
        }
    }
    if (bcmwl_chanspec_num >= BCMWL_CHANSPEC_MAX_RADIOS) {
        return NULL;
    }
    t = &bcmwl_chanspec_table[bcmwl_chanspec_num];
    if (!bcmwl_chanspec_load(ifname, t)) {
        return NULL;
    }
    bcmwl_chanspec_num++;
    return t;
}

/* get chanspec info
 * input:
 *   ifname (wl0, wl1)
 *   chanspec (eg 0x1803)
 * output:
 *   channel (1-14, 36-216)
 *   bandwidth (20,40,80)
 *   sideband (for 40bw: -1=lower 0=none 1=upper)
 */
bcmwl_chanspec_t* bcmwl_chanspec_get(char *ifname, int chanspec)
{
    bcmwl_chanspec_table_t *t;
    bcmwl_chanspec_t *cs;
    int i;
    t = bcmwl_chanspec_get_table(ifname);
    if (WARN_ON(!t))
        return NULL;
    for (i = 0; i < t->num; i++) {
        cs = &t->cs_table[i];
        if (chanspec == cs->chanspec) {
            return cs;
        }
    }
    return NULL;
}

