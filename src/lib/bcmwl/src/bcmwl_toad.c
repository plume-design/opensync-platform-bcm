/*
* Copyright (c) 2021, Sagemcom.
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
* 1. Redistributions of source code must retain the above copyright notice,
*    this list of conditions and the following disclaimer.
*
* 2. Redistributions in binary form must reproduce the above copyright notice,
*    this list of conditions and the following disclaimer in the documentation
*    and/or other materials provided with the distribution.
*
* 3. Neither the name of the copyright holder nor the names of its contributors
*    may be used to endorse or promote products derived from this software
*    without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
* LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
* CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
* SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
* CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <net/if.h>

#include "target.h"
#include "log.h"
#include "schema.h"
#include "kconfig.h"

#include "bcmwl.h"
#include "bcmwl_nvram.h"
#include "bcmwl_toad.h"
#include "daemon.h"

struct bcmwl_toad
{
    daemon_t toad_proc;
    char ifname[IFNAMSIZ];
    struct ds_dlist_node    list;
};

static ds_dlist_t g_wl_toad_list = DS_DLIST_INIT(struct bcmwl_toad, list);
static bool g_toad_init=true;
static int g_rule_index=1;

static bool bcmwl_toad_daemon_start(struct bcmwl_toad *node)
{
    if (!node)
    {
        return false;
    }

    if (!daemon_init(&node->toad_proc, CONFIG_BCM_TOAD_PATH, DAEMON_LOG_ALL))
    {
        return false;
    }
    daemon_arg_add(&node->toad_proc, "-i", node->ifname);
    daemon_arg_add(&node->toad_proc, "-D", "00000002");

    if (!daemon_start(&node->toad_proc))
    {
        return false;
    }
    return true;
}

static struct bcmwl_toad *bcmwl_toad_find(const char *if_name)
{
    struct bcmwl_toad *node;
    ds_dlist_foreach(&g_wl_toad_list, node)
    {
        if (!strncmp(if_name,node->ifname,sizeof(node->ifname)))
        {
            return node;
        }
    }
    return NULL;
}

static struct bcmwl_toad *bcmwl_toad_create(const char *if_name)
{
    struct bcmwl_toad *node;

    node = calloc(1,sizeof(struct bcmwl_toad));
    if (!node)
    {
        LOGD("bcmwl: failed to create node for toad");
        return NULL;
    }
    STRSCPY_WARN(node->ifname, if_name);
    return node;
}

static void bcmwl_toad_cleanup(struct bcmwl_toad *node)
{
    if(!node)
        return;

    ds_dlist_remove(&g_wl_toad_list, node);
    free(node);
}

static bool bcmwl_toad_if_running(const char *if_name)
{
    bool enabled;
    struct bcmwl_toad *node;

    node=bcmwl_toad_find(if_name);
    if (node != NULL)
    {
        daemon_is_started(&node->toad_proc, &enabled);
        return enabled;
    }
    return false;
}

bool bcmwl_toad_restart(const char *if_name)
{
    struct bcmwl_toad *node;
    if (!if_name)
    {
        return false;
    }

    node=bcmwl_toad_find(if_name);
    if(node)
    {
        if(daemon_stop(&node->toad_proc))
        {
            if(daemon_start(&node->toad_proc))
            return true;
        }
    }
    return false;
}

static void bcmwl_toad_node_init(const char *if_name)
{
    bool rc;
    struct bcmwl_toad *node;

    node = bcmwl_toad_create(if_name);
    if(node)
    {
        ds_dlist_insert_head(&g_wl_toad_list, node);
        rc = bcmwl_toad_daemon_start(node);
        if (!rc)
        {
            bcmwl_toad_cleanup(node);
            return;
        }
    }
    return;
}

static void bcmwl_toad_start(const char *if_name)
{
    bool flag=false;
    char *pri_if_name = NULL;
    struct bcmwl_toad *node;
    char token[8];

    STRSCPY_WARN(token,if_name);
    pri_if_name=strtok(token,".");

    if (g_toad_init && pri_if_name != NULL)
    {
        bcmwl_toad_node_init(pri_if_name);
        g_toad_init=false;
        return;
    }

    if (!g_toad_init && pri_if_name != NULL)
    {
        flag = bcmwl_toad_if_running(pri_if_name);
    }

    if (flag == true)
    {
        bcmwl_toad_restart(pri_if_name);
    }

    else
    {
        node=bcmwl_toad_find(pri_if_name);
        if (!node)
        {
            bcmwl_toad_node_init(pri_if_name);
        }
    }
}

void bcmwl_toad_configure_atf(const struct schema_Wifi_VIF_Config *vconf)
{
    const char *if_name = vconf->if_name;
    const char *airtime_precedence = vconf->airtime_precedence;
    int if_index = vconf->vif_radio_idx;
    char cmd[128];
    char tmp_cmd[128];
    int i;
    char nv_param[128]; 
    char *token;
    char *value=NULL;
    int nvram_if_index;
    char nvram_if_type[16];
    char wl_iftype[16];

    if (!strncmp(airtime_precedence,"low",sizeof("low")))
    {
        STRSCPY_WARN(wl_iftype,"public");
    }
 
    else if(!strncmp(airtime_precedence,"medium",sizeof("medium")))
    {
        STRSCPY_WARN(wl_iftype,"data");
    }

    else
    {
        WARN_ON(1);
        return;
    }

    for(i=1;i<=g_rule_index;i++)
    {
        snprintf(tmp_cmd,sizeof(tmp_cmd)-1,"toa-bss-%d",i);
        value=NVG("",tmp_cmd);
        if((value != NULL) && (value[0] != '\0'))
        {
            STRSCPY_WARN(nv_param,value);
            /*** "nvram get toa-bss-%d" is not empty then it will return "%d type=public" where %d is if_index*/
            token = strtok(nv_param, " ");
            if(token!=NULL)
            {
                nvram_if_index = atoi(token);
                token = strtok(NULL, "="); 
                token = strtok(NULL, "="); 
                if(token!=NULL)
                {
                    STRSCPY_WARN(nvram_if_type,token);
                }
                LOGD("bcmwl_toad: if type in nvram is %s for index %d and if_type is %s",nvram_if_type,nvram_if_index,wl_iftype);
                
                if(nvram_if_index == vconf->vif_radio_idx)
                {   
                    if(!strncmp(wl_iftype,nvram_if_type,sizeof(wl_iftype)-1))
                        LOGI("bcmwl_toad: Rule is already present for index %d no need to add rule for different AP with same index",if_index);
                    else
                    {
                        LOGW("bcmwl_toad: invalid configuration iftype should be same for same index BSSID fall back to privious configuration");
                        WARN_ON(!NVS("",strfmta("toa-bss-%d",i),NULL));
                    }
                    break;
                }
            }
        }
        else if(!strncmp(wl_iftype,"public",sizeof("public")))
        {
            if(i==g_rule_index)
            {
                snprintf(cmd, sizeof(cmd)-1,"toa-bss-%d",g_rule_index);
                WARN_ON(!NVS("", cmd, strfmta("%d type=public", if_index)));
                g_rule_index++;
                break;
            }
        }
    }
       
    WARN_ON(!NVS("", "toa-defs","default type=data"));
    if(vconf->enabled)
        bcmwl_toad_start(if_name);
    return;
}
