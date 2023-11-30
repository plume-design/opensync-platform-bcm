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

#ifndef OSN_MCAST_BCM_H_INCLUDED
#define OSN_MCAST_BCM_H_INCLUDED

#include "evx.h"

#include "osn_igmp.h"
#include "osn_mld.h"

struct osn_igmp
{
    bool                        initialized;
    enum osn_igmp_version       version;

    bool                        snooping_enabled;
    char                        snooping_bridge[IFNAMSIZ];
    bool                        snooping_bridge_up;
    char                        static_mrouter[IFNAMSIZ];
    bool                        static_mrouter_up;
    char                      **mcast_exceptions;
    int                         mcast_exceptions_len;
    enum osn_mcast_unknown_grp  unknown_group;
    int                         robustness_value;
    int                         max_groups;
    int                         max_sources;
    int                         aging_time;
    bool                        fast_leave_enable;

    bool                        proxy_enabled;
    char                        proxy_upstream_if[IFNAMSIZ];
    bool                        proxy_upstream_if_up;
    char                        proxy_downstream_if[IFNAMSIZ];
    bool                        proxy_downstream_if_up;

    bool                        querier_enabled;
    int                         query_interval;
    int                         query_response_interval;
    int                         last_member_query_interval;

    /* BCM specific configuration */
    bool                        mcast_bridge;
    char                        mcast_interface[IFNAMSIZ];
    int                         max_members;
};

struct osn_mld
{
    bool                        initialized;
    enum osn_mld_version        version;

    bool                        snooping_enabled;
    char                        snooping_bridge[IFNAMSIZ];
    bool                        snooping_bridge_up;
    char                        static_mrouter[IFNAMSIZ];
    bool                        static_mrouter_up;
    char                      **mcast_exceptions;
    int                         mcast_exceptions_len;
    enum osn_mcast_unknown_grp  unknown_group;
    int                         robustness_value;
    int                         max_groups;
    int                         max_sources;
    int                         aging_time;
    bool                        fast_leave_enable;

    bool                        proxy_enabled;
    char                        proxy_upstream_if[IFNAMSIZ];
    bool                        proxy_upstream_if_up;
    char                        proxy_downstream_if[IFNAMSIZ];
    bool                        proxy_downstream_if_up;

    bool                        querier_enabled;
    int                         query_interval;
    int                         query_response_interval;
    int                         last_member_query_interval;

    /* BCM specific configuration */
    bool                        mcast_bridge;
    char                        mcast_interface[IFNAMSIZ];
    int                         max_members;
};

typedef struct
{
    bool                        initialized;
    ev_debounce                 mcpd_debounce;
    int                         mcpd_retry;
    ev_debounce                 ovs_debounce;
    int                         ovs_retry;
    ev_debounce                 native_debounce;
    int                         native_retry;
    bool                        igmp_initialized;
    osn_igmp_t                  igmp;
    bool                        mld_initialized;
    osn_mld_t                   mld;
    char                        snooping_bridge[IFNAMSIZ];
    char                        static_mrouter[IFNAMSIZ];
} osn_mcast_bridge;

osn_igmp_t *osn_mcast_bridge_igmp_init();
osn_mld_t *osn_mcast_bridge_mld_init();
bool osn_mcast_apply();

bool osn_igmp_write_section(osn_igmp_t *self, FILE *f);
bool osn_mld_write_section(osn_mld_t *self, FILE *f);

char *osn_mcast_other_config_get_string(
        const struct osn_mcast_other_config *other_config,
        const char *key);
long osn_mcast_other_config_get_long(
        const struct osn_mcast_other_config *other_config,
        const char *key);
bool osn_mcast_free_string_array(char **arr, int len);

#endif /* OSN_MCAST_BCM_H_INCLUDED */
