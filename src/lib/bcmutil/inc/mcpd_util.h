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

#ifndef MCPD_UTIL_H_INCLUDED
#define MCPD_UTIL_H_INCLUDED

#include "schema.h"
#include "target.h"

/*
 * Update mcpd basic params.
 * @param proxy_param Proxy configuration
 * @return true if configured
 */
bool mcpd_util_update_proxy_params(const target_mcproxy_params_t *proxy_param);

/*
 * Update the igmp sys params.
 * @param iccfg tunable parameters for igmp
 * @return true if updated
 */
bool mcpd_util_update_igmp_sys_params(const struct schema_IGMP_Config *iccfg);

/*
 * Update the mld sys params.
 * All tunable parameters are defined here:
 * https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt
 * @param mlcfg tunable parameters for mld
 * @return true if updated
 */
bool mcpd_util_update_mld_sys_params(const struct schema_MLD_Config *mlcfg);

/*
 * Write the config and trigger a reload.
 * @return true if applied
 */
bool mcpd_util_apply(void);

/*
 * Update the list of uplink interfaces for mcast daemon
 * @param ifname uplink interface name
 * @param enable add or remove interface
 * @param bridge parent bridge interface or NULL if none
 * @return true if updated
 */
bool mcpd_util_update_uplink(const char *ifname, bool enable, const char *bridge);

/*
 * Update the list of snooping interfaces for mcast daemon
 * @param ifname igmp snooping interface name
 * @param enable add or remove interface
 * @return true if updated
 */
bool mcpd_util_update_snooping(const char *ifname, bool enable);

#endif /* MCPD_UTIL_H_INCLUDED */
