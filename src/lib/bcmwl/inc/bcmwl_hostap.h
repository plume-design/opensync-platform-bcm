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

#ifndef BCMWL_HOSTAP_H_INCLUDED
#define BCMWL_HOSTAP_H_INCLUDED

#ifdef CONFIG_BCM_USE_HOSTAP
void bcmwl_hostap_init(void);
void bcmwl_hostap_init_bss(const char *bss);
void bcmwl_hostap_bss_apply(const struct schema_Wifi_VIF_Config *vconf,
                            const struct schema_Wifi_Radio_Config *rconf,
                            const struct schema_Wifi_Credential_Config *cconf,
                            const struct schema_Wifi_VIF_Config_flags *vchanged,
                            size_t n_cconf);
void bcmwl_hostap_bss_get(const char *bss,
                          struct schema_Wifi_VIF_State *vstate);
void bcmwl_hostap_sta_get(const char *bss,
                          const char *mac,
                          struct schema_Wifi_Associated_Clients *client);
bool bcmwl_hostap_dpp_set(const struct schema_DPP_Config **dpp);
void bcmwl_hostap_ctrl_wps_session(const char *bss, int wps, int wps_pbc);
void bcmwl_hostap_reset_wps_pbc(const char* ifname);
#else
static inline void bcmwl_hostap_init(void) {}
static inline void bcmwl_hostap_init_bss(const char *bss) {}
static inline void bcmwl_hostap_bss_apply(const struct schema_Wifi_VIF_Config *vconf,
                                          const struct schema_Wifi_Radio_Config *rconf,
                                          const struct schema_Wifi_Credential_Config *cconf,
                                          const struct schema_Wifi_VIF_Config_flags *vchanged,
                                          size_t n_cconf) {}
static inline void bcmwl_hostap_bss_get(const char *bss,
                                        struct schema_Wifi_VIF_State *vstate) {}
static inline void bcmwl_hostap_sta_get(const char *bss,
                                        const char *mac,
                                        struct schema_Wifi_Associated_Clients *client) {}
static inline bool bcmwl_hostap_dpp_set(const struct schema_DPP_Config **dpp) { return false; }
static inline void bcmwl_hostap_ctrl_wps_session(const char *bss, int wps, int wps_pbc) {}
static inline void bcmwl_hostap_reset_wps_pbc(const char* ifname) {}
#endif

#endif /* BCMWL_HOSTAP_H_INCLUDED */
