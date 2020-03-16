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

#ifndef BCMWL_WPS_H_INCLUDED
#define BCMWL_WPS_H_INCLUDED

#ifdef CONFIG_BCM_USE_NAS
bool bcmwl_wps_enabled(void);
bool bcmwl_wps_configured(void);
bool bcmwl_wps_init(void);
bool bcmwl_wps_set_on_state_change_script(const char *wps_script);
bool bcmwl_wps_restart(void);
char* bcmwl_wps_process_name(void);
#else
static inline bool bcmwl_wps_enabled(void) { return false; }
static inline bool bcmwl_wps_configured(void) { return false; }
static inline bool bcmwl_wps_init(void) { return true; }
static inline bool bcmwl_wps_set_on_state_change_script(const char *wps_script) { return true; }
static inline bool bcmwl_wps_restart(void) { return true; }
static inline char* bcmwl_wps_process_name(void) { return ""; }
#endif

#endif /* BCMWL_WPS_H_INCLUDED */
