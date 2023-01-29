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

#define _GNU_SOURCE /* for alloca */

/* std libc */
#include <string.h>
#include <sys/types.h>
#include <dirent.h>

/* internal */
#include <log.h>
#include <target.h>
#include <bcmwl.h>
#include <bcmwl_nas.h>
#include <bcmwl_wps.h>
#include <bcmwl_hostap.h>
#include <kconfig.h>

#define MODULE_ID LOG_MODULE_ID_TARGET

static void
target_radio_init_uapsd_war(void)
{
    /* FIXME: This is ugly but avoids radio down/up to change uapsd
     *        setting in driver. This is best-effort. It'll work only
     *        on initial wm startup when radios are down. Only home ap
     *        is expected to have uapsd enabled by default. This will
     *        obviously stop working (as intended) if uapsd default
     *        setting in cloud changes.
     */
    WL("wl0", "wme_apsd", "0");
    WL("wl0.1", "wme_apsd", "0");
    WL("wl0.2", "wme_apsd", "1");
    WL("wl0.3", "wme_apsd", "0");
    WL("wl0.6", "wme_apsd", "1");
    WL("wl1", "wme_apsd", "0");
    WL("wl1.1", "wme_apsd", "0");
    WL("wl1.2", "wme_apsd", "1");
    WL("wl1.3", "wme_apsd", "0");
    WL("wl1.6", "wme_apsd", "1");
    WL("wl2", "wme_apsd", "0");
    WL("wl2.1", "wme_apsd", "0");
    WL("wl2.2", "wme_apsd", "1");
    WL("wl2.3", "wme_apsd", "0");
    WL("wl2.6", "wme_apsd", "1");
}

static void
target_radio_init_steer_war(void)
{
    /* FIXME: These settings can be configured by cloud via VIF_Config. However
     *        driver is limited to apply them only when radio is down. Downing
     *        radio introduces a severe service interruption so it's best to
     *        avoid it if possible. These settings are for BM which works on
     *        home-vaps only. It is expected that these will always be either
     *        [set,[]] or 1 in ovsdb for home vifs.
     */
    WL("wl0.2", "rrm", "+2");
    WL("wl1.2", "rrm", "+2");
    WL("wl2.2", "rrm", "+2");
    WL("wl0.6", "rrm", "+2");
    WL("wl1.6", "rrm", "+2");
    WL("wl2.6", "rrm", "+2");
    WL("wl0.2", "wnm", "+1");
    WL("wl1.2", "wnm", "+1");
    WL("wl2.2", "wnm", "+1");
    WL("wl0.6", "wnm", "+1");
    WL("wl1.6", "wnm", "+1");
    WL("wl2.6", "wnm", "+1");
}

static void
target_radio_init_mbo(void)
{
    struct dirent *p;
    DIR *d;

    /* On older (notably 11ac driver) MBO is enabled by
     * default. This is not a good idea since it requires
     * PMF to be enabled. Opensync doesn't really enable
     * explicit PMF, and it only ever gets enabled
     * implicitly when using WPA3 which isn't even supported
     * on 11ac drivers. Just disable it to avoid interop
     * issues until Opensync really needs this. The newer
     * 11ax drivers disable MBO by default.
     */
    for (d = opendir("/sys/class/net"); d && (p = readdir(d)); )
        if (bcmwl_is_phy(p->d_name) || bcmwl_is_vif(p->d_name))
            WL(p->d_name, "mbo", "ap_enable", "0");

    if (!WARN_ON(!d))
        closedir(d);
}

static void
target_bcmwl_wps_set_script(void)
{
    char wps_script[64] = { 0 };

    snprintf(wps_script, sizeof(wps_script)-1, "%s/wps_state_change.sh", target_bin_dir());
    if (access(wps_script, X_OK) == 0)
    {
        bcmwl_wps_set_on_state_change_script(wps_script);
    }
}

bool
target_radio_init(const struct target_radio_ops *ops)
{
    if (WARN_ON(!bcmwl_init(ops)))
        return false;
    if (WARN_ON(!bcmwl_init_wm()))
        return false;
    bcmwl_vap_prealloc_all();
    bcmwl_vap_enumerate();
    target_bcmwl_wps_set_script();
    target_radio_init_mbo();
    target_radio_init_uapsd_war();
    target_radio_init_steer_war();

    return true;
}

bool
target_radio_config_set2(const struct schema_Wifi_Radio_Config *rconf,
                         const struct schema_Wifi_Radio_Config_flags *rchanged)
{
    return bcmwl_radio_update2(rconf, rchanged);
}

bool
target_vif_config_set2(const struct schema_Wifi_VIF_Config *vconf,
                       const struct schema_Wifi_Radio_Config *rconf,
                       const struct schema_Wifi_Credential_Config *cconfs,
                       const struct schema_Wifi_VIF_Config_flags *vchanged,
                       int num_cconfs)
{
    return bcmwl_vap_update2(vconf, rconf, cconfs, vchanged, num_cconfs);
}

bool
target_vif_config_set3(const struct schema_Wifi_VIF_Config *vconf,
                       const struct schema_Wifi_Radio_Config *rconf,
                       const struct schema_Wifi_Credential_Config *cconfs,
                       const struct schema_Wifi_VIF_Config_flags *vchanged,
                       const struct schema_Wifi_VIF_Neighbors *nbors_list,
                       const struct schema_RADIUS *radius_list,
                       int num_cconfs,
                       int num_nbors_list,
                       int num_radius_list)
{
    return bcmwl_vap_update3(vconf, rconf, cconfs, vchanged,
                             nbors_list, radius_list,
                             num_cconfs, num_nbors_list,
                             num_radius_list);
}

bool
target_dpp_supported(void)
{
    return kconfig_enabled(CONFIG_BCM_USE_DPP);
}

bool
target_dpp_config_set(const struct schema_DPP_Config **config)
{
    return bcmwl_hostap_dpp_set(config);
}
