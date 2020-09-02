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

#ifndef BCMWL_H_INCLUDED
#define BCMWL_H_INCLUDED

#include <ev.h>
#include <stdbool.h>
#include <string.h>

#include "schema.h"
#include "os_nif.h"
#include "ds_dlist.h"

// some platforms use _ as delimiter, but default is .
#ifndef CONFIG_BCMWL_VAP_DELIMITER
#define CONFIG_BCMWL_VAP_DELIMITER "."
#endif

#define STRFMTA_VIF(PHY,IDX) ((IDX == 0) ? strfmta("%s", PHY) \
        : strfmta("%s%s%d", PHY, CONFIG_BCMWL_VAP_DELIMITER, IDX))

#define bcmwl_for_each_mac(mac, macs)       \
    while ((mac = strsep(&macs, "\n")) &&   \
            strsep(&mac, " ") &&            \
            (mac = strsep(&mac, "")))

#define bcmwl_is_phy(ifname) \
    (strstr(ifname, "wl") == ifname && !strstr(ifname, CONFIG_BCMWL_VAP_DELIMITER))
#define bcmwl_is_vif(ifname) \
    (strstr(ifname, "wl") == ifname && strstr(ifname, CONFIG_BCMWL_VAP_DELIMITER))
#define bcmwl_is_netdev(ifname) \
    (strstr(ifname, "wl") == ifname || strstr(ifname, "wds") == ifname)

extern struct target_radio_ops bcmwl_ops;

// Radio handling
bool        bcmwl_init(const struct target_radio_ops *ops);
bool        bcmwl_init_wm(void);
bool        bcmwl_radio_adapter_is_operational(const char *radio);
bool        bcmwl_radio_is_dhd(const char *ifname);
bool        bcmwl_radio_update2(const struct schema_Wifi_Radio_Config *rconf,
                                const struct schema_Wifi_Radio_Config_flags *rchanged);
bool        bcmwl_radio_state(const char *phyname,
                              struct schema_Wifi_Radio_State *rstate);
void        bcmwl_radio_state_report(const char *ifname);
void        bcmwl_radio_chanspec_extract(const char *chanspec, int *chan, int *width);
bool        bcmwl_radio_channel_set(const char *phy, int channel, const char *ht_mode);
int         bcmwl_radio_get_ap_active_cnt(const char *phy);
bool        bcmwl_radio_chanspec_get(const char *phyname, int *channel, int *ht_mode);
bool        bcmwl_radio_band_get(const char *phyname, char *band, ssize_t band_len);
int         bcmwl_radio_ht_mode_to_int(const char *ht_mode);
const char* bcmwl_radio_ht_mode_to_str(int ht_mode);
int         bcmwl_radio_max_vifs(const char *phy);
int         bcmwl_radio_count(void);

// VAP handling

#define BCMWL_RRM_NEIGH_REPORT 0x2
#define BCMWL_RRM BCMWL_RRM_NEIGH_REPORT

struct bcmwl_vap_config_t
{
    int             index;
    os_macaddr_t    bssid;
};

struct wl_status
{
    char bssid[6*2 + 5 + 1];
    char ssid[32 + 1];
    int rssi;
    int channel;
    int width_mhz;
    int is_up;
    int is_sta;  /* if false, it's an ap */
    int is_authorized;  /* valid if is_sta==true, eapol completed */
};

void bcmwl_vap_get_status(const char *ifname, struct wl_status *status);
bool bcmwl_vap_ready(const char *ifname);
bool bcmwl_vap_update2(const struct schema_Wifi_VIF_Config *vconf,
                       const struct schema_Wifi_Radio_Config *rconf,
                       const struct schema_Wifi_Credential_Config *cconfs,
                       const struct schema_Wifi_VIF_Config_flags *vchanged,
                       int num_cconfs);
bool bcmwl_vap_state(const char *ifname,
                     struct schema_Wifi_VIF_State *vstate);
void bcmwl_vap_state_report(const char *ifname);
bool bcmwl_vap_is_sta(const char *ifname);
void bcmwl_vap_mac_xfrm(char *addr, int idx, int max);
bool bcmwl_vap_prealloc(const char *phy, int max_idx, void (*mac_xfrm)(char *addr, int idx, int max));
void bcmwl_vap_prealloc_all(void);
bool bcmwl_vap_update_acl(const struct schema_Wifi_VIF_Config *vconf,
                          const struct schema_Wifi_Radio_Config *rconf,
                          const struct schema_Wifi_VIF_Config_flags *vchanged);
bool bcmwl_vap_update_security(const struct schema_Wifi_VIF_Config *vconf,
                               const struct schema_Wifi_Radio_Config *rconf,
                               const struct schema_Wifi_Credential_Config *cconfs,
                               const struct schema_Wifi_VIF_Config_flags *vchanged,
                               int num_cconfs);
bool bcmwl_parse_vap(const char *ifname, int *ri, int *vi);

bool bcmwl_sta_deauth(const char *ifame,
                      const os_macaddr_t *mac,
                      int reason);

bool bcmwl_sta_is_associated(const char *ifname,
                             const char *mac);

bool bcmwl_sta_is_authorized(const char *ifname,
                             const char *mac);

bool bcmwl_sta_is_connected(const char *ifname,
                            const char *mac);


bool bcmwl_sta_get_rssi(const char *ifname,
                        const os_macaddr_t *hwaddr,
                        int *rssi);

char* bcmwl_sta_get_authorized_macs(const char *ifname);
void bcmwl_sta_get_schema(const char *ifname,
                          const char *mac,
                          struct schema_Wifi_Associated_Clients *c);
void bcmwl_sta_resync(const char *ifname);

struct bcmwl_sta_rate {
    float tried;
    float mbps_capacity; /* normalizes towards SU */
    float mbps_perceived; /* includes both SU+MU */
    float psr;
};

int bcmwl_sta_get_tx_avg_rate(const char *ifname,
                              const char *mac,
                              struct bcmwl_sta_rate *rate);
int bcmwl_sta_get_rx_avg_rate(const char *ifname,
                              void (*iter)(const char *ifname,
                                           const char *mac_octet,
                                           const struct bcmwl_sta_rate *rate,
                                           void *arg),
                              void *arg);

char *bcmwl_wl(const char *ifname, const char *prog, const char *args[]);

#define WL(ifname, ...) strdupafree(strchomp(bcmwl_wl(ifname, "wlctl", (const char *[]) { __VA_ARGS__, NULL }), " \t\r\n"))
#define WL_VAL(s) (strsep(&s, " ") && (s = strsep(&s, "")))
#define DHD(ifname, ...) strdupafree(strchomp(bcmwl_wl(ifname, "dhdctl", (const char *[]) { __VA_ARGS__, NULL }), " \t\r\n"))

// chanspec util
typedef struct
{
    int chanspec;
    int channel;
    int bandwidth;
    int sideband;
} bcmwl_chanspec_t;

bcmwl_chanspec_t* bcmwl_chanspec_get(char *ifname, int chanspec);
int bcmwl_chanspec_get_primary(const int cs);

// Miscellaneous
bool bcmwl_misc_send_action_frame(const char *ifname,
                                  const os_macaddr_t *hwaddr,
                                  const char *frame_hex);

bool bcmwl_misc_is_valid_mac(const char *mac);
bool bcmwl_misc_is_rrm_enabled(const char*ifname,
                               bool *is_enabled);

bool bcmwl_misc_is_wnm_enabled(const char*ifname,
                               bool *is_enabled);
bool bcmwl_get_noise(const char *ifname, int *noise);

// DFS

enum bcmwl_chan_state
{
    BCMWL_CHAN_STATE_ALLOWED,
    BCMWL_CHAN_STATE_CAC_STARTED,
    BCMWL_CHAN_STATE_CAC_COMPLETED,
    BCMWL_CHAN_STATE_NOP_STARTED,
    BCMWL_CHAN_STATE_NOP_FINISHED,
};

typedef struct
{
    uint16_t wlc_ver_major;
    uint16_t wlc_ver_minor;
} bcmwl_wlc_ver_t;

void bcmwl_dfs_init(void);
void bcmwl_event_handle_radar(const char *ifname);
void bcmwl_event_handle_ap_chan_change(const char *ifname, void *ev);
void bcmwl_radio_radar_get(const char *phyname, struct schema_Wifi_Radio_State *rstate);
char* bcmwl_radio_get_vifs(const char *phy);
void bcmwl_radio_channels_get(const char *phyname, struct schema_Wifi_Radio_State *rstate);
const char* bcmwl_channel_state(enum bcmwl_chan_state state);
bool bcmwl_radio_get_chanspec(const char *phy, int *chan, int *width);
int bcmwl_get_current_channels(const char *phyname, int *chan, int size);
void bcmwl_radio_fallback_parents_set(const char *phyname, const struct schema_Wifi_Radio_Config *rconf);
void bcmwl_radio_fallback_parents_get(const char *phyname, struct schema_Wifi_Radio_State *rstate);

bool bcmwl_misc_set_neighbor(const char *ifname, const char *bssid, const char *bssid_info,
                             const char *regulatory, const char *channel, const char *phytype,
                             const char *prefer, const char *ssid);
bool bcmwl_misc_remove_neighbor(const char *ifname, const char *bssid);
int bcmwl_system_start_closefd(const char *command);
bool bcmwl_radio_is_dfs_channel(const char *phy, uint8_t chan, const char *ht_mode);
bool bcmwl_dfs_bgcac_active(const char *phy, uint8_t chan, const char *ht_mode);
void bcmwl_dfs_bgcac_deactivate(const char *phy);
void bcmwl_dfs_bgcac_recalc(const char *phy);
bool bcmwl_wlc_ver(const char *ifname, bcmwl_wlc_ver_t *ver);

#endif /* BCMWL_H_INCLUDED */
