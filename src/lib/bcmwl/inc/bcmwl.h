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
#include <devctrl_if/wlioctl_defs.h>

#include "schema.h"
#include "os_nif.h"
#include "ds_dlist.h"
#include "bcmwl_priv.h"

#define bcmwl_for_each_mac(mac, macs)       \
    while ((mac = strsep(&macs, "\n")) &&   \
            strsep(&mac, " ") &&            \
            (mac = strsep(&mac, "")))

#define bcmwl_is_phy(ifname) \
    (strstr(ifname, "wl") == ifname && !strstr(ifname, "."))
#define bcmwl_is_vif(ifname) \
    (strstr(ifname, "wl") == ifname && strstr(ifname, "."))

extern struct target_radio_ops bcmwl_ops;

// Radio handling
bool        bcmwl_init(const struct target_radio_ops *ops);
bool        bcmwl_init_wm(void);
bool        bcmwl_radio_is_dhd(const char *ifname);
bool        bcmwl_radio_create(const struct schema_Wifi_Radio_Config *rconfig);
bool        bcmwl_radio_update(const struct schema_Wifi_Radio_Config *rconfig,
                               const struct schema_Wifi_Radio_Config_flags *rchanged);
bool        bcmwl_radio_update2(const struct schema_Wifi_Radio_Config *rconf,
                                const struct schema_Wifi_Radio_Config_flags *rchanged);
bool        bcmwl_radio_state(const char *phyname,
                              struct schema_Wifi_Radio_State *rstate);
void        bcmwl_radio_state_report(const char *ifname);
void        bcmwl_radio_chanspec_extract(const char *chanspec, int *chan, int *width);
bool        bcmwl_radio_channel_set(const char *phy, int channel, const char *ht_mode);
int         bcmwl_radio_get_ap_active_cnt(const char *phy);
bool        bcmwl_radio_channel_get(const char *phyname, int *channel);
bool        bcmwl_radio_chanspec_get(const char *phyname, int *channel, int *ht_mode);
bool        bcmwl_radio_get_chanspec(const char *phy, int *chan, int *width);
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
bool bcmwl_vap_create(const struct bcmwl_vap_config_t *bcmwl_vap_config,
                      const struct schema_Wifi_VIF_Config *vconfig,
                      const struct schema_Wifi_Radio_Config *rconfig);
bool bcmwl_vap_update(const struct schema_Wifi_VIF_Config *vconfig,
                      const struct schema_Wifi_Radio_Config *rconfig,
                      const struct schema_Wifi_VIF_Config_flags *vchanged);
bool bcmwl_vap_update2(const struct schema_Wifi_VIF_Config *vconf,
                       const struct schema_Wifi_Radio_Config *rconf,
                       const struct schema_Wifi_Credential_Config *cconfs,
                       const struct schema_Wifi_VIF_Config_flags *vchanged,
                       int num_cconfs);
bool bcmwl_vap_state(const char *ifname,
                     struct schema_Wifi_VIF_State *vstate);
void bcmwl_vap_state_report(const char *ifname);
bool bcmwl_vap_psk_get(const char *ifname, char *psk, ssize_t psk_len);
bool bcmwl_vap_ssid_get(const char *ifname, char *ssid, ssize_t ssid_len);
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

bool        bcmwl_vap_ssid_broadcast_get(const char *ifname, int *ssid_broadcast);
int         bcmwl_vap_ssid_broadcast_to_int(const char *ssid_broadcast);
const char *bcmwl_vap_ssid_broadcast_to_str(int ssid_broadcast);

bool        bcmwl_vap_mac_list_type_get(const char *ifname, int *mac_list_type);
int         bcmwl_vap_mac_list_type_to_int(const char *mac_list_type);
const char *bcmwl_vap_mac_list_type_to_str(int mac_list_type);

typedef void bcmwl_vap_assoc_list_cb_t(const char *ifname,
                                       const os_macaddr_t *mac,
                                       const int index,
                                       void *context);
typedef void bcmwl_vap_mac_list_cb_t(const char *ifname,
                                     const os_macaddr_t *mac,
                                     const int index,
                                     void *context);
bool bcmwl_vap_mac_list_foreach(const char *ifname,
                                bcmwl_vap_mac_list_cb_t cb,
                                void *context);
bool bcmwl_vap_assoc_list_foreach(const char *ifname,
                                  bcmwl_vap_mac_list_cb_t cb,
                                  void *context);

bool bcmwl_vap_br_tag_get(const char *ifname, char *brtag, size_t brtag_len);
bool bcmwl_vap_br_name_get(const char *ifname, char *brname, size_t brname_len);

// Events handling
#define BCMWL_EVENT_MASK_BITS_SIZE ((WLC_E_LAST / 8) + 1)

#define BCMWL_EVENT_HANDLED true
#define BCMWL_EVENT_CONTINUE false

typedef bool bcmwl_event_cb_t(const char *ifname, os_macaddr_t *client, void  *event);

typedef struct {
   uint8_t bits[BCMWL_EVENT_MASK_BITS_SIZE];
} bcmwl_event_mask_t;

bool    bcmwl_event_register(struct ev_loop *evloop, const char *ifname, bcmwl_event_cb_t cb);
void    bcmwl_event_unregister(struct ev_loop *evloop, const char *ifname, bcmwl_event_cb_t cb);
bool    bcmwl_event_handler(const char *ifname,
                            os_macaddr_t *hwaddr,
                            void *event);
void    bcmwl_event_setup(struct ev_loop *loop);
void    bcmwl_event_setup_extra_cb(bcmwl_event_cb_t cb);
int     bcmwl_event_socket_open(const char *ifname);
int     bcmwl_event_socket_close(int fd);
void    bcmwl_event_discard_probereq(void);
ssize_t bcmwl_event_msg_read(int fd, void *msg, size_t msglen);


bool bcmwl_event_mask_get(const char* ifname, bcmwl_event_mask_t* mask);
bool bcmwl_event_mask_set(const char* ifname,
                          const bcmwl_event_mask_t* mask);
void bcmwl_event_mask_bit_set(bcmwl_event_mask_t* mask, unsigned int bit);
void bcmwl_event_mask_bit_unset(bcmwl_event_mask_t* mask, unsigned int bit);
bool bcmwl_event_mask_bit_isset(bcmwl_event_mask_t* mask, unsigned int bit);
bool bcmwl_event_enable(const char *ifname, unsigned int bit);

// STA handling
typedef struct
{
    bool is_authorized;
    uint16_t capabilities;
    uint64_t rx_total_bytes;
    uint64_t tx_total_bytes;
    bool is_btm_supported;
    int rssi;
    int nf;
    uint8_t max_chwidth;
    uint8_t max_streams;
    uint8_t max_mcs;
} bcmwl_sta_info_t;

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

bool bcmwl_sta_get_sta_info(const char *ifname,
                            const os_macaddr_t *hwaddr,
                            bcmwl_sta_info_t *sta_info);

char* bcmwl_sta_get_authorized_macs(const char *ifname);
void bcmwl_sta_get_schema(const char *ifname,
                          const char *mac,
                          struct schema_Wifi_Associated_Clients *c);
void bcmwl_sta_resync(const char *ifname);

// ACLs
typedef enum
{
    BCMWL_ACL_MODE_DISABLE = 0,
    BCMWL_ACL_MODE_DENY = 1,
    BCMWL_ACL_MODE_ALLOW = 2,
} bcmwl_acl_mode_t;

bool bcmwl_acl_set_mode(const char* ifname,
                        bcmwl_acl_mode_t mode);

bool bcmwl_acl_del_devs(const char* ifname);

bool bcmwl_acl_del_dev(const char* ifname,
                       const os_macaddr_t* hwaddr);

bool bcmwl_acl_add_dev(const char* ifname,
                       const os_macaddr_t* hwaddr);

bool bcmwl_acl_set_prob_resp_blocking(const char* ifname,
                                      bool block);

bool bcmwl_acl_set_auth_resp_blocking(const char* ifname,
                                      bool block);

bool bcmwl_acl_contains_dev(const char* ifname,
                            const os_macaddr_t* hwaddr,
                            bool* contains);

#define WL(ifname, ...) strchomp(strexa("wlctl", "-i", ifname, ##__VA_ARGS__), " \t\r\n")
#define WL_VAL(s) (strsep(&s, " ") && (s = strsep(&s, "")))
#define DHD(ifname, ...) strchomp(strexa("dhdctl", "-i", ifname, ##__VA_ARGS__), " \t\r\n")

enum {
    BCMWL_NAS_RELOAD_FULL,
    BCMWL_NAS_RELOAD_FAST,
};

bool bcmwl_acl_is_synced(const char *ifname);
bool bcmwl_acl_commit(const char *ifname);
bool bcmwl_acl_init(void);

enum bcmwl_acl_policy {
    BCMWL_ACL_NONE = 0,
    BCMWL_ACL_DENY = 1,
    BCMWL_ACL_ALLOW = 2,
};

#define BCMWL_ACL_WM "wm"
#define BCMWL_ACL_BM "bm"
#define BCMWL_ACL_GET(ifname, entity) (NVG(ifname, strfmta("acl_%s", entity)))
#define BCMWL_ACL_SET(ifname, entity, acl) (NVS(ifname, strfmta("acl_%s", entity), acl))
#define BCMWL_ACL_ADD(ifname, entity, mac) (bcmwl_nvram_append(ifname, strfmta("acl_%s", entity), mac, strcasecmp) >= 0)
#define BCMWL_ACL_DEL(ifname, entity, mac) (bcmwl_nvram_remove(ifname, strfmta("acl_%s", entity), mac, strcasecmp) >= 0)
#define BCMWL_ACL_POLICY_SET(ifname, entity, policy) (NVS(ifname, strfmta("acl_policy_%s", entity), strfmta("%d", policy)))
#define BCMWL_ACL_POLICY_GET(ifname, entity) (NVG(ifname, strfmta("acl_policy_%s", entity)))

// chanspec util
typedef struct
{
    int chanspec;
    int channel;
    int bandwidth;
    int sideband;
} bcmwl_chanspec_t;

bcmwl_chanspec_t* bcmwl_chanspec_get(char *ifname, int chanspec);

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

void bcmwl_dfs_init(void);
void bcmwl_event_handle_radar(const char *ifname);
void bcmwl_radio_radar_get(const char *phyname, struct schema_Wifi_Radio_State *rstate);
void bcmwl_radio_channels_get(const char *phyname, struct schema_Wifi_Radio_State *rstate);
const char* bcmwl_channel_state(enum bcmwl_chan_state state);
int bcmwl_get_current_channels(const char *phyname, int *chan, int size);
void bcmwl_radio_fallback_parents_set(const char *phyname, const struct schema_Wifi_Radio_Config *rconf);
void bcmwl_radio_fallback_parents_get(const char *phyname, struct schema_Wifi_Radio_State *rstate);
void bcmwl_radio_dfs_demo_set(const char *cphy, const struct schema_Wifi_Radio_Config *rconf);
void bcmwl_radio_dfs_demo_get(const char *cphy, struct schema_Wifi_Radio_State *rstate);

bool bcmwl_misc_set_neighbor(const char *ifname, const char *bssid, const char *bssid_info,
                             const char *regulatory, const char *channel, const char *phytype,
                             const char *prefer);
bool bcmwl_misc_remove_neighbor(const char *ifname, const char *bssid);

#endif /* BCMWL_H_INCLUDED */
