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

#define _GNU_SOURCE

#include <stdio.h>
#include <arpa/inet.h>
#include <errno.h>

#include "target.h"
#include "log.h"
#include "os_time.h"

#include "bcmwl.h"
#include "bcmwl_lan.h"
#include "bcmwl_nvram.h"
#include "bcmwl_event.h"
#include "bcmwl_ioctl.h"

static log_severity_t g_opt_severity = LOG_SEVERITY_INFO;
static int g_opt_delay;
static int g_opt_count;

static int g_count;
static int g_stats[WLC_E_LAST+1];
static int64_t g_time1, g_time2;

void usage()
{
    printf("Usage:\n" \
           " bcmcli [OPT] CMD ARGS\n\n" \
           " OPT:\n" \
           "    -v      increase verbose level\n" \
           "    -q      decrease verbose level\n" \
           "    -d MS   delay in ms (causes drops)\n" \
           "    -c NUM  exit after NUM events and print stats\n" \
           " CMDs:\n" \
           " detect_max_lan_ifnames [limit]\n" \
           "   Detect how many lan_ifnames the system supports.\n" \
           "   [limit] is default 32 and is optional.\n" \
           "   Be careful. This changes system state and can race with daemons.\n" \
           " watch_events ifname<ifname,ifname,...>\n" \
           "   Monitor BCM events on specified interfaces.\n" \
           " wlctl ifname <args..>\n" \
           "   Launch iovar wrapper, similar to native wlctl\n" \
           " dhdctl ifname <args..>\n" \
           "   Launch iovar wrapper, similar to native dhdctl\n" \
           " set_event e ifname<ifname,ifname,...>\n" \
           " unset_event e ifname<ifname,ifname,...>\n" \
           "   Manage BCM active events on specified interfaces. \"e\" is a decimal \n" \
           "   number of set/unset event \n");
}

static const char *event2str(int e)
{
#define CASE2STR(x) case x: return #x
    switch (e) {
        CASE2STR(WLC_E_SET_SSID);
        CASE2STR(WLC_E_JOIN);
        CASE2STR(WLC_E_START);
        CASE2STR(WLC_E_AUTH);
        CASE2STR(WLC_E_AUTH_IND);
        CASE2STR(WLC_E_DEAUTH);
        CASE2STR(WLC_E_DEAUTH_IND);
        CASE2STR(WLC_E_ASSOC);
        CASE2STR(WLC_E_ASSOC_IND);
        CASE2STR(WLC_E_REASSOC);
        CASE2STR(WLC_E_REASSOC_IND);
        CASE2STR(WLC_E_DISASSOC);
        CASE2STR(WLC_E_DISASSOC_IND);
        CASE2STR(WLC_E_QUIET_START);
        CASE2STR(WLC_E_QUIET_END);
        CASE2STR(WLC_E_BEACON_RX);
        CASE2STR(WLC_E_LINK);
        CASE2STR(WLC_E_MIC_ERROR);
        CASE2STR(WLC_E_NDIS_LINK);
        CASE2STR(WLC_E_ROAM);
        CASE2STR(WLC_E_TXFAIL);
        CASE2STR(WLC_E_PMKID_CACHE);
        CASE2STR(WLC_E_RETROGRADE_TSF);
        CASE2STR(WLC_E_PRUNE);
        CASE2STR(WLC_E_AUTOAUTH);
        CASE2STR(WLC_E_EAPOL_MSG);
        CASE2STR(WLC_E_SCAN_COMPLETE);
        CASE2STR(WLC_E_ADDTS_IND);
        CASE2STR(WLC_E_DELTS_IND);
        CASE2STR(WLC_E_BCNSENT_IND);
        CASE2STR(WLC_E_BCNRX_MSG);
        CASE2STR(WLC_E_BCNLOST_MSG);
        CASE2STR(WLC_E_ROAM_PREP);
        CASE2STR(WLC_E_PFN_NET_FOUND);
        CASE2STR(WLC_E_PFN_NET_LOST);
        CASE2STR(WLC_E_RESET_COMPLETE);
        CASE2STR(WLC_E_JOIN_START);
        CASE2STR(WLC_E_ROAM_START);
        CASE2STR(WLC_E_ASSOC_START);
        CASE2STR(WLC_E_IBSS_ASSOC);
        CASE2STR(WLC_E_RADIO);
        CASE2STR(WLC_E_PSM_WATCHDOG);
        CASE2STR(WLC_E_PROBREQ_MSG);
        CASE2STR(WLC_E_SCAN_CONFIRM_IND);
        CASE2STR(WLC_E_PSK_SUP);
        CASE2STR(WLC_E_COUNTRY_CODE_CHANGED);
        CASE2STR(WLC_E_EXCEEDED_MEDIUM_TIME);
        CASE2STR(WLC_E_ICV_ERROR);
        CASE2STR(WLC_E_UNICAST_DECODE_ERROR);
        CASE2STR(WLC_E_MULTICAST_DECODE_ERROR);
        CASE2STR(WLC_E_TRACE);
        CASE2STR(WLC_E_IF);
        CASE2STR(WLC_E_P2P_DISC_LISTEN_COMPLETE);
#ifdef WLC_E_RSSI
        CASE2STR(WLC_E_RSSI);
#endif
        CASE2STR(WLC_E_EXTLOG_MSG);
        CASE2STR(WLC_E_ACTION_FRAME);
        CASE2STR(WLC_E_ACTION_FRAME_COMPLETE);
        CASE2STR(WLC_E_PRE_ASSOC_IND);
        CASE2STR(WLC_E_PRE_REASSOC_IND);
        CASE2STR(WLC_E_CHANNEL_ADOPTED);
        CASE2STR(WLC_E_AP_STARTED);
        CASE2STR(WLC_E_DFS_AP_STOP);
        CASE2STR(WLC_E_DFS_AP_RESUME);
        CASE2STR(WLC_E_WAI_STA_EVENT);
        CASE2STR(WLC_E_WAI_MSG);
        CASE2STR(WLC_E_ESCAN_RESULT);
        CASE2STR(WLC_E_ACTION_FRAME_OFF_CHAN_COMPLETE);
        CASE2STR(WLC_E_PROBRESP_MSG);
        CASE2STR(WLC_E_P2P_PROBREQ_MSG);
        CASE2STR(WLC_E_DCS_REQUEST);
        CASE2STR(WLC_E_FIFO_CREDIT_MAP);
        CASE2STR(WLC_E_ACTION_FRAME_RX);
        CASE2STR(WLC_E_WAKE_EVENT);
        CASE2STR(WLC_E_RM_COMPLETE);
        CASE2STR(WLC_E_HTSFSYNC);
        CASE2STR(WLC_E_OVERLAY_REQ);
        CASE2STR(WLC_E_CSA_COMPLETE_IND);
        CASE2STR(WLC_E_EXCESS_PM_WAKE_EVENT);
        CASE2STR(WLC_E_GTK_PLUMBED);
        CASE2STR(WLC_E_ASSOC_IND_NDIS);
        CASE2STR(WLC_E_REASSOC_IND_NDIS);
        CASE2STR(WLC_E_ASSOC_REQ_IE);
        CASE2STR(WLC_E_ASSOC_RESP_IE);
        CASE2STR(WLC_E_ASSOC_RECREATED);
        CASE2STR(WLC_E_ACTION_FRAME_RX_NDIS);
        CASE2STR(WLC_E_AUTH_REQ);
        CASE2STR(WLC_E_TDLS_PEER_EVENT);
        CASE2STR(WLC_E_SPEEDY_RECREATE_FAIL);
        CASE2STR(WLC_E_NATIVE);
        CASE2STR(WLC_E_PKTDELAY_IND);
        CASE2STR(WLC_E_PSTA_PRIMARY_INTF_IND);
#ifdef WLC_E_NAN
        CASE2STR(WLC_E_NAN);
#endif
        CASE2STR(WLC_E_BEACON_FRAME_RX);
        CASE2STR(WLC_E_SERVICE_FOUND);
        CASE2STR(WLC_E_GAS_FRAGMENT_RX);
        CASE2STR(WLC_E_GAS_COMPLETE);
        CASE2STR(WLC_E_P2PO_ADD_DEVICE);
        CASE2STR(WLC_E_P2PO_DEL_DEVICE);
        CASE2STR(WLC_E_WNM_STA_SLEEP);
        CASE2STR(WLC_E_TXFAIL_THRESH);
        CASE2STR(WLC_E_PROXD);
        CASE2STR(WLC_E_BSS_LOAD);
#ifdef WLC_E_MIMO_PWR_SAVE
        CASE2STR(WLC_E_MIMO_PWR_SAVE);
#endif
#ifdef WLC_E_LEAKY_AP_STATS
        CASE2STR(WLC_E_LEAKY_AP_STATS);
#endif
#ifdef WLC_E_ALLOW_CREDIT_BORROW
        CASE2STR(WLC_E_ALLOW_CREDIT_BORROW);
#endif
#ifdef WLC_E_MSCH
        CASE2STR(WLC_E_MSCH);
#endif
        CASE2STR(WLC_E_CSA_START_IND);
        CASE2STR(WLC_E_CSA_DONE_IND);
        CASE2STR(WLC_E_CSA_FAILURE_IND);
        CASE2STR(WLC_E_CCA_CHAN_QUAL);
        CASE2STR(WLC_E_BSSID);
        CASE2STR(WLC_E_TX_STAT_ERROR);
        CASE2STR(WLC_E_BCMC_CREDIT_SUPPORT);
        CASE2STR(WLC_E_PEER_TIMEOUT);
#ifdef WLC_E_BT_WIFI_HANDOVER_REQ
        CASE2STR(WLC_E_BT_WIFI_HANDOVER_REQ);
#endif
#ifdef WLC_E_SPW_TXINHIBIT
        CASE2STR(WLC_E_SPW_TXINHIBIT);
#endif
#ifdef WLC_E_FBT_AUTH_REQ_IND
        CASE2STR(WLC_E_FBT_AUTH_REQ_IND);
#endif
#ifdef WLC_E_RSSI_LQM
        CASE2STR(WLC_E_RSSI_LQM);
#endif
#ifdef WLC_E_PFN_GSCAN_FULL_RESULT
        CASE2STR(WLC_E_PFN_GSCAN_FULL_RESULT);
#endif
#ifdef WLC_E_PFN_SWC
        CASE2STR(WLC_E_PFN_SWC);
#endif
        CASE2STR(WLC_E_AUTHORIZED);
        CASE2STR(WLC_E_PROBREQ_MSG_RX);
#ifdef WLC_E_RMC_EVENT
        CASE2STR(WLC_E_RMC_EVENT);
#endif
#ifdef WLC_E_DPSTA_INTF_IND
        CASE2STR(WLC_E_DPSTA_INTF_IND);
#endif
        CASE2STR(WLC_E_RRM);
#ifdef WLC_E_PFN_SSID_EXT
        CASE2STR(WLC_E_PFN_SSID_EXT);
#endif
#ifdef WLC_E_ROAM_EXP_EVENT
        CASE2STR(WLC_E_ROAM_EXP_EVENT);
#endif
#ifdef WLC_E_ULP
        CASE2STR(WLC_E_ULP);
#endif
#ifdef WLC_E_MACDBG
        CASE2STR(WLC_E_MACDBG);
#endif
#ifdef WLC_E_RESERVED
        CASE2STR(WLC_E_RESERVED);
#endif
        CASE2STR(WLC_E_PRE_ASSOC_RSEP_IND);
#ifdef WLC_E_PSK_AUTH
        CASE2STR(WLC_E_PSK_AUTH);
#endif
#ifdef WLC_E_TKO
        CASE2STR(WLC_E_TKO);
#endif
#ifdef WLC_E_SDB_TRANSITION
        CASE2STR(WLC_E_SDB_TRANSITION);
#endif
#ifdef WLC_E_NATOE_NFCT
        CASE2STR(WLC_E_NATOE_NFCT);
#endif
#ifdef WLC_E_TEMP_THROTTLE
        CASE2STR(WLC_E_TEMP_THROTTLE);
#endif
#ifdef WLC_E_LINK_QUALITY
        CASE2STR(WLC_E_LINK_QUALITY);
#endif
        CASE2STR(WLC_E_BSSTRANS_RESP);
#ifdef WLC_E_HE_TWT_SETUP
        CASE2STR(WLC_E_HE_TWT_SETUP);
#endif
#ifdef WLC_E_NAN_CRITICAL
        CASE2STR(WLC_E_NAN_CRITICAL);
#endif
#ifdef WLC_E_NAN_NON_CRITICAL
        CASE2STR(WLC_E_NAN_NON_CRITICAL);
#endif
        CASE2STR(WLC_E_RADAR_DETECTED);
        CASE2STR(WLC_E_RANGING_EVENT);
        CASE2STR(WLC_E_INVALID_IE);
        CASE2STR(WLC_E_MODE_SWITCH);
#ifdef WLC_E_PKT_FILTER
        CASE2STR(WLC_E_PKT_FILTER);
#endif
#ifdef WLC_E_DMA_TXFLUSH_COMPLETE
        CASE2STR(WLC_E_DMA_TXFLUSH_COMPLETE);
#endif
#ifdef WLC_E_FBT
        CASE2STR(WLC_E_FBT);
#endif
#ifdef WLC_E_PFN_SCAN_BACKOFF
        CASE2STR(WLC_E_PFN_SCAN_BACKOFF);
#endif
#ifdef WLC_E_PFN_BSSID_SCAN_BACKOFF
        CASE2STR(WLC_E_PFN_BSSID_SCAN_BACKOFF);
#endif
#ifdef WLC_E_AGGR_EVENT
        CASE2STR(WLC_E_AGGR_EVENT);
#endif
#ifdef WLC_E_AP_CHAN_CHANGE
        CASE2STR(WLC_E_AP_CHAN_CHANGE);
#endif
#ifdef WLC_E_PSTA_CREATE_IND
        CASE2STR(WLC_E_PSTA_CREATE_IND);
#endif
#ifdef WLC_E_AIRIQ_EVENT
        CASE2STR(WLC_E_AIRIQ_EVENT);
#endif
#ifdef WLC_E_LTE_U_EVENT
        CASE2STR(WLC_E_LTE_U_EVENT);
#endif
        CASE2STR(WLC_E_LAST);

        /* The following have duplicate numbers and compiler will complain.
         * Also it'd be ambiguous what print it should spit out, therefore
         * handle these cases explicitly.
         */
        case WLC_E_PFN_SCAN_NONE:
        // case WLC_E_PFN_BSSID_NET_FOUND;
            return "WLC_E_PFN_SCAN_NONE_OR_WLC_E_PFN_BSSID_NET_FOUND";
        case WLC_E_PFN_SCAN_ALLGONE:
        // case WLC_E_PFN_BSSID_NET_LOST;
            return "WLC_E_PFN_SCAN_ALLGONE_OR_WLC_E_PFN_BSSID_NET_LOST";
        case WLC_E_PFN_BEST_BATCHING:
        // case WLC_E_PFN_SCAN_COMPLETE
            return "WLC_E_PFN_BEST_BATCHING_OR_WLC_E_PFN_SCAN_COMPLETE";
        case WLC_E_IBSS_COALESCE:
        // case WLC_E_AIBSS_TXFAIL;
            return "WLC_E_IBSS_COALESCE_OR_WLC_E_AIBSS_TXFAIL";
    }
#undef CASE2STR
    return "unknown";
}

static void print_stats(void)
{
    int i;
    int64_t delta = g_time2 - g_time1;
    double sec = (double)delta / 1000.0;
    printf("Received %d events\n", g_count);
    printf("Time: %.3f s\n", sec);
    printf("Rate: %.3f ev/s\n", delta ? (double)g_count / sec : 0);
    for (i=0; i <= WLC_E_LAST; i++) {
        if (g_stats[i]) {
            printf("%6d  %s\n", g_stats[i], event2str(i));
        }
    }
}

static bool cmd_watch_events_callback(const char *ifname, os_macaddr_t *client, void  *event)
{
    if (g_opt_count && g_count >= g_opt_count) {
        // discard what is in queue
        ev_break(EV_DEFAULT, EVBREAK_ALL);
        return BCMWL_EVENT_HANDLED;
    }
    // TODO: add more information
    bcm_event_t *ev = (bcm_event_t *)event;
    int type = ntohl(ev->event.event_type);
    LOGI("BCM driver event :: type=%d (%s) ifname=%s hwaddr="PRI(os_macaddr_t),
         type,
         event2str(type),
         ifname,
         FMT(os_macaddr_t, *client));

    // range check, update stats
    if (type < 0) type = 0;
    if (type > WLC_E_LAST) type = WLC_E_LAST;
    g_stats[type]++;

    if (g_opt_delay) usleep(g_opt_delay * 1000);
    g_count++;
    if (g_opt_count && g_count >= g_opt_count) {
        ev_break(EV_DEFAULT, EVBREAK_ALL);
    }

    return BCMWL_EVENT_HANDLED;
}

static bool cmd_watch_events(int argc, char *argv[])
{
    int              i;
    struct ev_loop  *loop = EV_DEFAULT;

    if (argc < 3)
    {
        return false;
    }

    for (i=2; i<argc; i++)
    {
        char *ifname = argv[i];

        if (bcmwl_event_register(loop, ifname, cmd_watch_events_callback))
        {
            LOGI("Registered to events on %s", ifname);
        }
    }

    LOGI("Listening for events...");
    g_time1 = clock_mono_ms();
    ev_run(loop, 0);
    g_time2 = clock_mono_ms();
    print_stats();

    for (i=2; i<argc; i++) {
        bcmwl_event_unregister(loop, argv[i], cmd_watch_events_callback);
    }

    return true;
}

static bool cmd_set_event(int argc, char *argv[])
{
    int i;
    unsigned long e;

    if (argc < 4)
    {
        return false;
    }

    e = strtol(argv[2], NULL, 10);
    if (e >= WLC_E_LAST)
    {
        LOGE("Invalid event value! :: e=%s", argv[2]);
        return false;
    }

    for (i=3; i<argc; i++)
    {
        char *ifname = argv[i];
        bcmwl_event_mask_t m;
        if (!bcmwl_event_mask_get(ifname, &m))
        {
            LOGE("Failed to get active events! :: ifname=%s", ifname);
            return false;
        }

        bcmwl_event_mask_bit_set(&m, e);

        if (!bcmwl_event_mask_set(ifname, &m))
        {
            LOGE("Failed to store active events! :: ifname=%s", ifname);
            return false;
        }
    }

    return true;
}

static bool cmd_unset_event(int argc, char *argv[])
{
    int           i;
    unsigned long e;

    if (argc < 4)
    {
        return false;
    }

    e = strtol(argv[2], NULL, 10);
    if (e >= WLC_E_LAST)
    {
        LOGE("Invalid event value! :: e=%s", argv[2]);
        return false;
    }

    for (i=3; i<argc; i++)
    {
        char *ifname = argv[i];
        bcmwl_event_mask_t m;
        if (!bcmwl_event_mask_get(ifname, &m))
        {
            LOGE("Failed to get active events! :: ifname=%s", ifname);
            return false;
        }

        bcmwl_event_mask_bit_unset(&m, e);

        if (!bcmwl_event_mask_set(ifname, &m))
        {
            LOGE("Failed to store active events! :: ifname=%s", ifname);
            return false;
        }
    }

    return true;
}

static bool cmd_detect_max_lan_ifnames(int argc, char *argv[])
{
    const char *ifname;
    const char *ifnames;
    int limit;
    int ok;
    int i;

    limit = 32;
    if (argc >= 3)
        limit = atoi(argv[2]);

    for (i=0; i<limit; i++)
    {
        /* bcmwl_lan_validate is intended to be internal function helper for
         * bcmwl_lan_alloc(). It changes system state to probe if something
         * it's asked to is possible. Try our best to avoid breaking the system
         * as it's running by preserving nvram values.
         */
        ifname = NVG(bcmwl_lan(i), "ifname");
        ifnames = NVG(bcmwl_lan(i), "ifnames");
        LOGI("testing lan ifname idx %d / %d", i, limit);
        ok = bcmwl_lan_validate(i) >= 0;
        if (ifname && strlen(ifname)) NVS(bcmwl_lan(i), "ifname", ifname);
        if (ifnames && strlen(ifnames)) NVS(bcmwl_lan(i), "ifnames", ifnames);
        if (ok) continue;
        LOGI("max number of lans: %d", i);
        break;
    }

    return true;
}

static bool cmd_tx_avg_rate(int argc, char *argv[])
{
    struct bcmwl_sta_rate rate;
    const char *ifname;
    const char *macstr;

    if (WARN_ON(argc < 2))
        return false;

    bcmwl_ioctl_init();
    ifname = *argv++;
    macstr = *argv++;
    if (bcmwl_sta_get_tx_avg_rate(ifname, macstr, &rate) < 0)
        return false;

    printf("%s: %s: tx mbps %f/%f psr %f tried %f expected %f/%f\n",
           ifname, macstr, rate.mbps_perceived, rate.mbps_capacity, rate.psr, rate.tried,
           /* rule of thumb: 10% mac overhead, 15% tcp ack/collisions */
           rate.mbps_perceived * rate.psr * 0.9 * 0.85,
           rate.mbps_capacity * rate.psr * 0.9 * 0.85);
    return true;
}

int main(int argc, char *argv[])
{
    bool success = false;
    int opt;

    while ((opt = getopt(argc, argv, "vqhd:c:")) != -1)
    {
        switch (opt) {
            case 'v':
                if (g_opt_severity < LOG_SEVERITY_TRACE) g_opt_severity++;
                break;

            case 'q':
                if (g_opt_severity > LOG_SEVERITY_WARN) g_opt_severity--;
                break;

            case 'd':
                g_opt_delay = atoi(optarg);
                break;

            case 'c':
                g_opt_count = atoi(optarg);
                break;

            case 'h':
            default:
                usage();
                return EXIT_FAILURE;
        }
    }
    argc -= optind - 1;
    argv += optind - 1;

    if (argc < 2)
    {
        usage();
        goto end;
    }

    target_log_open("BCMCLI", 0);

    log_severity_set(g_opt_severity);

    if (strcmp(argv[1], "watch_events") == 0)
    {
        success = cmd_watch_events(argc, argv);
    }
    else if (strcmp(argv[1], "set_event") == 0)
    {
        success = cmd_set_event(argc, argv);
    }
    else if (strcmp(argv[1], "unset_event") == 0)
    {
        success = cmd_unset_event(argc, argv);
    }
    else if (strcmp(argv[1], "detect_max_lan_ifnames") == 0)
    {
        success = cmd_detect_max_lan_ifnames(argc, argv);
    }
    else if (strcmp(argv[1], "tx_avg_rate") == 0)
    {
        success = cmd_tx_avg_rate(argc - 2, argv + 2);
    }
    else if (strcmp(argv[1], "detect_dongle") == 0)
    {
        success = bcmwl_radio_adapter_is_operational(argv[2]);
        printf("Dongle %s: attached: %s", argv[2], success == true ? "yes" : "no");
        success = true;
    }
    else if ((strcmp(argv[1], "dhdctl") == 0) || (strcmp(argv[1], "wlctl") == 0))
    {
        char *buf = bcmwl_wl(argv[2], argv[1], (const char **)argv + 3);

        if (buf) {
            printf("%s\n", buf);
            free(buf);
            success = true;
        }
    }
    else
    {
        usage();
    }

end:
    if (!success)
    {
        LOGE("Command failed");
    }
    exit(success ? EXIT_SUCCESS : EXIT_FAILURE);
}
