#!/bin/sh
# {# jinja-parse #}
#
# Collect BCM info
#
. "$LOGPULL_LIB"

bcmwl_list_vifs()
{
    ls /sys/class/net | grep ^wl
}

bcmwl_list_phys()
{
    ls /sys/class/net | grep ^wl | grep -vF .
}

collect_bcmwl()
{
    collect_cmd nvram getall
    collect_cmd cat /data/.kernel_nvram.setting
    for i in $(bcmwl_list_vifs); do
        collect_cmd wl -i $i assoc
        collect_cmd wl -i $i chanspec
        collect_cmd wl -i $i curpower
        collect_cmd wl -i $i PM
        collect_cmd wl -i $i rrm_nbr_list
        collect_cmd wl -i $i mac
        collect_cmd wl -i $i macmode
        collect_cmd wl -i $i assoclist
        collect_cmd wl -i $i bss
        collect_cmd wl -i $i ap
        collect_cmd wl -i $i apsta
        collect_cmd wl -i $i infra
        collect_cmd wl -i $i ssid
        collect_cmd wl -i $i bi
        for sta in $(wl -i $i assoclist | cut -d' ' -f2)
        do
            collect_cmd wl -i $i sta_info $sta
        done
    done
    for i in $(bcmwl_list_phys); do
        collect_cmd wl -i $i isup
        collect_cmd wl -i $i radio
        collect_cmd wl -i $i bw_cap 2g
        collect_cmd wl -i $i bw_cap 5g
        collect_cmd wl -i $i bw_cap 6g
        collect_cmd wl -i $i msched
        collect_cmd wl -i $i muinfo
        collect_cmd wl -i $i muinfo -v
        collect_cmd wl -i $i mu_policy
        collect_cmd wl -i $i mu_features
        collect_cmd wl -i $i max_muclients
        collect_cmd wl -i $i he enab
        collect_cmd wl -i $i he features
        collect_cmd wl -i $i he bsscolor
        collect_cmd wl -i $i he range_ext
        collect_cmd wl -i $i twt enab
        collect_cmd wl -i $i twt list
        collect_cmd wl -i $i radar
        collect_cmd wl -i $i dfs_preism
        collect_cmd wl -i $i dfs_ap_move
        collect_cmd wl -i $i dfs_status
        collect_cmd wl -i $i dfs_status_all
        collect_cmd wl -i $i chan_info
        collect_cmd wl -i $i scanresults
        collect_cmd wl -i $i chanim_stats
        collect_cmd wl -i $i chanspecs
        collect_cmd wl -i $i country
        collect_cmd wl -i $i chanspec_txpwr_max
        collect_cmd wl -i $i txpwr
        collect_cmd wl -i $i txpwr1
        collect_cmd wl -i $i txpwr_target_max
        collect_cmd wl -i $i curppr
        collect_cmd wl -i $i ver
        collect_cmd wl -i $i revinfo
        collect_cmd wl -i $i radar_status
        collect_cmd dhdctl -i $i consoledump
    done

    collect_cmd cat /proc/fcache/misc/host_dev_mac
    collect_cmd ls -al /data

    if [ -e /etc/patch.version ]; then
        collect_cmd cat /etc/patch.version
    fi
    if [ -e /proc/driver/license ]; then
        collect_cmd cat /proc/driver/license
    else
        collect_cmd bp3 status
    fi
}

collect_flowcache()
{
    if [ -e /bin/fcctl ]; then
        find /proc/fcache/ -type f -exec echo {} \; -exec cat {} \; > /tmp/fcache_logs
        mv /tmp/fcache_logs "$LOGPULL_TMP_DIR"/_tmp_fcache_logs
        collect_cmd fcctl status
    fi
}

collect_archer()
{
    if [ -e /bin/archerctl ]; then
        archerctl flows --all
        archerctl status
        archerctl host
        archerctl stats
        sleep 1
        dmesg > /tmp/archer_logs
        mv /tmp/archer_logs "$LOGPULL_TMP_DIR"/_tmp_archer_logs
    fi
}

collect_flowmgr()
{
    if [ -e /proc/driver/flowmgr ]; then
        collect_file /proc/driver/flowmgr/status
        collect_file /proc/net/nf_conntrack_offload
    fi
}

collect_debug_monitor()
{
    if [ -e {{INSTALL_PREFIX}}/log_archive/debug_monitor/* ]; then
        mkdir -p "$LOGPULL_TMP_DIR/debug_monitor"
        mv {{INSTALL_PREFIX}}/log_archive/debug_monitor/* "$LOGPULL_TMP_DIR/debug_monitor"
    fi
}

collect_platform_bcm()
{
    collect_bcmwl
# Currently disabled since it can trigger kernel panic
# when collecting flowcache or archer status
#    collect_flowcache
#    collect_archer
    collect_flowmgr
    collect_debug_monitor
}

collect_platform_bcm
