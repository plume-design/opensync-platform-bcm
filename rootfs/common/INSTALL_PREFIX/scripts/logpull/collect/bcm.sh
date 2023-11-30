#!/bin/sh

# Copyright (c) 2017, Plume Design Inc. All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#    3. Neither the name of the Plume Design Inc. nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL Plume Design Inc. BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

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
        collect_cmd dhdctl -i $i consoledump
    done

    collect_cmd cat /proc/fcache/misc/host_dev_mac
    collect_cmd ls -al /data

    if [ -e /etc/patch.version ]; then
        collect_cmd cat /etc/patch.version
    fi
    collect_cmd cat /proc/driver/license
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
