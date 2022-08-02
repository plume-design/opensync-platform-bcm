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


####################### INFORMATION SECTION - START ###########################
#
#   Broadcom (BCM) platform overrides
#
####################### INFORMATION SECTION - STOP ############################

echo "${FUT_TOPDIR}/shell/lib/override/bcm_platform_override.sh sourced"

###############################################################################
# DESCRIPTION:
#   Function starts wireless driver on a device.
# INPUT PARAMETER(S):
#   None.
# RETURNS:
#   None.
# USAGE EXAMPLE(S):
#   start_wireless_driver
###############################################################################
start_wireless_driver()
{
    /etc/init.d/bcm-wlan-drivers.sh start
}

###############################################################################
# DESCRIPTION:
#   Function stops wireless driver on a device.
# INPUT PARAMETER(S):
#   None.
# RETURNS:
#   None.
# USAGE EXAMPLE(S):
#   stop_wireless_driver
###############################################################################
stop_wireless_driver()
{
    /etc/init.d/bcm-wlan-drivers.sh stop
}

###############################################################################
# DESCRIPTION:
#   Function retrieves interface regulatory domain.
# INPUT PARAMETER(S):
#   $1  Physical Radio interface name for which to retrieve regulatory domain (string, required)
# ECHOES:
#   Interface regulatory domain - defaults to US if any failure occurs
# NOTE:
#   Function first checks Wifi_Radio_State interface 'country' field, if it is not populated, it retrieves
#   Wifi_Radio_State 'hw_params' field and looks for 'reg_domain' entry
# USAGE EXAMPLE(S):
#   get_iface_regulatory_domain wifi0
###############################################################################
get_iface_regulatory_domain()
{
    local NARGS=1
    [ $# -ne ${NARGS} ] &&
        raise "wm2_lib:get_iface_regulatory_domain requires ${NARGS} input argument(s), $# given" -arg
    # shellcheck disable=SC2034
    if_name="${1}"
    country_found=1
    country=$(get_ovsdb_entry_value Wifi_Radio_State country -w if_name "${if_name}")
    if [ "${country}" == "[\"set\",[]]" ]; then
        log -deb "wm2_lib:get_iface_regulatory_domain - Country is not set in Wifi_Radio_State."
        hw_params_reg_domain=$(get_ovsdb_entry_value Wifi_Radio_State hw_params -w if_name "${if_name}" -json_value reg_domain)
        log -deb "wm2_lib:get_iface_regulatory_domain - Trying to acquire country region trough hw_params: ${hw_params_reg_domain}"
        # 58 (3a hex) US | 55 (37 hex) EU
        if [ ${?} == 0 ]; then
            if [ ${hw_params_reg_domain} == '"58"' ]; then
                country='US'
            elif [ ${hw_params_reg_domain} == '"55"' ]; then
                country='EU'
            else
                log -deb "wm2_lib:get_iface_regulatory_domain - Failed to retrieve device regulatory domain. Defaulting to US regulatory rules!"
                country='US'
            fi
        else
            log -deb "wm2_lib:get_iface_regulatory_domain - Failed to retrieve device regulatory domain. Defaulting to US regulatory rules!"
            country='US'
        fi
        country_found=0
    else
        country_found=0
    fi
    if [ "${country_found}" == 1 ];then
        log -deb "wm2_lib:get_iface_regulatory_domain - Failed to retrieve device regulatory domain. Defaulting to US regulatory rules!"
        country='US'
    fi
    echo "${country}"
}

###############################################################################
# DESCRIPTION:
#   Function checks if Country is applied at OS - LEVEL2.
#   Uses wl to get Country info.
#   Provide override function if wl not available on device.
#   Raises exception on fail.
# INPUT PARAMETER(S):
#   $1  Country (string, required)
#   $2  Interface name (string, required)
# RETURNS:
#   0   Country is as expected.
#   See DESCRIPTION.
# USAGE EXAMPLE(S):
#   check_country_at_os_level US <IF_NAME>
###############################################################################
check_country_at_os_level()
{
    local NARGS=2
    [ $# -ne ${NARGS} ] &&
        raise "bcm_platform_override:check_country_at_os_level requires ${NARGS} input argument(s), $# given" -arg
    wm2_country=$1
    wm2_if_name=$2

    log "bcm_platform_override:check_country_at_os_level - Checking COUNTRY at OS - LEVEL2"

    wait_for_function_response 0 "wl -a $wm2_if_name country | grep -F $wm2_country" &&
        log -deb "bcm_platform_override:check_country_at_os_level - Country '$wm2_country' is set at OS - LEVEL2 - Success" ||
        raise "FAIL: Country '$wm2_country' is not set at OS - LEVEL2" -l "bcm_platform_override:check_country_at_os_level" -tc

    return 0
}


###############################################################################
# DESCRIPTION:
#   Function simulates DFS (Dynamic Frequency Shift) radar event on interface.
# INPUT PARAMETER(S):
#   $1  channel (int, required)
# RETURNS:
#   0   Simulation was a success.
# USAGE EXAMPLE(S):
#   simulate_dfs_radar <IF_NAME>
###############################################################################
simulate_dfs_radar()
{
    local NARGS=1
    [ $# -ne ${NARGS} ] &&
        raise "bcm_platform_override:simulate_dfs_radar requires ${NARGS} input argument(s), $# given" -arg
    wm2_if_name=$1

    log "bcm_platform_override:simulate_dfs_radar - Trigering DFS radar event on wm2_if_name"

    wait_for_function_response 0 "wl -i $wm2_if_name radar 2" &&
        log -deb "bcm_platform_override:simulate_dfs_radar - DFS event: '$wm2_if_name' simulation was SUCCESSFUL" ||
        log -err "bcm_platform_override:simulate_dfs_radar - DFS event: '$wm2_if_name' simulation was UNSUCCESSFUL"

    return 0
}

###############################################################################
# DESCRIPTION:
#   Function echoes Tx Power set at OS – LEVEL2.
#   Uses wl to get Tx Power info for VIF interface.
# INPUT PARAMETER(S):
#   $1  VIF interface name (string, required)
# RETURNS:
#   0   on successful Tx Power retrieval, fails otherwise
# ECHOES:
#   Tx Power from OS
# USAGE EXAMPLE(S):
#   get_tx_power_from_os home-ap-24
###############################################################################
get_tx_power_from_os()
{
    local NARGS=1
    [ $# -ne ${NARGS} ] &&
        raise "bcm_platform_override:get_tx_power_from_os requires ${NARGS} input argument(s), $# given" -arg
    wm2_vif_if_name=$1

    wl -i $wm2_vif_if_name txpwr | awk '{print $1}' | awk -F '.' '{print $1}'
}

###############################################################################
# DESCRIPTION:
#   Function checks if Tx Chainmask is applied at OS - LEVEL2.
#   Function raises an exception if Tx Chainmask is not applied.
# INPUT PARAMETER(S):
#   $1  Tx Chainmask (int, required)
#   $2  Interface name (string, required)
# RETURNS:
#   0   On success.
#   See DESCRIPTION.
# USAGE EXAMPLE(S):
#   check_tx_chainmask_at_os_level 3 home-ap-U50
###############################################################################
check_tx_chainmask_at_os_level()
{
    local NARGS=2
    [ $# -ne ${NARGS} ] &&
        raise "bcm_platform_override:check_tx_chainmask_at_os_level requires ${NARGS} input argument(s), $# given" -arg
    wm2_tx_chainmask=$1
    wm2_if_name=$2

    log -deb "bcm_platform_override:check_tx_chainmask_at_os_level - Checking Tx Chainmask at OS - LEVEL2"

    wait_for_function_response 0 "wl -a $wm2_if_name txchain | grep -F $wm2_tx_chainmask" &&
        log -deb "bcm_platform_override:check_tx_chainmask_at_os_level - Tx Chainmask '$wm2_tx_chainmask' is set at OS - LEVEL2 - Success" ||
        raise "FAIL: Tx Chainmask '$wm2_tx_chainmask' is not set at OS - LEVEL2" -l "bcm_platform_override:check_tx_chainmask_at_os_level" -tc

    return 0
}

###############################################################################
# DESCRIPTION:
#   Function checks if Beacon interval is applied at OS - LEVEL2.
#   Function raises an exception if Beacon interval is not applied.
# INPUT PARAMETER(S):
#   $1  Beacon interval (int, required)
#   $2  VIF interface name (string, required)
# RETURNS:
#   0   Beacon interval is as expected.
#   See DESCRIPTION.
# USAGE EXAMPLE(S):
#   check_beacon_interval_at_os_level 600 home-ap-U50
###############################################################################
check_beacon_interval_at_os_level()
{
    local NARGS=2
    [ $# -ne ${NARGS} ] &&
        raise "bcm_platform_override:check_beacon_interval_at_os_level requires ${NARGS} input argument(s), $# given" -arg
    wm2_bcn_int=$1
    wm2_vif_if_name=$2

    log -deb "bcm_platform_override:check_beacon_interval_at_os_level - Checking Beacon interval at OS - LEVEL2"

    wait_for_function_response 0 "wl -a $wm2_vif_if_name bi | grep -F $wm2_bcn_int" &&
        log -deb "bcm_platform_override:check_beacon_interval_at_os_level - Beacon interval '$wm2_bcn_int' for '$wm2_vif_if_name' is set at OS - LEVEL2 - Success" ||
        raise "FAIL: Beacon interval $'wm2_bcn_int' is not set at OS - LEVEL2" -l "bcm_platform_override:check_beacon_interval_at_os_level" -tc

    return 0
}

###############################################################################
# DESCRIPTION:
#   Function returns channel set at OS - LEVEL2.
# INPUT PARAMETER(S):
#   $1  VIF interface name (string, required)
# RETURNS:
#   0   On successful channel retrieval, fails otherwise
# ECHOES:
#   Channel from OS
# USAGE EXAMPLE(S):
#   get_channel_from_os wl0
###############################################################################
get_channel_from_os()
{
    local NARGS=1
    [ $# -ne ${NARGS} ] &&
        raise "bcm_platform_override:get_channel_from_os requires ${NARGS} input argument(s), $# given" -arg
    wm2_vif_if_name=$1

    wl -a $wm2_vif_if_name channel | grep -F "current mac channel" | cut -f2
}

###############################################################################
# DESCRIPTION:
#   Function returns HT mode set at OS - LEVEL2.
# INPUT PARAMETER(S):
#   $1  VIF interface name (string, required)
#   $2  channel (int, required)
# RETURNS:
#   0   On successful channel retrieval, fails otherwise
# ECHOES:
#   HT mode from OS in format: HT20, HT40 (examples)
# USAGE EXAMPLE(S):
#   get_ht_mode_from_os wl1.2 1
###############################################################################
get_ht_mode_from_os()
{
    local NARGS=2
    [ $# -ne ${NARGS} ] &&
        raise "bcm_platform_override:get_ht_mode_from_os requires ${NARGS} input argument(s), $# given" -arg
    wm2_vif_if_name=$1
    wm2_channel=$2

    chanspec_str=$(wl -a "$wm2_vif_if_name" chanspec | cut -d' ' -f1)
    echo $chanspec_str | grep -q "/160"
    if [ $? -eq 0 ]; then
        echo "HT160"
        exit 0
    fi
    echo $chanspec_str | grep -q "/80"
    if [ $? -eq 0 ]; then
        echo "HT80"
        exit 0
    fi
    echo $chanspec_str | grep -q "[lu]"
    if [ $? -eq 0 ]; then
        echo "HT40"
        exit 0
    fi
    echo $chanspec_str | grep -qw "$wm2_channel"
    if [ $? -eq 0 ]; then
        echo "HT20"
        exit 0
    fi
    exit 1
}

###############################################################################
# DESCRIPTION:
#   Function checks vlan interface existence at OS - LEVEL2.
# INPUT PARAMETER(S):
#   $1  parent_ifname (string, required)
#   $2  vlan_id (int, required)
# RETURNS:
#   0   On success.
# USAGE EXAMPLE(S):
#  check_vlan_iface eth0 100
###############################################################################
check_vlan_iface()
{
    local NARGS=2
    [ $# -ne ${NARGS} ] &&
        raise "bcm_platform_override:check_vlan_iface requires ${NARGS} input argument(s), $# given" -arg
    parent_ifname=$1
    vlan_id=$2

    if_name="$parent_ifname.$vlan_id"
    sys_entry="/sys/class/net/${if_name}"

    log "bcm_platform_override:check_vlan_iface: Checking for ${sys_entry} existence - LEVEL2"
    wait_for_function_response 0 "[ -e ${sys_entry} ]" &&
        log "bcm_platform_override:check_vlan_iface: LEVEL2 - sys file entry '${sys_entry}' exists - Success" ||
        raise "FAIL: LEVEL2 - sys file entry '${sys_entry}' does not exist" -l "bcm_platform_override:check_vlan_iface" -tc

    return 0
}

###############################################################################
# DESCRIPTION:
#   Function checks for CSA(Channel Switch Announcement) msg on the LEAF device
#   sent by GW on channel change.
# INPUT PARAMETER(S):
#   $1  mac address of GW (string, required)
#   $2  CSA channel GW switches to (int, required)
#   $3  HT mode of the channel (string, required)
# RETURNS:
#   0   CSA message is found in LEAF device var logs, fail otherwise.
# USAGE EXAMPLE(S):
#   check_sta_send_csa_message 1A:2B:3C:4D:5E:6F 6 HT20
###############################################################################
check_sta_send_csa_message()
{
    local NARGS=3
    [ $# -ne ${NARGS} ] &&
        raise "bcm_platform_override:check_sta_send_csa_message requires ${NARGS} input argument(s), $# given" -arg
    gw_vif_mac=$1
    gw_csa_channel=$2
    ht_mode=$3

    # Example log:
    # Sep 30 09:29:52 WM[2724]: <INFO> MISC: wl0.2: csa completed (52 (0xec32))
    wm_csa_log_grep="$LOGREAD | grep -i 'csa completed ($gw_csa_channel'"
    wait_for_function_response 0 "${wm_csa_log_grep}" 90 &&
        log "bcm_platform_override:check_sta_send_csa_message : 'csa completed' message found in logs for channel:${gw_csa_channel} with HT mode: ${ht_mode} - Success" ||
        raise "FAIL: Failed to find 'csa completed' message in logs for channel: ${gw_csa_channel} with HT mode: ${ht_mode}" -l "bcm_platform_override:check_sta_send_csa_message" -tc
    return 0
}

####################### Broadcom (BCM) PLATFORM OVERRIDE SECTION - STOP #########################

###################################################################################
# DESCRIPTION:
#   Function clears the DNS cache on BCM platforms by killing the dnsmasq process.
# INPUT PARAMETER(S):
#   None.
# RETURNS:
#   0   On successful DNS cache clear.
#   1   On failure to clear DNS cache.
# USAGE EXAMPLE(S):
#   clear_dns_cache
###############################################################################
clear_dns_cache()
{
    log -deb "bcm_platform_override:clear_dns_cache - Clearing DNS cache."

    process="dnsmasq"
    $(killall -HUP ${process})
    if [ $? -eq 0 ]; then
        log -deb "bcm_platform_override:clear_dns_cache - ${process} killed - DNS cache cleared - Success"
        return 0
    else
        log -err "FAIL: bcm_platform_override:clear_dns_cache - ${process} kill failed - DNS cache not cleared"
        return 1
    fi
}
