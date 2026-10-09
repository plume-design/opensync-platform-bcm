#!/bin/sh
# Checks if BSS is up using platform-specific tools.
#
# 1. Ensures the VAP is managed by the driver
# 2. Checks if the BSS is up and not in CAC
# 3. Validates if the BSS is associated


ifname=$1

if ! wl -i "$ifname" bss >/dev/null 2>/dev/null
then
    # Possibly handled by different driver.
    exit_health_bss_driver_mismatch
fi

if ! wl -i "$ifname" bss | grep -q up
then
    if wl -i "$ifname" dfs_status | grep -q PRE-ISM
    then
        # Driver sometimes puts some of the BSSes down while
        # CAC is in progress.
        log_info "$ifname: bss is down, but cac is in progress, ignoring"
        exit 0
    fi
    log_warn "$ifname: bss is not up"
    exit_health_bss_down
fi

if wl -i "$ifname" bssid | grep -q '00:00:00:00:00:00'
then
    log_warn "$ifname: bss up, but not associated"
    exit_health_bss_up_not_associated
fi

exit 0
