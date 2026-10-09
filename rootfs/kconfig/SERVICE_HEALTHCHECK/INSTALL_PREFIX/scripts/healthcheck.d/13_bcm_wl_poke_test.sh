#!/bin/sh
# Checks if driver is still responding in a meaningful way.
#
# If the driver doesn't respond to basic commands it's
# likely not working properly anymore, and links (if any)
# are likely dead too, because wpa re-keying needs to talk
# to the driver via ioctls.
#
# If this is neither a transient nor one-off failure
# we need to reboot the unit to recover.
#
# This is especially important for units in GW role.

die() { log_warn "$*"; Healthcheck_Fail; }
set -e
cd /sys/class/net
for i in wl?
do
    wl -i $i event_msgs_ext | grep -q . || die $i not responsive
done
Healthcheck_Pass
