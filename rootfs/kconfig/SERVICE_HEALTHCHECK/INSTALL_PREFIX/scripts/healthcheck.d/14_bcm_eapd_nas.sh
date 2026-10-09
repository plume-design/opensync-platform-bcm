#!/bin/sh
# Checks if authorization (wpa psk handling) processes are
# still running. Without them no leaf or client will be able
# to connect.
#
# OWM/target is expected to supervise and restart these.
# However if the failure is neither transient nor one-off
# we need to reboot the unit to recover.
#
# This is especially important for units in GW role.

die() { log_warn "$*"; Healthcheck_Fail; }
set -e
pidof nas | grep -q .
pidof eapd | grep -q .
! test -e /tmp/.nas_ping_supported || rm /tmp/.nas_ping || die nas ping failed
! test -e /tmp/.eapd_ping_supported || rm /tmp/.eapd_ping || die eapd ping failed
Healthcheck_Pass
