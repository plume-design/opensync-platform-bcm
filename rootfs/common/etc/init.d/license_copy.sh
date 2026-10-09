#!/bin/sh

# SDK 5.04L.04 and newer use bp3 for licensing and expect
# the licenses to be available in /data/licenses
# There are two startup scripts that handle the bp3 licenses:
# - S45bcm-base-drivers -> ../init.d/bcm-base-drivers.sh
#   loads the bp3 driver:
#   insmod bcm_bp3drv.ko modparam_license_dir="/data/licenses"
# - S45bcm-c-license -> ../init.d/license_init.sh
#   creates a /data/licenses directory
# This startup script will copy any /etc/licenses_bp3/*.bin to /data/licenses
# because /data is not part of an fw image. note, /etc/licenses is not
# used here to avoid conflict with the previous licensing type
# which used text based license files in /etc/licenses

LIC_SRC=/etc/licenses_bp3
LIC_DEST=/data/licenses

start()
{
    if ! which bp3 2>/dev/null; then exit 0; fi
    mkdir -p "$LIC_DEST"
    for F in "$LIC_SRC"/*.bin; do
        if [ ! -f "$F" ]; then continue; fi
        DEST="$LIC_DEST"/$(basename "$F")
        # cmp is used to avoid unneccesary writes to flash
        if ! cmp "$F" "$DEST" 2>/dev/null; then
            cp -p "$F" "$DEST"
        fi
    done
}

case "$1" in
    start) start; exit 0 ;;
    *) exit 0 ;;
esac

