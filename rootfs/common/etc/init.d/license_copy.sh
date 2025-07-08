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

