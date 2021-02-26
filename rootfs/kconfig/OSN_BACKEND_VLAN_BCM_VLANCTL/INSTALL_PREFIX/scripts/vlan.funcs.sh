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


vlan_log()
{
    logger -st vlan "$@"
}

vlan_ifname()
{
    echo "$1.$2"
}

vlan_add()
{
    [ -d "/sys/class/net/$1.$2" ] && return 0

    if [ -d "/sys/class/net/$1.vc" ]
    then
        vlan_log "Adding VLAN interface $1.$2 usig vlanctl"
        vlanctl --mcast --if-create-name $1.vc $1.$2
        vlanctl --if $1.vc --rx --tags 1 --filter-vid $2 0 --pop-tag --set-rxif $1.$2 --rule-append
        vlanctl --if $1.vc --tx --tags 0 --filter-txif $1.$2 --push-tag --set-vid $2 0 --rule-append
        vlanctl --if $1.vc --set-if-mode-rg
    else
        vlan_log "Adding VLAN interface $1.$2 usig vconfig"
        vconfig add "$1" "$2"
    fi
}

vlan_del()
{
    [ ! -d "/sys/class/net/$1.$2" ] && return 0

    if [ -d "/sys/class/net/$1.vc" ]
    then
        vlan_log "Removing VLAN interface $1.$2 using vlanctl"
        vlanctl --if-delete "$1.$2"
    else
        vlan_log "Removing VLAN interface $1.$2 using vconfig"
        vconfig rem "$1.$2"
    fi
}
