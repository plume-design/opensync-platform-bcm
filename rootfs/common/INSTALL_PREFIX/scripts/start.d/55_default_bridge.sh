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

# add default internal bridge
{%- if CONFIG_TARGET_USE_WAN_BRIDGE %}
# Add offset to a MAC address
mac_set_local_bit()
{
    local MAC="$1"

    # ${MAC%%:*} - first digit in MAC address
    # ${MAC#*:} - MAC without first digit
    printf "%02X:%s" $(( 0x${MAC%%:*} | 0x2 )) "${MAC#*:}"
}
{%- endif %}

# Get the MAC address of an interface
mac_get()
{
    ifconfig "$1" | grep -o -E '([A-F0-9]{2}:){5}[A-F0-9]{2}'
}

MAC_ETH0=$(mac_get eth0)
{%- if CONFIG_TARGET_USE_WAN_BRIDGE %}
# Set the local bit on eth0
MAC_BRHOME=$(mac_set_local_bit ${MAC_ETH0})
{%- else %}
MAC_BRHOME=$MAC_ETH0
{%- endif %}

{%- if CONFIG_TARGET_USE_WAN_BRIDGE %}
echo "Adding WAN bridge with MAC address $MAC_ETH0"
ovs-vsctl add-br {{ CONFIG_TARGET_WAN_BRIDGE_NAME }}
ovs-vsctl set bridge {{ CONFIG_TARGET_WAN_BRIDGE_NAME }} other-config:hwaddr="$MAC_ETH0"
ovs-vsctl set int {{ CONFIG_TARGET_WAN_BRIDGE_NAME }} mtu_request=1500
{%- endif %}

echo "Adding LAN bridge with MAC address $MAC_BRHOME"
ovs-vsctl add-br {{ CONFIG_TARGET_LAN_BRIDGE_NAME }}
ovs-vsctl set bridge {{ CONFIG_TARGET_LAN_BRIDGE_NAME }} other-config:hwaddr="$MAC_BRHOME"
ovs-ofctl add-flow {{ CONFIG_TARGET_LAN_BRIDGE_NAME }} table=0,priority=50,dl_type=0x886c,actions=local

