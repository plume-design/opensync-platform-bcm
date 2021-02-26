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

#
# Override file for OSN
#

# Add BCM QoS Implementation
ifdef CONFIG_OSN_BACKEND_QOS_BCM_ARCHER

UNIT_SRC_TOP += $(OVERRIDE_DIR)/src/osn_qos_bcm_archer.c

# Add BCMSDK include paths that are required for archer.h, archer_api.h and
# skb_defines.h
UNIT_CFLAGS += -I$(BCM_BUILD_ROOT)/bcmdrivers/opensource/include/bcm963xx
UNIT_CFLAGS += -I$(BCM_BUILD_ROOT)/userspace/private/include

# The final binary must be linked with -larcher
UNIT_EXPORT_LDFLAGS += -larcher

endif

UNIT_SRC_TOP += $(if $(CONFIG_OSN_BACKEND_VLAN_BCM_VLANCTL),$(OVERRIDE_DIR)/src/osn_vlan_bcm_vlanctl.c,)
