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

##############################################################################
#
# BCM wireless lan abstraction layer lib
#
##############################################################################

UNIT_NAME := bcmwl
UNIT_TYPE := LIB

UNIT_SRC  := src/bcmwl_radio.c
UNIT_SRC  += src/bcmwl_vap.c
UNIT_SRC  += src/bcmwl_event.c
UNIT_SRC  += src/bcmwl_sta.c
UNIT_SRC  += src/bcmwl_acl.c
UNIT_SRC  += src/bcmwl_nvram.c
UNIT_SRC  += $(if $(CONFIG_BCM_NVRAM_EXEC),src/bcmwl_nvram_exec.c,)
UNIT_SRC  += $(if $(CONFIG_BCM_NVRAM_LIB),src/bcmwl_nvram_lib.c,)
UNIT_SRC  += src/bcmwl_lan.c
UNIT_SRC  += src/bcmwl_chanspec.c
UNIT_SRC  += src/bcmwl_misc.c
UNIT_SRC  += src/bcmwl_ioctl.c
UNIT_SRC  += $(if $(CONFIG_BCM_USE_NAS),src/bcmwl_roam.c,)
UNIT_SRC  += $(if $(CONFIG_BCM_USE_NAS),src/bcmwl_nas.c,)
UNIT_SRC  += $(if $(CONFIG_BCM_USE_NAS),src/bcmwl_wps.c,)
UNIT_SRC  += $(if $(CONFIG_BCM_USE_HOSTAP),src/bcmwl_hostap.c,)
UNIT_SRC  += src/bcmwl_debounce.c
UNIT_SRC  += src/bcmwl_dfs.c
UNIT_SRC  += src/bcmwl_cim.c
UNIT_SRC  += src/bcmwl.c

UNIT_CFLAGS := -I$(UNIT_PATH)/inc
UNIT_CFLAGS += $(if $(CONFIG_BCM_NVRAM_LIB),-I$(BCM_BUILD_ROOT)/userspace/private/libs/wlcsm/include,)
UNIT_LDFLAGS += $(if $(CONFIG_BCM_NVRAM_LIB),-L$(INSTALL_DIR)/lib -lwlcsm,)

UNIT_EXPORT_CFLAGS := $(UNIT_CFLAGS)
UNIT_EXPORT_LDFLAGS := $(UNIT_LDFLAGS)

# CMN_WLAN_FLAGS includes -DWL_DEFAULT_NUM_SSID=$(BRCM_DEFAULT_NUM_MBSS)
# which is required when using headers from SDK 5.4.2:
#   bcmwl_nvram_lib.c:#include <wlcsm_lib_api.h>
#   libs/wlcsm/include/wl_common_defs.h:55:2: error: #error WL_DEFAULT_NUM_SSID is not defined!!!!!
# adding to UNIT_CFLAGS post UNIT_EXPORT_CFLAGS because it is only needed
# by this unit, not by any other unit that depends on this
UNIT_CFLAGS += $(CMN_WLAN_FLAGS)

UNIT_DEPS := src/lib/ds
UNIT_DEPS += src/lib/schema
UNIT_DEPS += src/lib/common
UNIT_DEPS += src/lib/evx
UNIT_DEPS += src/lib/kconfig
UNIT_DEPS += src/lib/log
UNIT_DEPS += $(if $(CONFIG_BCM_USE_HOSTAP),src/lib/hostap,)

UNIT_DEPS_CFLAGS += src/lib/target

include platform/bcm/build/bcm-sdk-wifi.mk
