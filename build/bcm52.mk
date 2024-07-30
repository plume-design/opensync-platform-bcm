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

# parse driver impl version
ifeq ($(DRIVER_VERSION),)
ifneq ($(BCM_WLIMPL),)
DRIVER_VERSION                  := impl$(BCM_WLIMPL)
else ifneq ($(PROFILE_PATH),)
DRIVER_VERSION                  := impl$(shell grep BCM_WLIMPL= $(PROFILE_PATH) | cut -d= -f2 | tail -1)
else ifneq ($(PROFILE_DIR),)
DRIVER_VERSION                  := impl$(shell grep BCM_WLIMPL= $(PROFILE_DIR)/$(shell basename $(PROFILE_DIR)) | cut -d= -f2 | tail -1)
else
DRIVER_VERSION                  := impl0
endif
endif

# SDK version
-include $(BRCMDRIVERS_DIR)/../version.make
DEFINES += -DBRCM_VERSION=$(BRCM_VERSION)
DEFINES += -DBRCM_RELEASE=$(BRCM_RELEASE)
DEFINES += -DBRCM_EXTRAVERSION=$(BRCM_EXTRAVERSION)
DEFINES += -DBCM_SDK_VERSION=$(shell expr $(BRCM_VERSION) \* 65536 + $(BRCM_RELEASE) \* 256 + $(shell echo $(BRCM_EXTRAVERSION) | sed 's/^\([[:digit:]]*\).*/\1/') 2>/dev/null)
DEFINES += -DBCM_WLIMPL=$(BCM_WLIMPL)

# This is example of include paths for different wl
# implementations for wlioctl_defs.h:
#
# bcmdrivers/broadcom/net/wl/impl29/main/src/common/include/devctrl_if/wlioctl_defs.h
# bcmdrivers/broadcom/net/wl/impl32/main/src/common/include/devctrl_if/wlioctl_defs.h
# bcmdrivers/broadcom/net/wl/impl53/main/components/wlioctl/include/wlioctl_defs.h
# bcmdrivers/broadcom/net/wl/impl61/main/components/wlioctl/include/wlioctl_defs.h
#
# DRIVER_VERSION contains implXX, so strip away non-numeric
# characters and compare against the threshold version.
OVS_PACKAGE_VER := $(shell sed -n '/^APP/{s/^.*-//p;q}' $(USERSPACE_DIR)/public/apps/openvswitch/Makefile)
SDK_OPENVSWITCH_PATH := $(USERSPACE_DIR)/public/apps/openvswitch/openvswitch-$(OVS_PACKAGE_VER)
SDK_NEW_INC_PATHS_SINCE = 53
SDK_DRV_VER = $(if $(strip $(DRIVER_VERSION_REAL)),$(DRIVER_VERSION_REAL),$(DRIVER_VERSION))
SDK_NEW_INC_PATHS = $(shell test $(shell echo $(SDK_DRV_VER) | tr -dc 0-9) -ge $(SDK_NEW_INC_PATHS_SINCE) && echo y || echo n)

SDK_INCLUDES += -I$(BCM_FSBUILD_DIR)/public/include
SDK_INCLUDES += -I$(BCM_FSBUILD_DIR)/gpl/include
SDK_INCLUDES += -I$(BCM_FSBUILD_DIR)/public/include/protobuf-c
SDK_INCLUDES += -I$(BCM_FSBUILD_DIR)/public/include/libev
SDK_INCLUDES += -I$(BRCMDRIVERS_DIR)/broadcom/net/wl/$(DRIVER_VERSION)/main/src/include/
ifeq ($(SDK_NEW_INC_PATHS),y)
# Add core/src/lib/common/inc first for duplicate naming of monitor.h
SDK_INCLUDES += -I$(shell pwd)/src/lib/common/inc
SDK_INCLUDES += -I$(BRCMDRIVERS_DIR)/broadcom/net/wl/$(DRIVER_VERSION)/main/components/wlioctl/include
SDK_INCLUDES += -I$(BRCMDRIVERS_DIR)/broadcom/net/wl/$(DRIVER_VERSION)/main/components/proto/include
else
SDK_INCLUDES += -I$(BRCMDRIVERS_DIR)/broadcom/net/wl/$(DRIVER_VERSION)/main/src/common/include
endif
SDK_INCLUDES += -I$(BRCMDRIVERS_DIR)/broadcom/net/wl/$(DRIVER_VERSION)/main/src/shared/bcmwifi/include

SDK_INCLUDES += -I$(BCM_FSBUILD_DIR)/kernel/$(PROFILE_ARCH)/include/
SDK_INCLUDES += -I$(BCM_FSBUILD_DIR)/kernel/include/

INCLUDES     += $(SDK_INCLUDES)

HOSTAP_HEADERS := -I$(BRCMDRIVERS_DIR)/broadcom/net/wl/$(DRIVER_VERSION)/main/components/opensource/router_tools/hostapd/src/common

# libnl3 (netlink lib) available only together with hostap
ifeq ($(CONFIG_BCM_USE_HOSTAP),y)
ifneq ($(wildcard $(BCM_FSBUILD_DIR)/public/include/libnl3/netlink/netlink.h),)
LIBNL3_HEADERS = -I$(BCM_FSBUILD_DIR)/public/include/libnl3
else
LIBNL3_HEADERS = -I$(BRCMDRIVERS_DIR)/broadcom/net/wl/$(DRIVER_VERSION)/main/components/opensource/router_tools/libnl/install/include/libnl3
endif
export LIBNL3_HEADERS
endif

ifeq ($(SDK_NEW_INC_PATHS),y)
DEFINES += -DUSE_ALTERNATE_BCM_DRIVER_PATHS
endif
DEFINES      += -Wno-strict-aliasing
DEFINES      += -Wno-unused-but-set-variable
DEFINES      += -Wno-deprecated-declarations
DEFINES      += -Wno-clobbered
# Do not treat #warning as errors
DEFINES      += -Wno-error=cpp
#DEFINES      += -Os
OS_LDFLAGS   += -Wl,-rpath-link=$(BCM_FSBUILD_DIR)/lib
OS_LDFLAGS   += -Wl,-rpath-link=$(BCM_FSBUILD_DIR)/public/lib
OS_LDFLAGS   += -Wl,-rpath-link=$(BCM_FSBUILD_DIR)/gpl/lib
OS_LDFLAGS   += -L$(BCM_FSBUILD_DIR)/lib
OS_LDFLAGS   += -L$(BCM_FSBUILD_DIR)/public/lib
OS_LDFLAGS   += -L$(BCM_FSBUILD_DIR)/gpl/lib
OS_LDFLAGS   += -L$(INSTALL_DIR)/usr/lib
OS_LDFLAGS   += -L$(INSTALL_DIR)/lib/gpl
SDK_ROOTFS   := $(INSTALL_DIR)
SDK_DIR       = $(BCM_BUILD_ROOT)

SDK_MKSQUASHFS_CMD = $(HOSTTOOLS_DIR)/mksquashfs
SDK_MKSQUASHFS_ARGS = -noappend -all-root -comp xz

ifeq ($(V),1)
$(info --- BCM ENV ---)
$(info PROFILE=$(PROFILE))
$(info BRCM_BOARD_ID=$(BRCM_BOARD_ID))
$(info BRCM_BOARD=$(BRCM_BOARD))
$(info BCM_FSBUILD_DIR=$(BCM_FSBUILD_DIR))
$(info INSTALL_DIR=$(INSTALL_DIR))
$(info TARGET_FS=$(TARGET_FS))
$(info HOSTTOOLS_DIR=$(HOSTTOOLS_DIR))
$(info --- OpenSync ENV ---)
$(info PLATFORM=$(PLATFORM))
$(info TARGET=$(TARGET))
$(info INCLUDES=$(INCLUDES))
$(info DEFINES=$(DEFINES))
$(info SDK_ROOTFS=$(SDK_ROOTFS))
$(info DRIVER_VERSION=$(DRIVER_VERSION))
$(info BRCMDRIVERS_DIR=$(BRCMDRIVERS_DIR))
$(info KERNEL_ARCH=$(KERNEL_ARCH))
$(info PROFILE_ARCH=$(PROFILE_ARCH))
$(info SDK_DIR=$(SDK_DIR))
$(info -----------------)
endif

