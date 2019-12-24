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


SDK_INCLUDES += -I$(BCM_FSBUILD_DIR)/public/include
SDK_INCLUDES += -I$(BCM_FSBUILD_DIR)/public/include/protobuf-c

INCLUDES     +=   $(SDK_INCLUDES)
INCLUDES     += -I$(BCM_BUILD_ROOT)/bcmdrivers/broadcom/net/wl/$(DRIVER_VERSION)/main/src/common/include
INCLUDES     += -I$(BCM_BUILD_ROOT)/bcmdrivers/broadcom/net/wl/$(DRIVER_VERSION)/main/src/include
INCLUDES     += -I$(BCM_BUILD_ROOT)/bcmdrivers/broadcom/net/wl/$(DRIVER_VERSION)/main/src/shared/bcmwifi/include/

DEFINES      += -Wno-strict-aliasing
DEFINES      += -Wno-unused-but-set-variable
DEFINES      += -Wno-deprecated-declarations
DEFINES      += -Wno-clobbered

LDFLAGS      += -L$(BCM_FSBUILD_DIR)/lib
LDFLAGS      += -L$(BCM_FSBUILD_DIR)/public/lib
LDFLAGS      += -L$(TARGET_FS)/lib

SDK_ROOTFS   :=   $(INSTALL_DIR)


ifeq ($(V),1)
$(info --- BCM ENV ---)
$(info PROFILE=$(PROFILE))
$(info BRCM_BOARD_ID=$(BRCM_BOARD_ID))
$(info BRCM_BOARD=$(BRCM_BOARD))
$(info BCM_BUILD_ROOT=$(BCM_BUILD_ROOT))
$(info BCM_FSBUILD_DIR=$(BCM_FSBUILD_DIR))
$(info INSTALL_DIR=$(INSTALL_DIR))
$(info TARGET_FS=$(TARGET_FS))
$(info --- PLUME ENV ---)
$(info PLATFORM=$(PLATFORM))
$(info TARGET=$(TARGET))
$(info INCLUDES=$(INCLUDES))
$(info DEFINES=$(DEFINES))
$(info SDK_ROOTFS=$(SDK_ROOTFS))
$(info -----------------)
endif

