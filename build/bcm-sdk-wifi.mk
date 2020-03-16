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


ifeq ($(CONFIG_BCM_WIFI_DRIVER_PATH),y)

UNIT_CFLAGS  += -I$(SDK_DIR)/$(CONFIG_BCM_WIFI_IMPL_PATH)/impl$(CONFIG_BCM_IMP_DRIVER_VERSION)/main/src/include
UNIT_CFLAGS  += -I$(SDK_DIR)/$(CONFIG_BCM_WIFI_IMPL_PATH)/impl$(CONFIG_BCM_IMP_DRIVER_VERSION)/main/src/shared/bcmwifi/include

ifeq ($(shell test $(CONFIG_BCM_IMP_DRIVER_VERSION) -ge 53 && echo 1),1)
DEFINES += -DUSE_ALTERNATE_BCM_DRIVER_PATHS
UNIT_CFLAGS  += -I$(SDK_DIR)/$(CONFIG_BCM_WIFI_IMPL_PATH)/impl$(CONFIG_BCM_IMP_DRIVER_VERSION)/main/components/wlioctl/include
UNIT_CFLAGS  += -I$(SDK_DIR)/$(CONFIG_BCM_WIFI_IMPL_PATH)/impl$(CONFIG_BCM_IMP_DRIVER_VERSION)/main/components/proto/include
else
UNIT_CFLAGS  += -I$(SDK_DIR)/$(CONFIG_BCM_WIFI_IMPL_PATH)/impl$(CONFIG_BCM_IMP_DRIVER_VERSION)/main/src/common/include
endif

endif
