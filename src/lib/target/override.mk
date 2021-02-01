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

UNIT_CFLAGS := $(filter-out -DTARGET_H=%,$(UNIT_CFLAGS))
UNIT_CFLAGS += -DTARGET_H='"target_bcm.h"'
UNIT_CFLAGS += -I$(OVERRIDE_DIR)/inc


UNIT_DEPS   += $(LAYER_DIR)/src/lib/wl80211
UNIT_DEPS   += $(LAYER_DIR)/src/lib/bcmutil

UNIT_EXPORT_CFLAGS := $(UNIT_CFLAGS)

UNIT_SRC_TOP += $(if $(CONFIG_BCM_FORCE_FLOW_CACHE_FLUSH),$(OVERRIDE_DIR)/fc_util.c,)
UNIT_SRC_TOP += $(if $(CONFIG_BCM_REF_WIFI),$(OVERRIDE_DIR)/wifi.c,)
UNIT_SRC_TOP += $(if $(CONFIG_BCM_REF_WIFI),$(OVERRIDE_DIR)/bsal.c,)
UNIT_SRC_TOP += $(if $(CONFIG_BCM_REF_WIFI),$(OVERRIDE_DIR)/stats.c,)
UNIT_SRC_TOP += $(OVERRIDE_DIR)/target_mcpd.c

UNIT_SRC := $(TARGET_COMMON_SRC)
UNIT_SRC_PLATFORM := $(OVERRIDE_DIR)
UNIT_SRC_TARGET := $(UNIT_SRC_PLATFORM)/$(TARGET)
