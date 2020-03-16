/*
Copyright (c) 2017, Plume Design Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
   1. Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
   3. Neither the name of the Plume Design Inc. nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL Plume Design Inc. BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef BCMSB_H_INCLUDED
#define BCMSB_H_INCLUDED

#include "kconfig.h"

/**
 * @brief Broadcom secure boot modes
 */
enum bcmsb_mode
{
    BCMSB_UNKNOWN,
    BCMSB_UNSEC,
    BCMSB_MFG,
    BCMSB_FLD,
};

#ifdef CONFIG_BCM_SECURE_BOOT_LIB
/**
 * Burn fuses to put device into manufacturing secure mode
 *
 * @return 0 on success, -1 on error
 */
int bcmsb_set_mfg_mode(void);

/**
 * Burn fuses to put device into field secure mode.
 * Will fail if default keys have not been changed.
 *
 * @return 0 on success, -1 on error
 */
int bcmsb_set_fld_mode(void);

/**
 * Return the current secure boot mode
 *
 * @return current secure boot mode
 */
enum bcmsb_mode bcmsb_get_mode(void);

/**
 * Burn fuses to lock the JTAG access
 *
 * @return 0 on success, -1 on error
 */
int bcmsb_lock_jtag(void);

/**
 * Return status of JTAG lock
 *
 * @return true if JTAG access is locked
 */
bool bcmsb_is_jtag_locked(void);

/**
 * Returns null-terminated string of the given secure boot mode
 *
 */
const char *bcmsb_mode2str(enum bcmsb_mode mode);

#else

static inline int bcmsb_set_mfg_mode(void) { return -1; }
static inline int bcmsb_set_fld_mode(void) { return -1; }
static inline enum bcmsb_mode bcmsb_get_mode(void) { return 0; }
static inline int bcmsb_lock_jtag(void) { return 0; }
static inline bool bcmsb_is_jtag_locked(void) { return false; }
static inline const char *bcmsb_mode2str(enum bcmsb_mode mode) { return NULL; }

#endif /* CONFIG_BCM_SECURE_BOOT_LIB */

#endif /* BCMSB_H_INCLUDED */
