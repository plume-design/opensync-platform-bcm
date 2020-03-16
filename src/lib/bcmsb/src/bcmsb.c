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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>

/* Broadcom SDK include files */
#ifndef _LINUX_TYPES_H
#define _LINUX_TYPES_H
#endif

#include "otp_ioctl.h"
#include "bcm_sotp.h"
#include "47622_common.h"
/* */

#include "bcmsb.h"
#include "bcmsb_keys.h"


#define DEVNAME_SOTP        "/dev/sotp"
#define DEVNAME_OTP         "/dev/otp"

/*
 * Compare buffer against given bytes value
 */
static bool memcmp_b(const uint8_t *buff, uint8_t value, size_t sz)
{
    size_t i = 0;

    while (i < sz)
    {
        if (buff[i++] != value)
        {
            return false;
        }
    }

    return true;
}

static bool is_keys_empty(void)
{
    if ((memcmp_b((uint8_t *)&key_mid, 0, sizeof(key_mid)) == true) ||
        (memcmp_b((uint8_t *)key_kroe_fld, 0, sizeof(key_kroe_fld)) == true) ||
        (memcmp_b((uint8_t *)key_hmid_rot_fld_pub, 0, sizeof(key_hmid_rot_fld_pub)) == true))
    {
        fprintf(stderr, "Keys are empty\n");
        return true;
    }

    return false;
}


static int bcm_otp_ioctl(OTP_IOCTL_ENUM elem, unsigned long req, int addr, uint64_t *data)
{
    int fd;
    int rv;
    OTP_IOCTL_PARMS p;

    fd = open(DEVNAME_OTP, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "Could not open device: " DEVNAME_OTP "\n");
        return -1;
    }

    p.element = elem;
    p.result = 0;
    p.id = addr;
    p.value = *data;

    rv = ioctl(fd, req, &p);
    if (rv < 0) {
        fprintf(stderr, "Error running ioctl() on " DEVNAME_OTP "\n");
        close(fd);
        return -1;
    }

    if (req == OTP_IOCTL_GET)
        *data = p.value;

    close(fd);
    return p.result;
}


static int bcm_sotp_ioctl(SOTP_ELEMENT elem, unsigned long req, int addr, uint32_t *data, uint32_t data_len)
{
    int fd;
    int rv;
    SOTP_IOCTL_PARMS p;

    fd = open(DEVNAME_SOTP, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "Could not open device: " DEVNAME_SOTP "\n");
        return -1;
    }

    p.element = elem;
    p.result = 0;
    p.inout_data = data;
    p.data_len = data_len;
    p.raw_access = 0;

    switch (p.element) {
        case SOTP_ROW:
            p.row_addr = addr;
            break;

        case SOTP_REGION_FUSELOCK:
        case SOTP_REGION_READLOCK:
            p.region_num = addr;
            break;

        case SOTP_KEYSLOT:
        case SOTP_KEYSLOT_READLOCK:
            p.keyslot_section_num = addr;
            break;

        default:
            break;
    }

    rv = ioctl(fd, req, &p);
    if (rv < 0) {
        fprintf(stderr, "Error running ioctl() on " DEVNAME_SOTP "\n");
        close(fd);
        return -1;
    }

    return 0;
}



int bcmsb_set_mfg_mode(void)
{
    int rv;
    uint64_t data;

    if (is_keys_empty() == true) {
        return -1;
    }

    data = OTP_BRCM_BTRM_BOOT_ENABLE_MASK;
    rv = bcm_otp_ioctl(OTP_ROW, OTP_IOCTL_SET, OTP_BRCM_BTRM_BOOT_ENABLE_ROW, &data);
    if (rv != 0) {
        fprintf(stderr, "Could not burn BTRM boot enable\n");
        return -1;
    }

    data = 0;
    rv = bcm_otp_ioctl(OTP_BTRM_ENABLE_BIT, OTP_IOCTL_SET, 0, &data);
    if (rv != 0) {
        fprintf(stderr, "Could not burn Customer BTRM boot enable\n");
        return -1;
    }

    return 0;
}

int bcmsb_set_fld_mode(void)
{
    int rv;
    uint64_t data;

    if (is_keys_empty() == true) {
        return -1;
    }

    data = key_mid;

    rv = bcm_otp_ioctl(OTP_MID_BITS, OTP_IOCTL_SET, 0, &data);
    if (rv != 0) {
        fprintf(stderr, "Could not burn MID\n");
        return -1;
    }

    rv = bcm_sotp_ioctl(SOTP_KEYSLOT, SOTP_IOCTL_SET, 8, key_kroe_fld, sizeof(key_kroe_fld));
    if (rv != 0) {
        fprintf(stderr, "Could not burn Kroe-fld\n");
        return -1;
    }

    rv = bcm_sotp_ioctl(SOTP_KEYSLOT, SOTP_IOCTL_SET, 9, key_hmid_rot_fld_pub, sizeof(key_hmid_rot_fld_pub));
    if (rv != 0) {
        fprintf(stderr, "Could not burn Hmid+rot-fld-pub\n");
        return -1;
    }

    return 0;
}


enum bcmsb_mode bcmsb_get_mode(void)
{
    int rv;
    uint64_t bcmBtrmEn = 0;
    uint64_t cusBtrmEn = 0;
    uint64_t mid = 0;
    enum bcmsb_mode mode = BCMSB_UNKNOWN;

    rv = bcm_otp_ioctl(OTP_ROW, OTP_IOCTL_GET, OTP_BRCM_BTRM_BOOT_ENABLE_ROW, &bcmBtrmEn);
    rv |= bcm_otp_ioctl(OTP_BTRM_ENABLE_BIT, OTP_IOCTL_GET, 0, &cusBtrmEn);
    rv |= bcm_otp_ioctl(OTP_MID_BITS, OTP_IOCTL_GET, 0, &mid);

    if (rv != 0) {
        goto fail;
    }

    if ((bcmBtrmEn & OTP_BRCM_BTRM_BOOT_ENABLE_MASK) &&
        (cusBtrmEn & OTP_CUST_BTRM_BOOT_ENABLE_MASK))
    {
        mode = BCMSB_MFG;

        if (mid & OTP_CUST_MFG_MRKTID_MASK) {
            mode = BCMSB_FLD;
        }
    }
    else {
        mode = BCMSB_UNSEC;
    }

fail:
    return mode;

}


int bcmsb_lock_jtag(void)
{
    int rv;
    uint64_t tmp = 0;

    rv = bcm_otp_ioctl(OTP_JTAG_PERMLOCK, OTP_IOCTL_SET, 0, &tmp);
    if (rv != 0) {
        return -1;
    }

    return 0;
}

bool bcmsb_is_jtag_locked(void)
{
    int rv;
    uint32_t lock;
    uint64_t tmp = 0;

    rv = bcm_otp_ioctl(OTP_JTAG_PERMLOCK, OTP_IOCTL_GET, 0, &tmp);
    if (rv != 0) {
        return false;
    }
    lock = tmp;

    if (lock == 0) {
        return false;
    }

    return true;
}

const char *bcmsb_mode2str(enum bcmsb_mode mode)
{
    switch (mode) {
        case BCMSB_UNSEC:
            return "UNSECURE";
        case BCMSB_MFG:
            return "MFG";
        case BCMSB_FLD:
            return "FLD";
        case BCMSB_UNKNOWN:
        default:
            return "_UNKNOWN_";
    }

    return "_UNKNOWN_";
}
