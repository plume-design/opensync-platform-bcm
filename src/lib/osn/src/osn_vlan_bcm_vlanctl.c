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

#include <unistd.h>

#include "const.h"
#include "execsh.h"
#include "log.h"
#include "osn_vlan.h"
#include "util.h"

#include "linux/lnx_vlan.h"

#define BCM_VLAN_VC_PATH    "/sys/class/net/%s.vc"

struct osn_vlan
{
    bool        ov_is_bcm_vlan;
    bool        ov_is_lnx_vlan;
    char        ov_ifname[C_IFNAME_LEN];
    char        ov_ifparent[C_IFNAME_LEN];
    char        ov_egress_qos_map[C_QOS_MAP_LEN];
    int         ov_vid;
    lnx_vlan_t  ov_lnx_vlan;
};

static bool osn_vlan_fini(osn_vlan_t *self);
static bool osn_vlan_lnx_apply(osn_vlan_t *self);
static bool osn_vlan_bcm_has_vlanctl(const char *ifname);
static bool osn_vlan_bcm_apply(osn_vlan_t *self);
static bool osn_vlan_bcm_fini(osn_vlan_t *self);

/*
 * ===========================================================================
 *  Public API implementation
 * ===========================================================================
 */

osn_vlan_t *osn_vlan_new(const char *ifname)
{
    osn_vlan_t *self = calloc(1, sizeof(osn_vlan_t));
    if (self == NULL)
    {
        LOG(ERR, "osn_vlan_bcm: %s: Error allocating the VLAN object.", ifname);
        return NULL;
    }

    if (STRSCPY(self->ov_ifname, ifname) < 0)
    {
        LOG(ERR, "osn_vlan_bcm: %s: Interface name too long.", ifname);
        free(self);
        return NULL;
    }

    self->ov_vid = -1;

    return self;
}

bool osn_vlan_del(osn_vlan_t *self)
{
    bool retval = true;

    retval = osn_vlan_fini(self);
    if (!retval)
    {
        LOG(WARN, "osn_vlan_bcm: %s: Error finalizing VLAN object.", self->ov_ifname);
    }

    free(self);

    return retval;
}

bool osn_vlan_parent_set(osn_vlan_t *self, const char *parent_ifname)
{
    if (STRSCPY(self->ov_ifparent, parent_ifname) < 0)
    {
        LOG(ERR, "osn_vlan_bcm: %s: Parent interface name too long: %s.",
                self->ov_ifname, parent_ifname);
        self->ov_ifname[0] = '\0';
        return false;
    }

    return true;
}

bool osn_vlan_vid_set(osn_vlan_t *self, int vlanid)
{
    self->ov_vid = vlanid;
    return true;
}

bool osn_vlan_egress_qos_map_set(osn_vlan_t *self, const char *qos_map)
{
    if (STRSCPY(self->ov_egress_qos_map, qos_map) < 0)
    {
        LOG(ERR, "osn_vlan_bcm: %s: Egress qos_map too long: %s",
                self->ov_ifname, qos_map);

        self->ov_egress_qos_map[0] = '\0';
        return false;
    }

    return true;
}

bool osn_vlan_apply(osn_vlan_t *self)
{
    osn_vlan_fini(self);

    if (osn_vlan_bcm_has_vlanctl(self->ov_ifparent))
    {
        return osn_vlan_bcm_apply(self);
    }
    else
    {
        return osn_vlan_lnx_apply(self);
    }

    return false;
}

/*
 * ===========================================================================
 *  Helpers
 * ===========================================================================
 */
bool osn_vlan_fini(osn_vlan_t *self)
{
    if (self->ov_is_lnx_vlan)
    {
        return lnx_vlan_fini(&self->ov_lnx_vlan);
    }

    if (self->ov_is_bcm_vlan)
    {
        return osn_vlan_bcm_fini(self);
    }

    return true;
}


/*
 * ===========================================================================
 *  Linux VLAN wrappers
 * ===========================================================================
 */
bool osn_vlan_lnx_apply(osn_vlan_t *self)
{
    if (!lnx_vlan_init(&self->ov_lnx_vlan, self->ov_ifname))
    {
        LOG(ERR, "osn_vlan_bcm: %s: Error initializing the VLAN object.",
                self->ov_ifname);
        return false;
    }

    self->ov_is_lnx_vlan = true;

    if (!lnx_vlan_parent_ifname_set(&self->ov_lnx_vlan, self->ov_ifparent))
    {
        LOG(ERR, "osn_vlan_bcm: %s: Error setting LNX VLAN parent ifname: %s.",
                self->ov_ifname, self->ov_ifparent);
        return false;
    }

    if (!lnx_vlan_vid_set(&self->ov_lnx_vlan, self->ov_vid))
    {
        LOG(ERR, "osn_vlan_bcm: %s: Error setting LNX VLAN ID: %d.",
                self->ov_ifname, self->ov_vid);
        return false;
    }

    if (self->ov_egress_qos_map[0] != '\0' &&
            !lnx_vlan_egress_qos_map_set(&self->ov_lnx_vlan, self->ov_egress_qos_map))
    {
        LOG(ERR, "osn_vlan_bcm: %s: Error setting LNX egress QoS map: %s",
                self->ov_ifname, self->ov_egress_qos_map);
        return false;
    }

    if (!lnx_vlan_apply(&self->ov_lnx_vlan))
    {
        LOG(ERR, "osn_vlan_bcm: %s: Error applying LNX VLAN configuration.",
                self->ov_ifname);
        return false;
    }

    return true;
}

/*
 * ===========================================================================
 *  BCM VLANCTL implementation
 * ===========================================================================
 */

/*
 * Check if interface @p ifname has a corresponding `vlanctl` interface.
 * `vlanctl` interfaces are created during boot and have a `.vc` extension.
 */
bool osn_vlan_bcm_has_vlanctl(const char *ifname)
{
    char ifvc[C_IFNAME_LEN];

    snprintf(ifvc, sizeof(ifvc), BCM_VLAN_VC_PATH, ifname);
    if (access(ifvc, F_OK) != 0)
    {
        return false;
    }

    return true;
}

bool osn_vlan_bcm_apply(osn_vlan_t *self)
{
    char svlan[C_INT32_LEN];

    /*
     * Some sanity checks
     */
    if (self->ov_ifparent[0] == '\0')
    {
        LOG(ERR, "osn_vlan_bcm: %s: Parent interface name not set.",
                self->ov_ifname);
        return false;
    }

    if (self->ov_vid < 0 || self->ov_vid > 4094)
    {
        LOG(ERR, "osn_vlan_bcm: %s: VLAN ID out of range: %d",
                self->ov_ifname, self->ov_vid);
        return false;
    }

    snprintf(svlan, sizeof(svlan), "%d", self->ov_vid);

    /*
     * Script for adding a VLAN interface via `vlanctl`:
     *
     * $1 - VLAN interface name
     * $2 - VLAN ID
     * $3 - Parent interface name
     */
    static char vlanctl_add_cmd[] = _S(
            vlanctl --mcast --if-create-name "$3.vc" "$1";
            vlanctl --if "$3.vc" --rx --tags 1 --filter-vid $2 0 --pop-tag --set-rxif "$1" --rule-append;
            vlanctl --if "$3.vc" --tx --tags 0 --filter-txif "$1" --push-tag --set-vid $2 0 --rule-append;
            vlanctl --if "$3.vc" --set-if-mode-rg);

    if (execsh_log(LOG_SEVERITY_DEBUG, vlanctl_add_cmd, self->ov_ifname, svlan, self->ov_ifparent) != 0)
    {
        LOG(ERR, "osn_vlan_bcm: %s: Error creating VLAN interface. `vlanctl` failed.",
                self->ov_ifname);
        return false;
    }

    self->ov_is_bcm_vlan = true;

    return true;
}

bool osn_vlan_bcm_fini(osn_vlan_t *self)
{
    self->ov_is_bcm_vlan = false;

    /*
     * Script for deleting a VLAN interface via `vlanctl`:
     *
     * $1 - VLAN interface name
     */
    static char vlanctl_del_cmd[] = _S(
            vlanctl --if-delete "$1");

    if (execsh_log(LOG_SEVERITY_DEBUG, vlanctl_del_cmd, self->ov_ifname) != 0)
    {
        LOG(ERR, "osn_vlan_bcm: %s: Error deleting VLAN interface. `vlanctl` failed.",
                self->ov_ifname);
        return false;
    }

    return true;
}
