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

#ifndef BCMWL_ACL_H_INCLUDED
#define BCMWL_ACL_H_INCLUDED

bool bcmwl_acl_is_synced(const char *ifname);
bool bcmwl_acl_commit(const char *ifname);
bool bcmwl_acl_init(void);

enum bcmwl_acl_policy {
    BCMWL_ACL_NONE = 0,
    BCMWL_ACL_DENY = 1,
    BCMWL_ACL_ALLOW = 2,
};

#define BCMWL_ACL_WM "wm"
#define BCMWL_ACL_BM "bm"
#define BCMWL_ACL_GET(ifname, entity) (NVG(ifname, strfmta("acl_%s", entity)))
#define BCMWL_ACL_SET(ifname, entity, acl) (NVS(ifname, strfmta("acl_%s", entity), acl))
#define BCMWL_ACL_ADD(ifname, entity, mac) (bcmwl_nvram_append(ifname, strfmta("acl_%s", entity), mac, strcasecmp) >= 0)
#define BCMWL_ACL_DEL(ifname, entity, mac) (bcmwl_nvram_remove(ifname, strfmta("acl_%s", entity), mac, strcasecmp) >= 0)
#define BCMWL_ACL_POLICY_SET(ifname, entity, policy) (NVS(ifname, strfmta("acl_policy_%s", entity), strfmta("%d", policy)))
#define BCMWL_ACL_POLICY_GET(ifname, entity) (NVG(ifname, strfmta("acl_policy_%s", entity)))

#endif /* BCMWL_ACL_H_INCLUDED */
