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

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>

#include "log.h"
#include "util.h"
#include "evx_debounce_call.h"
#include "bcmwl.h"
#include "bcmwl_nvram.h"
#include "bcmwl_debounce.h"
#include "bcmwl_acl.h"

/**
 * Private
 */

#define BCMWL_ACL_LOCK_PATH "/tmp/.bcmwl.acl.lock"

static int bcmwl_acl_lock_fd = -1;


/**
 * Public
 */

static bool bcmwl_acl_sync(
        const char *ifname,
        enum bcmwl_acl_policy policy,
        const char *acl)
{
    char *i, *o, *n;

    LOGD("%s: acl: syncing", ifname);

    if ((int)policy != atoi(WL(ifname, "macmode") ?: "0")) {
        LOGI("%s: acl: policy: %d", ifname, policy);
        if (WARN_ON(!WL(ifname, "macmode", strfmta("%d", policy))))
            return false;
    }

    o = WL(ifname, "mac") ?: strdupa("");
    n = strdupa(acl);

    while ((i = strsep(&n, " ")))
        if (!strcasestr(o, i)) {
            LOGI("%s: acl: %s: adding", ifname, i);
            if (WARN_ON(!WL(ifname, "mac", i)))
                return false;
        }

    bcmwl_for_each_mac(i, o)
        if (!strcasestr(acl, i)) {
            LOGI("%s: acl: %s: removing", ifname, i);
            if (WARN_ON(!WL(ifname, "mac", "del", i)))
                return false;
        }

    return true;
}

static bool bcmwl_acl_enforce(const char *ifname)
{
    /*
     * Kick connected devices ONLY when WM explicitly blocks (ACL "deny" mode)
     * or don't allow (ACL "allow" mode) to connect.
     */
    enum bcmwl_acl_policy policy = atoi(BCMWL_ACL_POLICY_GET(ifname, BCMWL_ACL_WM) ?: "");
    const char *acl = BCMWL_ACL_GET(ifname, BCMWL_ACL_WM) ?: "";
    char *assoc;
    char *mac;

    LOGD("%s: acl: enforcing", ifname);

    if (WARN_ON(!(assoc = WL(ifname, "assoclist"))))
        return false;

    switch (policy) {
        case BCMWL_ACL_NONE:
            return true;
        case BCMWL_ACL_DENY:
        case BCMWL_ACL_ALLOW:
            bcmwl_for_each_mac(mac, assoc) {
                if ((policy == BCMWL_ACL_ALLOW && !strcasestr(acl, mac)) ||
                    (policy == BCMWL_ACL_DENY && strcasestr(acl, mac)))
                {
                    LOGI("%s: acl: %s: kicking", ifname, mac);
                    WARN_ON(!WL(ifname, "deauthenticate", mac));
                }
                else
                {
                    LOGI("%s: acl: %s: do not kick", ifname, mac);
                }
            }
            return true;
    }

    return false;
}

static char* bcmwl_acl_merge(const char *ifname, enum bcmwl_acl_policy *policy)
{
    enum bcmwl_acl_policy policy1;
    enum bcmwl_acl_policy policy2;
    enum bcmwl_acl_policy policy_want;
    const char *mac;
    char *acl1, *acl2;
    char *acl_allow, *acl_deny;
    char *acl_want = strdupa("");
    bool merge = false;

    policy1 = atoi(NVG(ifname, strfmta("acl_policy_%s", BCMWL_ACL_WM)) ?: "0");
    policy2 = atoi(NVG(ifname, strfmta("acl_policy_%s", BCMWL_ACL_BM)) ?: "0");
    acl1 = NVG(ifname, strfmta("acl_%s", BCMWL_ACL_WM)) ?: strdupa("");
    acl2 = NVG(ifname, strfmta("acl_%s", BCMWL_ACL_BM)) ?: strdupa("");

    if (policy1 == policy2)
        policy_want = policy1;
    else if (policy1 == BCMWL_ACL_NONE || policy2 == BCMWL_ACL_NONE)
        policy_want = policy1 == BCMWL_ACL_NONE ? policy2 : policy1;
    else {
        merge = true;
        policy_want = BCMWL_ACL_ALLOW;
    }

    if (policy1 == BCMWL_ACL_NONE)
        acl1 = strdupa("");
    if (policy2 == BCMWL_ACL_NONE)
        acl2 = strdupa("");

    LOGD("%s: acl: '%s' + '%s' [merge? %d]=", ifname, acl1, acl2, merge);
    if (merge) {
        acl_allow = policy1 == BCMWL_ACL_ALLOW ? acl1 : acl2;
        acl_deny = policy2 == BCMWL_ACL_DENY ? acl2 : acl1;

        while ((mac = strsep(&acl_allow, " \r\n")))
            acl_want = strfmta("%s %s", acl_want, mac);
        while ((mac = strsep(&acl_deny, " \r\n")))
            strdel(acl_want, mac, strcasecmp);
    } else {
        while ((mac = strsep(&acl1, " \r\n")))
            acl_want = strfmta("%s %s", acl_want, mac);
        while ((mac = strsep(&acl2, " \r\n")))
            acl_want = strfmta("%s %s", acl_want, mac);
    }
    strchomp(acl_want, " ");

    *policy = policy_want;
    return strdup(acl_want);
}

static bool bcmwl_acl_cmp(
        const char *ifname,
        enum bcmwl_acl_policy policy,
        const char *acl)
{
    char *mac, *macs, *p;
    if (WARN_ON(!(p = WL(ifname, "macmode"))))
        return false;
    if (atoi(p) != (int)policy)
        return false;
    if (WARN_ON(!(macs = WL(ifname, "mac"))))
        return false;
    p = strdupa(macs);
    bcmwl_for_each_mac(mac, p)
        if (!strcasestr(acl, mac))
            return false;
    for (p = strdupa(acl); (mac = strsep(&p, " ")); )
        if (!strcasestr(macs, mac))
            return false;
    return true;
}

bool bcmwl_acl_is_synced(const char *ifname)
{
    enum bcmwl_acl_policy policy;
    const char *str;
    char *acl;

    str = WL(ifname, "probresp_sw");
    if (str && atoi(str) != 1)
        return false;
    str = WL(ifname, "authresp_mac_filter");
    if (str && atoi(str) != 1)
        return false;
    str = WL(ifname, "probresp_mac_filter");
    if (WARN_ON(!str))
        return false;
    if (atoi(str) != 1)
        return false;
    if (WARN_ON(!(acl = bcmwl_acl_merge(ifname, &policy))))
        return false;
    return bcmwl_acl_cmp(ifname, policy, acl);
}

bool bcmwl_acl_commit(const char *ifname)
{
    enum bcmwl_acl_policy policy;
    char *acl;
    bool ok = false;

    if (WARN_ON(flock(bcmwl_acl_lock_fd, LOCK_EX) < 0))
        return false;
    WL(ifname, "authresp_mac_filter", "1");
    if (WARN_ON(!WL(ifname, "probresp_mac_filter", "1")))
        goto out;
    if (atoi(WL(ifname, "probresp_sw") ?: "0") != 1 &&
        WARN_ON(!WL(ifname, "probresp_sw", "1")))
        goto out;
    if (WARN_ON(!(acl = bcmwl_acl_merge(ifname, &policy))))
        goto out;
    ok = true;
    if (bcmwl_acl_cmp(ifname, policy, acl))
        goto out;
    if (WARN_ON(!bcmwl_acl_sync(ifname, policy, acl)))
        ok = false;
    if (WARN_ON(!bcmwl_acl_enforce(ifname)))
        ok = false;
    evx_debounce_call(bcmwl_vap_state_report, ifname);
out:
    WARN_ON(flock(bcmwl_acl_lock_fd, LOCK_UN) < 0);
    return ok;
}

bool bcmwl_acl_init(void)
{
    if (WARN_ON(bcmwl_acl_lock_fd != -1))
        return false;
    if (WARN_ON((bcmwl_acl_lock_fd = open(BCMWL_ACL_LOCK_PATH, O_TRUNC | O_CREAT | O_CLOEXEC)) < 0))
        return false;
    return true;
}
