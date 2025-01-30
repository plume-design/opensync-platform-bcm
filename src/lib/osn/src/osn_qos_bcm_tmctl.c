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

#include <stdint.h>
#include <stdlib.h>

#include "bcm_skb_defines.h"
#include "tmctl_api.h"

#include "const.h"
#include "log.h"
#include "memutil.h"
#include "osn_qos.h"

#define BCM_QOS_RATE_DEFAULT 1000000 /**< Default rate in kbit/s, used to reset queue speeds */
#define BCM_QOS_ID_BASE 0x44000000
#define BCM_QOS_ID_MASK 0x00ffffff

/*
 * There are 32 queues that need to be initialized, however the last queue (31)
 * is reserved for the default action and is not configurable
 */
#define BCM_QOS_INIT_QUEUES 32 /**< Number of queues to initialize */
#define BCM_QOS_MAX_QUEUES 31  /**< Maximum number of queues available */

struct osn_qos
{
    int *q_id;   /* Array of IDs used by this object */
    int *q_id_e; /* End of array */
};

struct bcm_qos_queue
{
    int qq_min_rate; /**< Queue min rate in kbit/s */
    int qq_max_rate; /**< Queue max rate in kbit/s */
    char *qq_tag;    /**< Queue tag */
    int qq_refcnt;   /**< Queue reference count, 0 if unused */
};

static struct bcm_qos_queue bcm_qos_queue_list[BCM_QOS_MAX_QUEUES];

static bool bcm_qos_global_init(void);
static bool bcm_qos_queue_reset(int queue_id);
static bool bcm_qos_queue_set(int queue_id, int min_rate, int max_rate);
static int bcm_qos_id_get(const char *tag);
static void bcm_qos_id_put(int id);

/*
 * ===========================================================================
 *  OSN API implementation
 * ===========================================================================
 */
osn_qos_t *osn_qos_new(const char *ifname)
{
    osn_qos_t *self;

    /*
     * BCM queues do not have a notion of network interfaces, so we can ignore
     * the name
     */
    (void)ifname;

    static bool global_init = false;

    if (!global_init)
    {
        if (!bcm_qos_global_init())
        {
            return NULL;
        }

        global_init = true;
    }

    self = CALLOC(1, sizeof(*self));
    return self;
}

void osn_qos_del(osn_qos_t *self)
{
    int *qp;

    for (qp = self->q_id; qp < self->q_id_e; qp++)
    {
        bcm_qos_id_put(*qp);
    }

    FREE(self->q_id);
}

bool osn_qos_apply(osn_qos_t *self)
{
    int *qp;

    bool retval = true;

    /*
     * Apply QoS configuration to system
     */
    for (qp = self->q_id; qp < self->q_id_e; qp++)
    {
        int qid = *qp;
        if (qid < 0 || qid >= BCM_QOS_MAX_QUEUES)
        {
            LOGE("%s: invalid queue id %d", __func__, qid);
            return false;
        }
        if (!bcm_qos_queue_set(qid, bcm_qos_queue_list[qid].qq_min_rate, bcm_qos_queue_list[qid].qq_max_rate))
        {
            /* bcm_qos_queue_set() reported the error already */
            retval = false;
        }
    }

    return retval;
}

bool osn_qos_begin(osn_qos_t *self, struct osn_qos_other_config *other_config)
{
    (void)self;
    (void)other_config;

    return true;
}

bool osn_qos_end(osn_qos_t *self)
{
    (void)self;

    return true;
}

bool osn_qos_queue_begin(
        osn_qos_t *self,
        int priority,
        int bandwidth,
        int bandwidth_ceil,
        const char *tag,
        const struct osn_qos_other_config *other_config,
        struct osn_qos_queue_status *qqs)
{
    (void)priority;
    (void)other_config;

    int qid;
    int *qp;

    memset(qqs, 0, sizeof(*qqs));

    qid = bcm_qos_id_get(tag);
    if (qid < 0)
    {
        LOG(ERR, "bcm_qos: All queues are full.");
        return false;
    }

    /* Append the queue id to the list for this object */
    qp = MEM_APPEND(&self->q_id, &self->q_id_e, sizeof(*qp));
    *qp = qid;

    if (bandwidth_ceil > 0)
    {
        bcm_qos_queue_list[qid].qq_max_rate = bandwidth_ceil;
        bcm_qos_queue_list[qid].qq_min_rate = bandwidth;
    }
    else
    {
        bcm_qos_queue_list[qid].qq_max_rate = bandwidth;
        bcm_qos_queue_list[qid].qq_min_rate = 0;
    }

    /* Calculate the MARK for this DPI */
    qqs->qqs_fwmark = SKBMARK_SET_DPIQ_MARK(0, qid);
    qqs->qqs_fwmark = SKBMARK_SET_SQ_MARK(qqs->qqs_fwmark, 1);

    return true;
}

bool osn_qos_queue_end(osn_qos_t *self)
{
    (void)self;
    return true;
}

/*
 * ===========================================================================
 *  BCM backend
 * ===========================================================================
 */

/*
 *  Initialize the TMCTL SVCQ subsystem
 */
bool bcm_qos_global_init(void)
{
    tmctl_ret_e rc;

    /*
     * Enable TMCTL service queue
     */

    rc = tmctl_portTmInit(TMCTL_DEV_SVCQ, NULL, TMCTL_INIT_DEFAULT_QUEUES | TMCTL_SCHED_TYPE_WRR, BCM_QOS_INIT_QUEUES);
    if (rc != TMCTL_SUCCESS)
    {
        LOGE("bcm_qos: error initializing TMCTL SVCQ %d", rc);
        return false;
    }

    LOG(NOTICE, "bcm_qos: TMCTL service queues initialized");

    return true;
}

bool bcm_qos_queue_set(int queue_id, int min_rate, int max_rate)
{
    tmctl_ret_e rc;
    tmctl_shaper_t tm_shaper = {0};

    LOG(INFO, "bcm_qos: queue[%d]: Applying settings min_rate=%d, max_rate=%d", queue_id, min_rate, max_rate);

    tm_shaper.shapingRate = max_rate;
    tm_shaper.minRate = min_rate;

    rc = tmctl_setQueueShaper(TMCTL_DEV_SVCQ, NULL, queue_id, &tm_shaper);
    if (rc != TMCTL_SUCCESS)
    {
        LOG(ERR, "bcm_qos: queue[%d]: Error %d setting rate %d %d", queue_id, rc, min_rate, max_rate);
        return false;
    }

    return true;
}

bool bcm_qos_queue_reset(int queue_id)
{
    return bcm_qos_queue_set(queue_id, 0, BCM_QOS_RATE_DEFAULT);
}

int bcm_qos_id_get(const char *tag)
{
    int qid;

    /* Check if there's a queue with a matching tag */
    if (tag != NULL)
    {
        for (qid = 0; qid < BCM_QOS_MAX_QUEUES; qid++)
        {
            if (bcm_qos_queue_list[qid].qq_tag != NULL && strcmp(bcm_qos_queue_list[qid].qq_tag, tag) == 0)
            {
                break;
            }
        }

        if (qid < BCM_QOS_MAX_QUEUES)
        {
            /* The tag was found return this index */
            bcm_qos_queue_list[qid].qq_refcnt++;
            return qid;
        }
    }

    /* Find first empty queue */
    for (qid = 0; qid < BCM_QOS_MAX_QUEUES; qid++)
    {
        if (bcm_qos_queue_list[qid].qq_refcnt == 0) break;
    }

    if (qid >= BCM_QOS_MAX_QUEUES)
    {
        return -1;
    }

    bcm_qos_queue_list[qid].qq_refcnt = 1;
    if (tag != NULL)
    {
        bcm_qos_queue_list[qid].qq_tag = strdup(tag);
    }

    return qid;
}

void bcm_qos_id_put(int qid)
{
    if (qid >= BCM_QOS_MAX_QUEUES) return;

    if (bcm_qos_queue_list[qid].qq_refcnt-- > 1)
    {
        return;
    }

    if (!bcm_qos_queue_reset(qid))
    {
        LOG(WARN, "bcm_qos: Unable to reset queue %d.", qid);
    }

    FREE(bcm_qos_queue_list[qid].qq_tag);
    bcm_qos_queue_list[qid].qq_tag = NULL;
}

bool osn_qos_notify_event_set(osn_qos_t *self, osn_qos_event_fn_t *event_fn_cb)
{
    (void)self;
    (void)event_fn_cb;

    /*
     * This implementation backend does not support QoS event reporting.
     * (There is no need for event reporting on this platform-specific implementation.)
     */
    return false;
}

bool osn_qos_is_qdisc_based(osn_qos_t *self)
{
    return false;
}
