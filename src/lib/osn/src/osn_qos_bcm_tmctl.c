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

#include <net/if.h>
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
#define BCM_QOS_ETH_DEV_PREFIX "eth"

enum bcm_qos_queue_type
{
    BCM_QUEUE_SVCQ = 0,
    BCM_QUEUE_DEVQ
};

struct osn_qos
{
    int *q_id;      /* Array of IDs used by this object */
    int *q_id_e;    /* End of array */
    char *q_ifname; /* ifname associated with BCM_QUEUE_DEVQ */
};

struct bcm_qos_queue
{
    int qq_min_rate; /**< Queue min rate in kbit/s */
    int qq_max_rate; /**< Queue max rate in kbit/s */
    int qq_priority; /**< Queue priority - needed for BCM_QUEUE_DEVQ */
    int qq_weight;   /**< Queue weight - needed for BCM_QUEUE_DEVQ */
    char *qq_tag;    /**< Queue tag */
    int qq_refcnt;   /**< Queue reference count, 0 if unused */
};

struct bcm_qos_queue_entry
{
    struct bcm_qos_queue *queue;
    enum bcm_qos_queue_type type;
    int index;
};

/*
 * Downstream traffic RL is managed by svcQ (Service Queues)
 * There are 32 svcq that need to be initialized, however the last queue (31) is the default Q
 *
 */
#define BCM_QOS_SVCQ_COUNT 32
static struct bcm_qos_queue bcm_qos_svcq_list[BCM_QOS_SVCQ_COUNT];

/*
 * Upstream traffic RL is managed by devQ (Device/Port Queues)
 * Each Ethernet port is assigned an egress_tm, and each tm can support 32 queues,
 * meaning each Ethernet port could theoretically support 32 queues.
 *
 * #define BCM_QOS_DEVQ_COUNT 32
 *
 * Limitation posted on BRCM ticket: CS00012408418 on 20250814:
 * In the current software, we have only reserved 3 bits for the Ethernet queue ID,
 * which limits it to supporting 8 queues.
 */
#define BCM_QOS_DEVQ_COUNT 8

static struct bcm_qos_queue bcm_qos_devq_list[BCM_QOS_DEVQ_COUNT];

/*
 * First Queue index - start at 1 (because for dev/portQ Q==0 is default Q while for svcQ default is Q 32)
 */
#define BCM_QOS_START_QUEUE 1

// Helpers
static int bcm_qos_get_queue_type(const char *ifname);
static int bcm_qos_get_queue_length(const char *ifname);
static struct bcm_qos_queue *bcm_qos_get_queue(const char *ifname);
static bool bcm_qos_find_queue(const char *ifname, const char *tag, struct bcm_qos_queue_entry *qe);
static bool bcm_qos_new_queue(const char *ifname, const char *tag, struct bcm_qos_queue_entry *qe);

// BRCM implementation
static bool bcm_qos_init(const char *ifname);
static bool bcm_qos_queue_reset(const char *ifname, int queue_id);
static bool bcm_qos_queue_set(const char *ifname, int queue_id, int min_rate, int max_rate);
static int bcm_qos_id_get(const char *ifname, const char *tag);
static void bcm_qos_id_put(const char *ifname, int id);

/*
 * ===========================================================================
 *  OSN API implementation
 * ===========================================================================
 */
osn_qos_t *osn_qos_new(const char *ifname)
{
    osn_qos_t *self;

    LOG(NOTICE, "bcm_qos_new: %s\n", ifname);

    if (!bcm_qos_init(ifname))
    {
        return NULL;
    }

    self = CALLOC(1, sizeof(*self));
    if (self == NULL)
    {
        return NULL;
    }

    self->q_ifname = (ifname != NULL) ? strdup(ifname) : NULL;

    return self;
}

void osn_qos_del(osn_qos_t *self)
{
    int *qp;

    /*
     * SvcQ:
     * are portless and since there is no specific Q provided for svcQ -> release them all
     *
     * DevQ/PortQ:
     * release specific devQ/portQ associated with this port - should only be one per dev, but check anyway
     */
    for (qp = self->q_id; qp < self->q_id_e; qp++)
    {
        bcm_qos_id_put(self->q_ifname, *qp);
    }

    if (self->q_ifname)
    {
        FREE(self->q_ifname);
    }

    FREE(self->q_id);
    FREE(self);
}

bool osn_qos_apply(osn_qos_t *self)
{
    int *qp;
    uint8_t bcm_queue_size;
    struct bcm_qos_queue *queue_list;

    queue_list = bcm_qos_get_queue(self->q_ifname);
    bcm_queue_size = bcm_qos_get_queue_length(self->q_ifname);

    /* Do we really need to apply config for ALL the Qs? */
    for (qp = self->q_id; qp < self->q_id_e; qp++)
    {
        int qid = *qp;
        if (qid < 0 || qid >= bcm_queue_size)
        {
            LOG(ERR, "%s: invalid queue id %d", __func__, qid);
            return false;
        }

        if (!bcm_qos_queue_set(self->q_ifname, qid, queue_list[qid].qq_min_rate, queue_list[qid].qq_max_rate))
        {
            return false;
        }
    }

    return true;
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

    struct bcm_qos_queue_entry qe;
    int qid;
    int *qp;

    memset(qqs, 0, sizeof(*qqs));

    qid = bcm_qos_id_get(self->q_ifname, tag);
    if (qid < 0)
    {
        LOG(ERR, "bcm_qos: All queues are full.");
        return false;
    }

    /* Append the queue id to the list for this object */
    qp = MEM_APPEND(&self->q_id, &self->q_id_e, sizeof(*qp));
    *qp = qid;

    /* Find the affected Q and set parameters */
    if (!bcm_qos_find_queue(self->q_ifname, tag, &qe))
    {
        LOG(ERR, "bcm_qos: queue created but missing?");
        return false;
    }

    if (bandwidth_ceil > 0)
    {
        qe.queue->qq_max_rate = bandwidth_ceil;
        qe.queue->qq_min_rate = bandwidth;
    }
    else
    {
        qe.queue->qq_max_rate = bandwidth;
        qe.queue->qq_min_rate = 0;
    }

    /* Calculate the MARK for this DPI */
    if (qe.type == BCM_QUEUE_DEVQ)
    {
        qqs->qqs_fwmark = SKBMARK_SET_Q(0, qid);
        qqs->qqs_fwmark = SKBMARK_SET_FLOW_ID(qqs->qqs_fwmark, 1);
    }
    else
    {
        qqs->qqs_fwmark = SKBMARK_SET_DPIQ_MARK(0, qid);
        qqs->qqs_fwmark = SKBMARK_SET_SQ_MARK(qqs->qqs_fwmark, 1);
    }

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
 * Gets parent eth interface from eth.vlan interface eth<port number>.<vlan number>
 */
static char *bcm_qos_get_eth_dev_parent(const char *ifname, char *parent)
{
    const char *punkt = strchr(ifname, '.');
    size_t len = punkt ? (size_t)(punkt - ifname) : strlen(ifname);

    strncpy(parent, ifname, len);
    return parent;
}

int bcm_qos_get_queue_type(const char *ifname)
{
    return (ifname && strstr(ifname, BCM_QOS_ETH_DEV_PREFIX)) ? BCM_QUEUE_DEVQ : BCM_QUEUE_SVCQ;
}

int bcm_qos_get_queue_length(const char *ifname)
{
    return (bcm_qos_get_queue_type(ifname) == BCM_QUEUE_DEVQ) ? BCM_QOS_DEVQ_COUNT : BCM_QOS_SVCQ_COUNT;
}

struct bcm_qos_queue *bcm_qos_get_queue(const char *ifname)
{
    return (bcm_qos_get_queue_type(ifname) == BCM_QUEUE_DEVQ) ? bcm_qos_devq_list : bcm_qos_svcq_list;
}

bool bcm_qos_find_queue(const char *ifname, const char *tag, struct bcm_qos_queue_entry *qe)
{
    struct bcm_qos_queue *queue_list;
    uint8_t bcm_queue_size, qid;

    qe->type = bcm_qos_get_queue_type(ifname);
    queue_list = bcm_qos_get_queue(ifname);
    bcm_queue_size = bcm_qos_get_queue_length(ifname);

    for (qid = BCM_QOS_START_QUEUE; qid < bcm_queue_size; qid++)
    {
        if (queue_list[qid].qq_tag != NULL && strcmp(queue_list[qid].qq_tag, tag) == 0)
        {
            qe->index = qid;
            qe->queue = &queue_list[qid];
            return true;
        }
    }

    return false;
}

bool bcm_qos_new_queue(const char *ifname, const char *tag, struct bcm_qos_queue_entry *qe)
{
    struct bcm_qos_queue *queue_list;
    uint8_t bcm_queue_size, qid;

    qe->type = bcm_qos_get_queue_type(ifname);
    queue_list = bcm_qos_get_queue(ifname);
    bcm_queue_size = bcm_qos_get_queue_length(ifname);

    for (qid = BCM_QOS_START_QUEUE; qid < bcm_queue_size; qid++)
    {
        if (queue_list[qid].qq_refcnt == 0)
        {
            qe->index = qid;
            qe->queue = &queue_list[qid];
            return true;
        }
    }

    return false;
}

bool bcm_qos_init(const char *ifname)
{
    tmctl_ret_e rc;
    tmctl_if_t tm_if = {0};
    char eth_dev_parent[IFNAMSIZ] = {0};
    static bool svcq_init = false;

    /*
     * if ifname is provided and is eth device, then configure devQ which is a subsidiary scheduler of the primary WAN
     * port scheduler since we don't have any other use cases, we will assume the device type is eth
     */
    if (bcm_qos_get_queue_type(ifname) == BCM_QUEUE_DEVQ)
    {
        tm_if.ethIf.ifname = bcm_qos_get_eth_dev_parent(ifname, eth_dev_parent);

        rc = tmctl_portTmInit(TMCTL_DEV_ETH, &tm_if, TMCTL_SCHED_TYPE_WRR | TMCTL_INIT_DEFAULT_QUEUES, -1);
        if (rc != TMCTL_SUCCESS)
        {
            LOG(ERR, "bcm_qos: error initializing TMCTL devQ on %s err: %d", ifname, rc);
            return false;
        }
        LOG(NOTICE, "bcm_qos: TMCTL devQ on: %s initialized", ifname);
        return true;
    }
    /*
     * if there is no ifname provided or it is not eth dev, then we want to configure SQ and portless scheduler
     * svcq are singular entity across the arch with scheduling process that is not bound to any port/interface
     */
    else
    {
        if (svcq_init)
        {
            return true;
        }

        rc = tmctl_portTmInit(
                TMCTL_DEV_SVCQ,
                NULL,
                TMCTL_SCHED_TYPE_WRR | TMCTL_INIT_DEFAULT_QUEUES,
                BCM_QOS_SVCQ_COUNT);
        if (rc != TMCTL_SUCCESS)
        {
            LOG(ERR, "bcm_qos: error initializing TMCTL svcQ err: %d", rc);
            return false;
        }
        svcq_init = true;

        LOG(NOTICE, "bcm_qos: TMCTL svcQ initialized");
        return true;
    }
}

bool bcm_qos_queue_set(const char *ifname, int queue_id, int min_rate, int max_rate)
{
    tmctl_ret_e rc;
    tmctl_shaper_t tm_shaper = {0};
    tmctl_if_t tm_if = {0};
    char eth_dev_parent[IFNAMSIZ] = {0};
    int que_type = TMCTL_DEV_SVCQ;

    if (bcm_qos_get_queue_type(ifname) == BCM_QUEUE_DEVQ)
    {
        que_type = TMCTL_DEV_ETH;
        tm_if.ethIf.ifname = bcm_qos_get_eth_dev_parent(ifname, eth_dev_parent);
    }

    LOG(INFO,
        "bcm_qos: queue[%d]: Applying settings queue_type: %s, dev: %s, min_rate=%d, max_rate=%d",
        queue_id,
        (que_type == TMCTL_DEV_ETH) ? "devQ" : "svcQ",
        (ifname != NULL) ? ifname : "NULL",
        min_rate,
        max_rate);

    tm_shaper.shapingRate = max_rate;
    tm_shaper.minRate = min_rate;

    rc = tmctl_setQueueShaper(que_type, &tm_if, queue_id, &tm_shaper);
    if (rc != TMCTL_SUCCESS)
    {
        LOG(ERR,
            "bcm_qos: device queue[%d]: Error %d, queue_type: %s, dev: %s, min_rate: %d, max_rate: %d",
            queue_id,
            rc,
            (que_type == TMCTL_DEV_ETH) ? "devQ" : "svcQ",
            (ifname != NULL) ? ifname : "NULL",
            min_rate,
            max_rate);
        return false;
    }

    return true;
}

bool bcm_qos_queue_reset(const char *ifname, int queue_id)
{
    return bcm_qos_queue_set(ifname, queue_id, 0, BCM_QOS_RATE_DEFAULT);
}

int bcm_qos_id_get(const char *ifname, const char *tag)
{
    struct bcm_qos_queue_entry qe;

    /* Check if there's a queue with a matching tag */
    if (bcm_qos_find_queue(ifname, tag, &qe))
    {
        /* The tag was found return this index */
        qe.queue->qq_refcnt++;
        return qe.index;
    }

    /* Find first empty queue */
    if (bcm_qos_new_queue(ifname, tag, &qe))
    {
        /* The tag was found return this index */
        qe.queue->qq_refcnt = 1;
        qe.queue->qq_tag = strdup(tag);
        return qe.index;
    }

    return -1;
}

void bcm_qos_id_put(const char *ifname, int qid)
{
    struct bcm_qos_queue *queue_list;
    uint8_t bcm_queue_size;

    queue_list = bcm_qos_get_queue(ifname);
    bcm_queue_size = bcm_qos_get_queue_length(ifname);

    if (qid < 0 || qid >= bcm_queue_size)
    {
        LOG(ERR, "%s: invalid queue id %d", __func__, qid);
        return;
    }

    /*
     * This implementation backend does not support QoS event reporting.
     * (There is no need for event reporting on this platform-specific implementation.)
     */
    if (queue_list[qid].qq_refcnt-- > 1)
    {
        return;
    }

    if (!bcm_qos_queue_reset(ifname, qid))
    {
        LOG(WARN, "bcm_qos: Unable to reset queue %d.", qid);
    }

    FREE(queue_list[qid].qq_tag);
    queue_list[qid].qq_tag = NULL;
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
