/*
 * Copyright (c) Sakion Team. All rights reserved.
 * Copyright (c) myflavor <admin@myflv.cn>.
 *
 * File name: rekernel_x_genl.c
 * Description: ReKernel-X generic netlink transport — family registration,
 *              event serialisation (NLA) and multicast to userspace.
 * Author: nep_timeline@outlook.com, myflavor <admin@myflv.cn>
 */
#include "rekernel_x_log.h"
#include "rekernel_x.h"
#include <linux/printk.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/netlink.h>
#include <net/sock.h>
#include <net/genetlink.h>

static bool rekernel_x_genl_registered = false;

bool rekernel_x_netlink_ready(void)
{
	return rekernel_x_genl_registered;
}

/* user -> kernel: add a uid to the network monitor hashmap. */
static int rekernel_x_genl_monitor_net(struct sk_buff *skb, struct genl_info *info)
{
	uid_t muid;

	if (!info->attrs[REKERNEL_X_A_UID])
		return -EINVAL;

	muid = (uid_t)nla_get_u32(info->attrs[REKERNEL_X_A_UID]);
	rekernel_x_debug_log("addMonitorUid uid=%d\n", muid);
	net_uid_add(muid);
	return 0;
}

/* user -> kernel: remove a uid from the network monitor hashmap. */
static int rekernel_x_genl_del_monitor_net(struct sk_buff *skb, struct genl_info *info)
{
	uid_t muid;

	if (!info->attrs[REKERNEL_X_A_UID])
		return -EINVAL;

	muid = (uid_t)nla_get_u32(info->attrs[REKERNEL_X_A_UID]);
	rekernel_x_debug_log("delMonitorNet uid=%d\n", muid);
	net_uid_del(muid);
	return 0;
}

static const struct nla_policy rekernel_x_genl_policy[REKERNEL_X_A_MAX + 1] = {
	[REKERNEL_X_A_EVENT]  = { .type = NLA_NESTED },
	[REKERNEL_X_A_UID]    = { .type = NLA_U32 },
};

static const struct genl_ops rekernel_x_genl_ops[] = {
	{
		.cmd  = REKERNEL_X_C_ADD_MONITOR_NET,
		.doit = rekernel_x_genl_monitor_net,
	},
	{
		.cmd  = REKERNEL_X_C_DEL_MONITOR_NET,
		.doit = rekernel_x_genl_del_monitor_net,
	},
};

static const struct genl_multicast_group rekernel_x_genl_mcgrps[] = {
	{ .name = REKERNEL_X_GENL_MCGRP_NAME },
};

static struct genl_family rekernel_x_genl_family = {
	.name     = REKERNEL_X_GENL_FAMILY_NAME,
	.version  = REKERNEL_X_GENL_VERSION,
	.maxattr  = REKERNEL_X_A_MAX,
	.policy   = rekernel_x_genl_policy,
	.module   = THIS_MODULE,
	.ops      = rekernel_x_genl_ops,
	.n_ops    = ARRAY_SIZE(rekernel_x_genl_ops),
	.mcgrps   = rekernel_x_genl_mcgrps,
	.n_mcgrps = ARRAY_SIZE(rekernel_x_genl_mcgrps),
};

/*
 * Generic Netlink: build nested NLA attributes from the event struct and
 * multicast to the "events" group.
 *
 * Wire format:
 *   REKERNEL_X_A_EVENT (NLA_NESTED)
 *     ├─ REKERNEL_X_A_EVENT_TYPE (u8)
 *     └─ REKERNEL_X_A_BINDER/_SIGNAL/_NETWORK (NLA_NESTED)
 *          └─ field sub-attributes
 */
int sendMessage(struct rekernel_x_event *event)
{
    struct sk_buff *skb;
    void *msg_head;
    struct nlattr *evt, *payload;
    int rc;

    /* Binder is the largest payload: ~168 bytes nested.  256 is safe. */
    skb = genlmsg_new(nla_total_size(256), GFP_ATOMIC);
    if (!skb) {
        rekernel_x_err_log("genlmsg alloc failure!\n");
        return LINE_ERROR;
    }

    msg_head = genlmsg_put(skb, 0, 0, &rekernel_x_genl_family, 0, REKERNEL_X_C_EVENT);
    if (!msg_head) {
        rekernel_x_err_log("genlmsg_put failure!\n");
        nlmsg_free(skb);
        return LINE_ERROR;
    }

    /* REKERNEL_X_A_EVENT (outer nest) */
    evt = nla_nest_start(skb, REKERNEL_X_A_EVENT);
    if (!evt)
        goto nla_fail;

    if (nla_put_u8(skb, REKERNEL_X_A_EVENT_TYPE, event->type))
        goto nla_fail;

    switch (event->type) {
    case REKERNEL_X_EVT_BINDER: {
        struct rekernel_x_binder_event *b = &event->u.binder;

        payload = nla_nest_start(skb, REKERNEL_X_A_BINDER);
        if (!payload)
            goto nla_fail;
        if (nla_put_u32(skb, REKERNEL_X_A_BINDER_TYPE, b->binder_type) ||
            nla_put_u32(skb, REKERNEL_X_A_BINDER_ONEWAY, b->oneway) ||
            nla_put_s32(skb, REKERNEL_X_A_BINDER_FROM_PID, b->from_pid) ||
            nla_put_u32(skb, REKERNEL_X_A_BINDER_FROM_UID, b->from_uid) ||
            nla_put_s32(skb, REKERNEL_X_A_BINDER_TARGET_PID, b->target_pid) ||
            nla_put_u32(skb, REKERNEL_X_A_BINDER_TARGET_UID, b->target_uid) ||
            nla_put_s32(skb, REKERNEL_X_A_BINDER_CODE, b->code) ||
            nla_put_string(skb, REKERNEL_X_A_BINDER_RPC_NAME, b->rpc_name))
            goto nla_fail;
        nla_nest_end(skb, payload);
        break;
    }
    case REKERNEL_X_EVT_SIGNAL: {
        struct rekernel_x_signal_event *s = &event->u.signal;

        payload = nla_nest_start(skb, REKERNEL_X_A_SIGNAL);
        if (!payload)
            goto nla_fail;
        if (nla_put_s32(skb, REKERNEL_X_A_SIGNAL_SIGNAL, s->signal) ||
            nla_put_s32(skb, REKERNEL_X_A_SIGNAL_KILLER_PID, s->killer_pid) ||
            nla_put_u32(skb, REKERNEL_X_A_SIGNAL_KILLER_UID, s->killer_uid) ||
            nla_put_s32(skb, REKERNEL_X_A_SIGNAL_DST_PID, s->dst_pid) ||
            nla_put_u32(skb, REKERNEL_X_A_SIGNAL_DST_UID, s->dst_uid))
            goto nla_fail;
        nla_nest_end(skb, payload);
        break;
    }
    case REKERNEL_X_EVT_NETWORK: {
        struct rekernel_x_network_event *n = &event->u.network;

        payload = nla_nest_start(skb, REKERNEL_X_A_NETWORK);
        if (!payload)
            goto nla_fail;
        if (nla_put_u32(skb, REKERNEL_X_A_NETWORK_PROTO, n->proto) ||
            nla_put_u32(skb, REKERNEL_X_A_NETWORK_TARGET_UID, n->target_uid) ||
            nla_put_s32(skb, REKERNEL_X_A_NETWORK_DATA_LEN, n->data_len))
            goto nla_fail;
        nla_nest_end(skb, payload);
        break;
    }
    default:
        goto nla_fail;
    }

    nla_nest_end(skb, evt);
    genlmsg_end(skb, msg_head);

    /* genlmsg_multicast consumes skb; -ESRCH only means "no listeners". */
    rc = genlmsg_multicast(&rekernel_x_genl_family, skb, 0, 0, GFP_ATOMIC);
    if (rc && rc != -ESRCH) {
        rekernel_x_err_log("genlmsg_multicast failed, rc=%d\n", rc);
        return LINE_ERROR;
    }

    return LINE_SUCCESS;

nla_fail:
    genlmsg_cancel(skb, msg_head);
    nlmsg_free(skb);
    rekernel_x_err_log("sendMessage: nla_put failed\n");
    return LINE_ERROR;
}

int register_genl(void)
{
	rekernel_x_info_log("Trying to register Generic Netlink family......\n");

	if (genl_register_family(&rekernel_x_genl_family) != 0) {
		rekernel_x_err_log("Failed to register genl family!\n");
		return LINE_ERROR;
	}
	rekernel_x_genl_registered = true;

	rekernel_x_info_log("Registered genl family! ID: %d\n", rekernel_x_genl_family.id);
	return LINE_SUCCESS;
}

void unregister_genl(void)
{
	if (rekernel_x_genl_registered) {
		genl_unregister_family(&rekernel_x_genl_family);
		rekernel_x_genl_registered = false;
	}
}
