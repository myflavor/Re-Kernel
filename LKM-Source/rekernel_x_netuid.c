/*
 * Copyright (c) Sakion Team. All rights reserved.
 * Copyright (c) myflavor <admin@myflv.cn>.
 *
 * File name: rekernel_x_netuid.c
 * Description: network-monitor uid hashmap. Uids are added/removed from
 *              userspace via genl and queried by the netfilter hook.
 * Author: nep_timeline@outlook.com, myflavor <admin@myflv.cn>
 */
#include "rekernel_x_log.h"
#include "rekernel_x.h"
#include <linux/printk.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/rcupdate.h>

/* hashmap for net monitor uids */
#define REKERNEL_X_NET_UID_HASH_BITS 6
static DEFINE_HASHTABLE(rekernel_x_net_uid_map, REKERNEL_X_NET_UID_HASH_BITS);
struct uid_info {
	uid_t uid;
	struct hlist_node hnode;
	struct rcu_head rcu;
};

static DEFINE_MUTEX(rekernel_x_net_uid_mutex);

bool net_uid_monitored_rcu(uid_t uid)
{
	struct uid_info *entry;
	bool found = false;

	hash_for_each_possible_rcu(rekernel_x_net_uid_map, entry, hnode, uid) {
		if (entry->uid == uid) {
			found = true;
			break;
		}
	}
	return found;
}

/* add a uid to the monitor map (no-op if already present). Caller must NOT hold the mutex. */
void net_uid_add(uid_t uid)
{
	struct uid_info *entry;
	bool found = false;

	mutex_lock(&rekernel_x_net_uid_mutex);
	hash_for_each_possible(rekernel_x_net_uid_map, entry, hnode, uid) {
		if (entry->uid == uid) {
			found = true;
			break;
		}
	}
	if (!found) {
		entry = kmalloc(sizeof(*entry), GFP_KERNEL);
		if (entry) {
			entry->uid = uid;
			hash_add_rcu(rekernel_x_net_uid_map, &entry->hnode, uid);
		}
	}
	mutex_unlock(&rekernel_x_net_uid_mutex);
}

/* remove a uid from the monitor map. Caller must NOT hold the mutex. */
void net_uid_del(uid_t uid)
{
	struct uid_info *entry;

	mutex_lock(&rekernel_x_net_uid_mutex);
	hash_for_each_possible(rekernel_x_net_uid_map, entry, hnode, uid) {
		if (entry->uid == uid) {
			hash_del_rcu(&entry->hnode);
			kfree_rcu(entry, rcu);
			break;
		}
	}
	mutex_unlock(&rekernel_x_net_uid_mutex);
}

/* tear down the map at module exit (called from netfilter unregister path). */
void net_uid_destroy(void)
{
	struct uid_info *entry;
	struct hlist_node *tmp;
	int bkt;

	synchronize_rcu();
	hash_for_each_safe(rekernel_x_net_uid_map, bkt, tmp, entry, hnode) {
		hash_del(&entry->hnode);
		kfree(entry);
	}
}

void net_uid_init(void)
{
	hash_init(rekernel_x_net_uid_map);
}
