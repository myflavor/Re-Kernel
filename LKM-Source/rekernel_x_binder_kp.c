/*
 * Copyright (c) Sakion Team. All rights reserved.
 * Copyright (c) myflavor <admin@myflv.cn>.
 *
 * File name: rekernel_x_binder_kp.c
 * Description: ReKernel-X binder hooks via kprobe — resolves internal binder
 *              symbols via kallsyms and intercepts binder_proc_transaction to
 *              drop outdated async transactions for frozen tasks.
 * Author: nep_timeline@outlook.com, myflavor <admin@myflv.cn>
 */
#include "rekernel_x_log.h"
#include "rekernel_x.h"
#include <linux/printk.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/kprobes.h>
#include <../android/binder_internal.h>

static unsigned long (*re_kallsyms_lookup_name)(const char* name);
static void (*re_binder_transaction_buffer_release)(struct binder_proc* proc, struct binder_thread* thread, struct binder_buffer* buffer, binder_size_t off_end_offset, bool is_failure);
static void (*re_binder_alloc_free_buf)(struct binder_alloc* alloc, struct binder_buffer* buffer);
static struct binder_stats(*re_binder_stats);

static inline void binder_inner_proc_lock(struct binder_proc* proc)
__acquires(&proc->inner_lock)
{
	spin_lock(&proc->inner_lock);
}

static inline void binder_inner_proc_unlock(struct binder_proc* proc)
__releases(&proc->inner_lock)
{
	spin_unlock(&proc->inner_lock);
}

static inline void binder_node_lock(struct binder_node* node)
__acquires(&node->lock)
{
	spin_lock(&node->lock);
}

static inline void binder_node_unlock(struct binder_node* node)
__releases(&node->lock)
{
	spin_unlock(&node->lock);
}

static bool binder_can_update_transaction(struct binder_transaction* t1, struct binder_transaction* t2)
{
	if ((t1->flags & t2->flags & TF_ONE_WAY) != TF_ONE_WAY || !t1->to_proc || !t2->to_proc)
		return false;
	if (t1->to_proc->tsk == t2->to_proc->tsk && t1->code == t2->code &&
		t1->flags == t2->flags && t1->buffer->pid == t2->buffer->pid &&
		t1->buffer->target_node->ptr == t2->buffer->target_node->ptr &&
		t1->buffer->target_node->cookie == t2->buffer->target_node->cookie)
		return true;
	return false;
}

static struct binder_transaction* binder_find_outdated_transaction_ilocked(struct binder_transaction* t,
	struct list_head* target_list)
{
	struct binder_work* w;
	bool second = false;

	list_for_each_entry(w, target_list, entry) {
		struct binder_transaction* t_queued;

		if (w->type != BINDER_WORK_TRANSACTION)
			continue;
		t_queued = container_of(w, struct binder_transaction, work);
		if (binder_can_update_transaction(t_queued, t)) {
			if (second)
				return t_queued;
			else
				second = true;
		}
	}
	return NULL;
}

static inline void __nocfi binder_release_entire_buffer(struct binder_proc* proc,
	struct binder_thread* thread, struct binder_buffer* buffer, bool is_failure)
{
	binder_size_t off_end_offset;

	off_end_offset = ALIGN(buffer->data_size, sizeof(void*));
	off_end_offset += buffer->offsets_size;

	re_binder_transaction_buffer_release(proc, thread, buffer,
		off_end_offset, is_failure);
}

static inline void binder_stats_deleted(enum binder_stat_types type)
{
	atomic_inc(&re_binder_stats->obj_deleted[type]);
}

static int __nocfi binder_proc_transaction_pre(struct kprobe* p, struct pt_regs* regs)
{
	struct binder_transaction* t = (struct binder_transaction*)regs->regs[0];
	struct binder_proc* proc = (struct binder_proc*)regs->regs[1];

	struct binder_node* node = t->buffer->target_node;
	struct binder_transaction* t_outdated = NULL;

	if (!node || !proc || proc->is_frozen || !(t->flags & TF_ONE_WAY))
		return 0;

	if (line_is_frozen(proc->tsk)) {
		binder_node_lock(node);
		if (!node->has_async_transaction) {
			binder_node_unlock(node);
			return 0;
		}
		binder_inner_proc_lock(proc);
		t_outdated = binder_find_outdated_transaction_ilocked(t, &node->async_todo);
		if (t_outdated) {
			list_del_init(&t_outdated->work.entry);
			proc->outstanding_txns--;
		}
		binder_inner_proc_unlock(proc);
		binder_node_unlock(node);

		if (t_outdated) {
			struct binder_buffer* buffer = t_outdated->buffer;
			rekernel_x_debug_log("free_outdated txn %d supersedes %d\n", t->debug_id, t_outdated->debug_id);
			t_outdated->buffer = NULL;
			buffer->transaction = NULL;
			binder_release_entire_buffer(proc, NULL, buffer, false);
			re_binder_alloc_free_buf(&proc->alloc, buffer);
			kfree(t_outdated);
			binder_stats_deleted(BINDER_STAT_TRANSACTION);
		}
	}
	return 0;
}

static struct kprobe kp_kallsyms_lookup_name = {
	.symbol_name = "kallsyms_lookup_name"
};
static struct kprobe kp_binder_proc_transaction = {
	.symbol_name = "binder_proc_transaction",
	.pre_handler = binder_proc_transaction_pre
};

static bool re_kp_binder_proc_registered;

void __nocfi register_binder_kp(void) {
	int rc = LINE_SUCCESS;

	rc = register_kprobe(&kp_kallsyms_lookup_name);
	if (rc != LINE_SUCCESS) {
		rekernel_x_err_log("register kallsyms_lookup_name kprobe failed, rc=%d (binder async-cleanup disabled)\n", rc);
		return;
	}
	re_kallsyms_lookup_name = (void*)kp_kallsyms_lookup_name.addr;
	unregister_kprobe(&kp_kallsyms_lookup_name);

	re_binder_transaction_buffer_release = (void*)re_kallsyms_lookup_name("binder_transaction_buffer_release");
	re_binder_alloc_free_buf = (void*)re_kallsyms_lookup_name("binder_alloc_free_buf");
	re_binder_stats = (void*)re_kallsyms_lookup_name("binder_stats");

	if (re_binder_transaction_buffer_release == NULL || re_binder_alloc_free_buf == NULL || re_binder_stats == NULL) {
		rekernel_x_err_log("resolve binder symbols failed (binder async-cleanup disabled)\n");
		return;
	}

	rc = register_kprobe(&kp_binder_proc_transaction);
	if (rc != LINE_SUCCESS) {
		rekernel_x_err_log("register binder_proc_transaction kprobe failed, rc=%d (binder async-cleanup disabled)\n", rc);
		return;
	}
	re_kp_binder_proc_registered = true;
}

void unregister_binder_kp(void) {
	if (re_kp_binder_proc_registered) {
		unregister_kprobe(&kp_binder_proc_transaction);
		re_kp_binder_proc_registered = false;
	}
}
