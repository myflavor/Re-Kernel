/*
 * Copyright (c) Sakion Team. All rights reserved.
 * Copyright (c) myflavor <admin@myflv.cn>.
 *
 * File name: rekernel_x_binder.c
 * Description: ReKernel-X binder trace hooks — sync/async transactions,
 *              replies, and async-buffer-full detection for frozen tasks.
 * Author: nep_timeline@outlook.com, myflavor <admin@myflv.cn>
 */
#include "rekernel_x_log.h"
#include "rekernel_x.h"
#include <linux/printk.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <trace/hooks/binder.h>
#include <../android/binder_internal.h>

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0))
void line_binder_alloc_new_buf_locked(void *data, size_t size, size_t *free_async_space, int is_async, bool *should_fail)
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0))
void line_binder_alloc_new_buf_locked(void *data, size_t size, size_t *free_async_space, int is_async)
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0))
void line_binder_alloc_new_buf_locked(void *data, size_t size, struct binder_alloc *alloc, int is_async)
#endif
{
	struct task_struct *p = NULL;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0))
	struct binder_alloc *alloc = NULL;

	alloc = container_of(free_async_space, struct binder_alloc, free_async_space);
	if (alloc == NULL) {
		return;
	}
#endif
	if (is_async
		&& (alloc->free_async_space < 3 * (size + sizeof(struct binder_buffer))
		|| (alloc->free_async_space < WARN_AHEAD_SPACE))) {
		rcu_read_lock();
		p = find_task_by_vpid(alloc->pid);
		rcu_read_unlock();
		if (p != NULL && line_is_frozen(p)) {
			rekernel_x_debug_log("Binder Free buffer full! from=%d | target=%d\n", task_uid(current).val, task_uid(p).val);
			if (rekernel_x_netlink_ready()) {
				struct rekernel_x_event event = {
					.type = REKERNEL_X_EVT_BINDER,
					.u.binder = {
						.binder_type = REKERNEL_X_BINDER_FREE_BUFFER_FULL,
						.oneway = 1,
						.from_pid = task_tgid_nr(current),
						.from_uid = task_uid(current).val,
						.target_pid = task_tgid_nr(p),
						.target_uid = task_uid(p).val,
						.code = -1,
						.rpc_name = "FREE_BUFFER_FULL",
					},
				};
				sendMessage(&event);
			}
		}
	}
}

struct hlist_head *binder_procs = NULL;
struct mutex *binder_procs_lock = NULL;

static bool re_binder_hook_alloc_buf;
static bool re_binder_hook_preset;
static bool re_binder_hook_reply;
static bool re_binder_hook_trans;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0))
void line_binder_preset(void *data, struct hlist_head *hhead,
	struct mutex *lock, struct binder_proc *proc)
#else
void line_binder_preset(void *data, struct hlist_head *hhead,
	struct mutex *lock)
#endif
{
	if (binder_procs == NULL)
		binder_procs = hhead;

	if (binder_procs_lock == NULL)
		binder_procs_lock = lock;
}

void line_binder_reply(void *data, struct binder_proc *target_proc, struct binder_proc *proc,
	struct binder_thread *thread, struct binder_transaction_data *tr)
{
	if (target_proc
		&& (NULL != target_proc->tsk)
		&& (NULL != proc->tsk)
		&& (task_uid(target_proc->tsk).val <= MAX_SYSTEM_UID)
		&& (proc->pid != target_proc->pid)
		&& line_is_frozen(target_proc->tsk)) {
		rekernel_x_debug_log("Sync Binder Reply! from=%d | target=%d\n", task_uid(proc->tsk).val, task_uid(target_proc->tsk).val);
		if (rekernel_x_netlink_ready()) {
			struct rekernel_x_event event = {
				.type = REKERNEL_X_EVT_BINDER,
				.u.binder = {
					.binder_type = REKERNEL_X_BINDER_REPLY,
					.from_pid = task_tgid_nr(proc->tsk),
					.from_uid = task_uid(proc->tsk).val,
					.target_pid = task_tgid_nr(target_proc->tsk),
					.target_uid = task_uid(target_proc->tsk).val,
					.code = -1,
					.rpc_name = "SYNC_BINDER_REPLY",
				},
			};
			sendMessage(&event);
		}
	}
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
static long line_copy_from_user_nofault(void *dst, const void __user *src, size_t size)
{
	long ret = -EFAULT;
	if (access_ok(src, size)) {
		pagefault_disable();
		ret = __copy_from_user_inatomic(dst, src, size);
		pagefault_enable();
	}
	if (ret)
		return -EFAULT;
	return 0;
}
#endif

static long line_copy_from_user_compatible(void *dst, const void __user *src, size_t size)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
	return line_copy_from_user_nofault(dst, src, size);
#else
	return copy_from_user(dst, src, size);
#endif
}

void line_binder_transaction(void *data, struct binder_proc *target_proc, struct binder_proc *proc,
	struct binder_thread *thread, struct binder_transaction_data *tr)
{
	if (!(tr->flags & TF_ONE_WAY) /* sync binder */
		&& target_proc
		&& (NULL != target_proc->tsk)
		&& (NULL != proc->tsk)
		&& (task_uid(target_proc->tsk).val > MIN_USERAPP_UID)
		&& (proc->pid != target_proc->pid)
		&& line_is_frozen(target_proc->tsk)) {
		rekernel_x_debug_log("Sync Binder Transaction! from=%d | target=%d\n", task_uid(proc->tsk).val, task_uid(target_proc->tsk).val);
		if (rekernel_x_netlink_ready()) {
			struct rekernel_x_event event = {
				.type = REKERNEL_X_EVT_BINDER,
				.u.binder = {
					.binder_type = REKERNEL_X_BINDER_TRANSACTION,
					.from_pid = task_tgid_nr(proc->tsk),
					.from_uid = task_uid(proc->tsk).val,
					.target_pid = task_tgid_nr(target_proc->tsk),
					.target_uid = task_uid(target_proc->tsk).val,
					.code = -1,
					.rpc_name = "SYNC_BINDER",
				},
			};
			sendMessage(&event);
		}
	}

	if ((tr->flags & TF_ONE_WAY) /* async binder */
		&& target_proc
		&& (NULL != target_proc->tsk)
		&& (NULL != proc->tsk)
		&& (task_uid(target_proc->tsk).val > MIN_USERAPP_UID)
		&& (proc->pid != target_proc->pid)
		&& line_is_frozen(target_proc->tsk)) {
		char buf_data[INTERFACETOKEN_BUFF_SIZE];
		char rpc_name[INTERFACETOKEN_BUFF_SIZE] = {0};
		size_t buf_data_size;
		int i = 0, j = 0;

		buf_data_size = tr->data_size > INTERFACETOKEN_BUFF_SIZE ? INTERFACETOKEN_BUFF_SIZE : tr->data_size;
		if (!line_copy_from_user_compatible(buf_data, (char*)tr->data.ptr.buffer, buf_data_size)) {
			if (buf_data_size > PARCEL_OFFSET) {
				char *p = (char *)(buf_data) + PARCEL_OFFSET;
				j = PARCEL_OFFSET + 1;
				while (i < INTERFACETOKEN_BUFF_SIZE && j < buf_data_size && *p != '\0') {
					rpc_name[i++] = *p;
					j += 2;
					p += 2;
				}
				if (i == INTERFACETOKEN_BUFF_SIZE) rpc_name[i-1] = '\0';
			}
			rekernel_x_debug_log("ASync Binder Transaction! from=%d | target=%d\n", task_uid(proc->tsk).val, task_uid(target_proc->tsk).val);
			if (rekernel_x_netlink_ready()) {
				struct rekernel_x_event event = {
					.type = REKERNEL_X_EVT_BINDER,
					.u.binder = {
						.binder_type = REKERNEL_X_BINDER_TRANSACTION,
						.oneway = 1,
						.from_pid = task_tgid_nr(proc->tsk),
						.from_uid = task_uid(proc->tsk).val,
						.target_pid = task_tgid_nr(target_proc->tsk),
						.target_uid = task_uid(target_proc->tsk).val,
						.code = tr->code,
					},
				};
				strscpy(event.u.binder.rpc_name, rpc_name, sizeof(event.u.binder.rpc_name));
				sendMessage(&event);
			}
		}
	}
}

int register_binder(void)
{
	int rc = LINE_SUCCESS;

	rc = register_trace_android_vh_binder_alloc_new_buf_locked(line_binder_alloc_new_buf_locked, NULL);
	if (rc != LINE_SUCCESS) {
		rekernel_x_err_log("register_trace_android_vh_binder_alloc_new_buf_locked failed, rc=%d\n", rc);
		goto err;
	}
	re_binder_hook_alloc_buf = true;

	rc = register_trace_android_vh_binder_preset(line_binder_preset, NULL);
	if (rc != LINE_SUCCESS) {
		rekernel_x_err_log("register_trace_android_vh_binder_preset failed, rc=%d\n", rc);
		goto err;
	}
	re_binder_hook_preset = true;

	rc = register_trace_android_vh_binder_reply(line_binder_reply, NULL);
	if (rc != LINE_SUCCESS) {
		rekernel_x_err_log("register_trace_android_vh_binder_reply failed, rc=%d\n", rc);
		goto err;
	}
	re_binder_hook_reply = true;

	rc = register_trace_android_vh_binder_trans(line_binder_transaction, NULL);
	if (rc != LINE_SUCCESS) {
		rekernel_x_err_log("register_trace_android_vh_binder_trans failed, rc=%d\n", rc);
		goto err;
	}
	re_binder_hook_trans = true;

	return LINE_SUCCESS;
err:
	unregister_binder();
	return rc;
}

void unregister_binder(void)
{
	if (re_binder_hook_trans) {
		unregister_trace_android_vh_binder_trans(line_binder_transaction, NULL);
		re_binder_hook_trans = false;
	}
	if (re_binder_hook_reply) {
		unregister_trace_android_vh_binder_reply(line_binder_reply, NULL);
		re_binder_hook_reply = false;
	}
	if (re_binder_hook_preset) {
		unregister_trace_android_vh_binder_preset(line_binder_preset, NULL);
		re_binder_hook_preset = false;
	}
	if (re_binder_hook_alloc_buf) {
		unregister_trace_android_vh_binder_alloc_new_buf_locked(line_binder_alloc_new_buf_locked, NULL);
		re_binder_hook_alloc_buf = false;
	}
}
