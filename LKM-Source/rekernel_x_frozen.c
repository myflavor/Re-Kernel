/*
 * Copyright (c) Sakion Team. All rights reserved.
 * Copyright (c) myflavor <admin@myflv.cn>.
 *
 * File name: rekernel_x_frozen.c
 * Description: task frozen-state predicate, version-compatible across the
 *              supported kernel range. Used by the binder/signal/kprobe hooks.
 * Author: nep_timeline@outlook.com, myflavor <admin@myflv.cn>
 */
#include "rekernel_x_log.h"
#include "rekernel_x.h"
#include <linux/printk.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/freezer.h>
#include <linux/cgroup.h>
#include <linux/version.h>
#include <linux/sched.h>

static inline bool rekernel_x_is_frozen_state_compatible(struct task_struct *task)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
	return READ_ONCE(task->__state) & TASK_FROZEN;
#else
	return frozen(task);
#endif
}

static inline bool rekernel_x_is_jobctl_frozen_compatible(struct task_struct *task)
{
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(5, 10, 0))
	return cgroup_task_freeze(task);
#else
	return ((task->jobctl & JOBCTL_TRAP_FREEZE) != 0);
#endif
}

bool line_is_frozen(struct task_struct *task)
{
	if (cgroup_task_frozen(task) || rekernel_x_is_jobctl_frozen_compatible(task))
		return true;

	/* if task->group_leader is NULL, unfreeze it to avoid some unknown problems */
	if (NULL == task->group_leader)
		return true;

	return rekernel_x_is_frozen_state_compatible(task->group_leader) || freezing(task->group_leader);
}
