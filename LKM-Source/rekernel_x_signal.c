/*
 * Copyright (c) Sakion Team. All rights reserved.
 * Copyright (c) myflavor <admin@myflv.cn>.
 *
 * File name: rekernel_x_signal.c
 * Description: ReKernel-X signal trace hook — fatal signals sent to frozen tasks.
 * Author: nep_timeline@outlook.com, myflavor <admin@myflv.cn>
 */
#include "rekernel_x_log.h"
#include "rekernel_x.h"
#include <linux/printk.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <trace/hooks/signal.h>

static bool re_signal_hook;

void line_signal(void *data, int sig, struct task_struct *killer, struct task_struct *dst)
{
	if (!dst || !killer)
		return;

	if (line_is_frozen(dst) &&
			(sig == SIGKILL
			|| sig == SIGTERM
			|| sig == SIGABRT
			|| sig == SIGQUIT)) {
		rekernel_x_debug_log("Process Signal! signal=%d\n", sig);
		if (rekernel_x_netlink_ready()) {
			struct rekernel_x_event event = {
				.type = REKERNEL_X_EVT_SIGNAL,
				.u.signal = {
					.signal = sig,
					.killer_pid = task_tgid_nr(killer),
					.killer_uid = task_uid(killer).val,
					.dst_pid = task_tgid_nr(dst),
					.dst_uid = task_uid(dst).val,
				},
			};
			sendMessage(&event);
		}
	}
}

int register_signal(void)
{
	int rc = LINE_SUCCESS;

	rc = register_trace_android_vh_do_send_sig_info(line_signal, NULL);
	if (rc != LINE_SUCCESS) {
		rekernel_x_err_log("register_trace_android_vh_do_send_sig_info failed, rc=%d\n", rc);
		return rc;
	}
	re_signal_hook = true;
	return LINE_SUCCESS;
}

void unregister_signal(void)
{
	if (re_signal_hook) {
		unregister_trace_android_vh_do_send_sig_info(line_signal, NULL);
		re_signal_hook = false;
	}
}
