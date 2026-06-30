/*
 * Copyright (c) Sakion Team. All rights reserved.
 * Copyright (c) myflavor <admin@myflv.cn>.
 *
 * File name: rekernel_x_main.c
 * Description: ReKernel-X module entry — init/exit glue wiring the genl
 *              transport and the binder/signal/netfilter/kprobe hooks.
 * Author: nep_timeline@outlook.com, myflavor <admin@myflv.cn>
 */
#include "rekernel_x_log.h"
#include "rekernel_x.h"
#include <linux/printk.h>
#include <linux/module.h>
#include <linux/init.h>

static int __init start_rekernel(void)
{
	rekernel_x_info_log("starting...\n");
	rekernel_x_debug_log("Debug mode is enabled!\n");
	rekernel_x_info_log("Version %s | Fork by myflavor | Upstream: Sakion Team\n", REKERNEL_X_VERSION);

	if (register_genl() != LINE_SUCCESS) {
		rekernel_x_err_log("%s: Failed to register genl family!\n", __func__);
		return LINE_ERROR;
	}

	rekernel_x_info_log("start hooking!\n");

	if (register_binder() != LINE_SUCCESS) {
		rekernel_x_err_log("%s: Failed to hook binder!\n", __func__);
		goto err;
	}

	if (register_signal() != LINE_SUCCESS) {
		rekernel_x_err_log("%s: Failed to hook signal!\n", __func__);
		goto err;
	}

	if (register_netfilter() != LINE_SUCCESS) {
		rekernel_x_err_log("%s: Failed to hook netfilter!\n", __func__);
		goto err;
	}

#ifdef CLEAN_UP_ASYNC_BINDER
	register_binder_kp();
#endif

	rekernel_x_info_log("hooked!\n");
	return LINE_SUCCESS;

err:
	unregister_binder_kp();
	unregister_netfilter();
	unregister_signal();
	unregister_binder();
	unregister_genl();
	return LINE_ERROR;
}

static void __exit exit_rekernel(void)
{
	rekernel_x_info_log("closing...\n");
	unregister_binder_kp();
	unregister_netfilter();
	unregister_signal();
	unregister_binder();
	unregister_genl();
}

module_init(start_rekernel);
module_exit(exit_rekernel);

MODULE_LICENSE("GPL");
