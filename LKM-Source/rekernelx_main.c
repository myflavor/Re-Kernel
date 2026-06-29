/*
 * Copyright (c) Sakion Team. All rights reserved.
 *
 * File name: main.c
 * Description: rekernel module entry — init/exit glue wiring the genl
 *              transport and the binder/signal/netfilter/kprobe hooks.
 * Author: nep_timeline@outlook.com
 */
#include <linux/printk.h>
#include <linux/module.h>
#include <linux/init.h>
#include "rekernel.h"

static int __init start_rekernel(void)
{
	pr_info("Thank you for choosing ReKernel-X!\n");
#ifdef DEBUG
	pr_info("Debug mode is enabled!\n");
#endif
	pr_info("ReKernel-X %s | DEVELOPER: Sakion Team | GENL FAMILY: %s\n", REKERNELX_VERSION, REKERNELX_GENL_FAMILY_NAME);

	if (register_genl() != LINE_SUCCESS) {
		pr_err("%s: Failed to register genl family!\n", __func__);
		return LINE_ERROR;
	}

	pr_info("ReKernel-X start hooking!\n");

	if (register_binder() != LINE_SUCCESS) {
		pr_err("%s: Failed to hook binder!\n", __func__);
		return LINE_ERROR;
	}

	if (register_signal() != LINE_SUCCESS) {
		pr_err("%s: Failed to hook signal!\n", __func__);
		return LINE_ERROR;
	}

	if (register_netfilter() != LINE_SUCCESS) {
		pr_err("%s: Failed to hook netfilter!\n", __func__);
		return LINE_ERROR;
	}

#ifdef CLEAN_UP_ASYNC_BINDER
	if (register_kp() != LINE_SUCCESS) {
		pr_err("%s: Failed to hook kprobe!\n", __func__);
		return LINE_ERROR;
	}
#endif

	pr_info("ReKernel-X hooked!\n");
	return LINE_SUCCESS;
}

static void __exit exit_rekernel(void)
{
	pr_info("ReKernel-X closing...\n");
	unregister_binder();
	unregister_signal();
	unregister_netfilter();
	unregister_kp();
	unregister_genl();
}

module_init(start_rekernel);
module_exit(exit_rekernel);

MODULE_LICENSE("GPL");
