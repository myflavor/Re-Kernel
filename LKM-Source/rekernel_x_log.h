#ifndef REKERNEL_X_LOG_H
#define REKERNEL_X_LOG_H

/* Include this header FIRST in each .c — pr_fmt must be defined before printk.h. */
#define pr_fmt(fmt) "[ReKernel-X LKM] " fmt
#include <linux/printk.h>

#define rekernel_x_info_log(fmt, ...)  pr_info(fmt, ##__VA_ARGS__)
#define rekernel_x_err_log(fmt, ...)   pr_err(fmt, ##__VA_ARGS__)
#define rekernel_x_warn_log(fmt, ...)  pr_warn(fmt, ##__VA_ARGS__)

#ifdef REKERNEL_X_DEBUG
#define rekernel_x_debug_log(fmt, ...)  pr_info(fmt, ##__VA_ARGS__)
#else
#define rekernel_x_debug_log(fmt, ...)  no_printk(fmt, ##__VA_ARGS__)
#endif

#endif /* REKERNEL_X_LOG_H */
