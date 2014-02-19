/*
 * include/linux/wakeup_reason.h
 *
 * Logs the reason which caused the kernel to resume
 * from the suspend mode.
 *
 */

#ifndef _LINUX_WAKEUP_REASON_H
#define _LINUX_WAKEUP_REASON_H

#include <linux/kernel.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/notifier.h>
#include <linux/suspend.h>

void log_wakeup_reason(int irq);

#endif /*__WAKEUP_REASON__ */
