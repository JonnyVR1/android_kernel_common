/*
 * arch/arm/include/asm/hardware/fiq_debugger.h
 *
 * Copyright (C) 2010 Google, Inc.
 * Author: Colin Cross <ccross@android.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef _ARCH_ARM_MACH_TEGRA_FIQ_DEBUGGER_H_
#define _ARCH_ARM_MACH_TEGRA_FIQ_DEBUGGER_H_

struct fiq_debugger {
	unsigned int base;
	struct clk *uart_clk;
	int fiq_irq;
	int signal_irq;
	int wakeup_irq;

	void (*uart_init)(void);
	int (*uart_getc)(void);
	void (*uart_putc)(unsigned int c);
	void (*uart_flush)(void);

	void (*fiq_set_handler)(unsigned int irq, void (*handler)(
					void *data, void *regs, void *svc_sp),
				void *data);
	void (*fiq_enable)(unsigned int, bool);

	void (*force_irq)(unsigned int);
	void (*force_irq_ack)(unsigned int);
};

void fiq_debugger_init(const struct fiq_debugger *config);
void fiq_debugger_enable(int enable);

#endif
