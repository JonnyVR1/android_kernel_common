/*
 * Copyright (C) 2014 Google, Inc.
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

#include <linux/ptrace.h>
#include <linux/uaccess.h>

#include <asm/stacktrace.h>

#include "fiq_debugger_priv.h"

static char *mode_name(unsigned cpsr)
{
	switch (cpsr & MODE_MASK) {
	case USR_MODE: return "USR";
	case FIQ_MODE: return "FIQ";
	case IRQ_MODE: return "IRQ";
	case SVC_MODE: return "SVC";
	case ABT_MODE: return "ABT";
	case UND_MODE: return "UND";
	case SYSTEM_MODE: return "SYS";
	default: return "???";
	}
}

void dump_pc(struct fiq_debugger_state *state, unsigned *regs)
{
	debug_printf(state, " pc %08x cpsr %08x mode %s\n",
		regs[15], regs[16], mode_name(regs[16]));
}

void dump_regs(struct fiq_debugger_state *state, unsigned *regs)
{
	debug_printf(state, " r0 %08x  r1 %08x  r2 %08x  r3 %08x\n",
			regs[0], regs[1], regs[2], regs[3]);
	debug_printf(state, " r4 %08x  r5 %08x  r6 %08x  r7 %08x\n",
			regs[4], regs[5], regs[6], regs[7]);
	debug_printf(state, " r8 %08x  r9 %08x r10 %08x r11 %08x  mode %s\n",
			regs[8], regs[9], regs[10], regs[11],
			mode_name(regs[16]));
	if ((regs[16] & MODE_MASK) == USR_MODE)
		debug_printf(state, " ip %08x  sp %08x  lr %08x  pc %08x  "
				"cpsr %08x\n", regs[12], regs[13], regs[14],
				regs[15], regs[16]);
	else
		debug_printf(state, " ip %08x  sp %08x  lr %08x  pc %08x  "
				"cpsr %08x  spsr %08x\n", regs[12], regs[13],
				regs[14], regs[15], regs[16], regs[17]);
}

struct mode_regs {
	unsigned long sp_svc;
	unsigned long lr_svc;
	unsigned long spsr_svc;

	unsigned long sp_abt;
	unsigned long lr_abt;
	unsigned long spsr_abt;

	unsigned long sp_und;
	unsigned long lr_und;
	unsigned long spsr_und;

	unsigned long sp_irq;
	unsigned long lr_irq;
	unsigned long spsr_irq;

	unsigned long r8_fiq;
	unsigned long r9_fiq;
	unsigned long r10_fiq;
	unsigned long r11_fiq;
	unsigned long r12_fiq;
	unsigned long sp_fiq;
	unsigned long lr_fiq;
	unsigned long spsr_fiq;
};

static void __naked get_mode_regs(struct mode_regs *regs)
{
	asm volatile (
	"mrs	r1, cpsr\n"
	"msr	cpsr_c, #0xd3 @(SVC_MODE | PSR_I_BIT | PSR_F_BIT)\n"
	"stmia	r0!, {r13 - r14}\n"
	"mrs	r2, spsr\n"
	"msr	cpsr_c, #0xd7 @(ABT_MODE | PSR_I_BIT | PSR_F_BIT)\n"
	"stmia	r0!, {r2, r13 - r14}\n"
	"mrs	r2, spsr\n"
	"msr	cpsr_c, #0xdb @(UND_MODE | PSR_I_BIT | PSR_F_BIT)\n"
	"stmia	r0!, {r2, r13 - r14}\n"
	"mrs	r2, spsr\n"
	"msr	cpsr_c, #0xd2 @(IRQ_MODE | PSR_I_BIT | PSR_F_BIT)\n"
	"stmia	r0!, {r2, r13 - r14}\n"
	"mrs	r2, spsr\n"
	"msr	cpsr_c, #0xd1 @(FIQ_MODE | PSR_I_BIT | PSR_F_BIT)\n"
	"stmia	r0!, {r2, r8 - r14}\n"
	"mrs	r2, spsr\n"
	"stmia	r0!, {r2}\n"
	"msr	cpsr_c, r1\n"
	"bx	lr\n");
}


void dump_allregs(struct fiq_debugger_state *state, unsigned *regs)
{
	struct mode_regs mode_regs;
	dump_regs(state, regs);
	get_mode_regs(&mode_regs);
	debug_printf(state, " svc: sp %08x  lr %08x  spsr %08x\n",
			mode_regs.sp_svc, mode_regs.lr_svc, mode_regs.spsr_svc);
	debug_printf(state, " abt: sp %08x  lr %08x  spsr %08x\n",
			mode_regs.sp_abt, mode_regs.lr_abt, mode_regs.spsr_abt);
	debug_printf(state, " und: sp %08x  lr %08x  spsr %08x\n",
			mode_regs.sp_und, mode_regs.lr_und, mode_regs.spsr_und);
	debug_printf(state, " irq: sp %08x  lr %08x  spsr %08x\n",
			mode_regs.sp_irq, mode_regs.lr_irq, mode_regs.spsr_irq);
	debug_printf(state, " fiq: r8 %08x  r9 %08x  r10 %08x  r11 %08x  "
			"r12 %08x\n",
			mode_regs.r8_fiq, mode_regs.r9_fiq, mode_regs.r10_fiq,
			mode_regs.r11_fiq, mode_regs.r12_fiq);
	debug_printf(state, " fiq: sp %08x  lr %08x  spsr %08x\n",
			mode_regs.sp_fiq, mode_regs.lr_fiq, mode_regs.spsr_fiq);
}

struct stacktrace_state {
	struct fiq_debugger_state *state;
	unsigned int depth;
};

static int report_trace(struct stackframe *frame, void *d)
{
	struct stacktrace_state *sts = d;

	if (sts->depth) {
		debug_printf(sts->state,
			"  pc: %p (%pF), lr %p (%pF), sp %p, fp %p\n",
			frame->pc, frame->pc, frame->lr, frame->lr,
			frame->sp, frame->fp);
		sts->depth--;
		return 0;
	}
	debug_printf(sts->state, "  ...\n");

	return sts->depth == 0;
}

struct frame_tail {
	struct frame_tail *fp;
	unsigned long sp;
	unsigned long lr;
} __attribute__((packed));

static struct frame_tail *user_backtrace(struct fiq_debugger_state *state,
					struct frame_tail *tail)
{
	struct frame_tail buftail[2];

	/* Also check accessibility of one struct frame_tail beyond */
	if (!access_ok(VERIFY_READ, tail, sizeof(buftail))) {
		debug_printf(state, "  invalid frame pointer %p\n", tail);
		return NULL;
	}
	if (__copy_from_user_inatomic(buftail, tail, sizeof(buftail))) {
		debug_printf(state,
			"  failed to copy frame pointer %p\n", tail);
		return NULL;
	}

	debug_printf(state, "  %p\n", buftail[0].lr);

	/* frame pointers should strictly progress back up the stack
	 * (towards higher addresses) */
	if (tail >= buftail[0].fp)
		return NULL;

	return buftail[0].fp-1;
}

void dump_stacktrace(struct fiq_debugger_state *state,
		struct pt_regs * const regs, unsigned int depth, void *ssp)
{
	struct frame_tail *tail;
	struct thread_info *real_thread_info = THREAD_INFO(ssp);
	struct stacktrace_state sts;

	sts.depth = depth;
	sts.state = state;
	*current_thread_info() = *real_thread_info;

	if (!current)
		debug_printf(state, "current NULL\n");
	else
		debug_printf(state, "pid: %d  comm: %s\n",
			current->pid, current->comm);
	dump_regs(state, (unsigned *)regs);

	if (!user_mode(regs)) {
		struct stackframe frame;
		frame.fp = regs->ARM_fp;
		frame.sp = regs->ARM_sp;
		frame.lr = regs->ARM_lr;
		frame.pc = regs->ARM_pc;
		debug_printf(state,
			"  pc: %p (%pF), lr %p (%pF), sp %p, fp %p\n",
			regs->ARM_pc, regs->ARM_pc, regs->ARM_lr, regs->ARM_lr,
			regs->ARM_sp, regs->ARM_fp);
		walk_stackframe(&frame, report_trace, &sts);
		return;
	}

	tail = ((struct frame_tail *) regs->ARM_fp) - 1;
	while (depth-- && tail && !((unsigned long) tail & 3))
		tail = user_backtrace(state, tail);
}
