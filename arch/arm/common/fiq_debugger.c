/*
 * arch/arm/common/fiq_debugger.c
 *
 * Serial Debugger Interface accessed through an FIQ interrupt.
 *
 * Copyright (C) 2008 Google, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <stdarg.h>
#include <linux/module.h>
#include <linux/io.h>
#include <linux/console.h>
#include <linux/interrupt.h>
#include <linux/clk.h>
#include <linux/platform_device.h>
#include <linux/kernel_debugger.h>
#include <linux/kernel_stat.h>
#include <linux/irq.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/wakelock.h>

#include <asm/stacktrace.h>

#include <asm/hardware/fiq_debugger.h>
#include <mach/system.h>
#include <mach/fiq.h>

#include <linux/uaccess.h>

static void sleep_timer_expired(unsigned long);

static bool ignore_next_wakeup_irq;
#ifdef CONFIG_FIQ_DEBUGGER_NO_SLEEP
static int no_sleep = true;
#else
static int no_sleep;
#endif
static DEFINE_TIMER(sleep_timer, sleep_timer_expired, 0, 0);
static int debug_enable;
static int debugger_enable;
static struct wake_lock debugger_wake_lock;
static bool uart_clk_enabled;

static const struct fiq_debugger *init_data;

module_param(no_sleep, bool, 0644);

#ifdef CONFIG_FIQ_DEBUGGER_WAKEUP_IRQ_ALWAYS_ON
static inline void enable_wakeup_irq(unsigned int irq) {}
static inline void disable_wakeup_irq(unsigned int irq) {}
#else
static inline void enable_wakeup_irq(unsigned int irq)
{
	enable_irq(irq);
}
static inline void disable_wakeup_irq(unsigned int irq)
{
	disable_irq_nosync(irq);
}
#endif

static void debug_puts(char *s)
{
	unsigned c;
	while ((c = *s++)) {
		if (c == '\n')
			init_data->uart_putc('\r');
		init_data->uart_putc(c);
	}
}

static void debug_prompt(void)
{
	debug_puts("debug> ");
}

int log_buf_copy(char *dest, int idx, int len);
static void dump_kernel_log(void)
{
	char buf[1024];
	int idx = 0;
	int ret;
	int saved_oip;

	/* setting oops_in_progress prevents log_buf_copy()
	 * from trying to take a spinlock which will make it
	 * very unhappy in some cases...
	 */
	saved_oip = oops_in_progress;
	oops_in_progress = 1;
	for (;;) {
		ret = log_buf_copy(buf, idx, 1023);
		if (ret <= 0)
			break;
		buf[ret] = 0;
		debug_puts(buf);
		idx += ret;
	}
	oops_in_progress = saved_oip;
}

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

#define DEBUG_MAX 64
static char debug_cmd[DEBUG_MAX];
static int debug_busy;
static int debug_abort;

static int debug_printf(void *cookie, const char *fmt, ...)
{
	char buf[256];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	debug_puts(buf);
	return debug_abort;
}

/* Safe outside fiq context */
static int debug_printf_nfiq(void *cookie, const char *fmt, ...)
{
	char buf[256];
	va_list ap;
	unsigned long irq_flags;

	va_start(ap, fmt);
	vsnprintf(buf, 128, fmt, ap);
	va_end(ap);

	local_irq_save(irq_flags);
	debug_puts(buf);
	init_data->uart_flush();
	local_irq_restore(irq_flags);
	return debug_abort;
}

#define dprintf(fmt...) debug_printf(0, fmt)

unsigned int last_irqs[NR_IRQS];

static void dump_regs(unsigned *regs)
{
	dprintf(" r0 %08x  r1 %08x  r2 %08x  r3 %08x\n",
		regs[0], regs[1], regs[2], regs[3]);
	dprintf(" r4 %08x  r5 %08x  r6 %08x  r7 %08x\n",
		regs[4], regs[5], regs[6], regs[7]);
	dprintf(" r8 %08x  r9 %08x r10 %08x r11 %08x  mode %s\n",
		regs[8], regs[9], regs[10], regs[11],
		mode_name(regs[16]));
	if ((regs[16] & MODE_MASK) == USR_MODE)
		dprintf(" ip %08x  sp %08x  lr %08x  pc %08x  cpsr %08x\n",
			regs[12], regs[13], regs[14], regs[15], regs[16]);
	else
		dprintf(" ip %08x  sp %08x  lr %08x  pc %08x  cpsr %08x  "
			"spsr %08x\n", regs[12], regs[13], regs[14], regs[15],
			regs[16], regs[17]);
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

void __naked get_mode_regs(struct mode_regs *regs)
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


static void dump_allregs(unsigned *regs)
{
	struct mode_regs mode_regs;
	dump_regs(regs);
	get_mode_regs(&mode_regs);
	dprintf(" svc: sp %08x  lr %08x  spsr %08x\n",
		mode_regs.sp_svc, mode_regs.lr_svc, mode_regs.spsr_svc);
	dprintf(" abt: sp %08x  lr %08x  spsr %08x\n",
		mode_regs.sp_abt, mode_regs.lr_abt, mode_regs.spsr_abt);
	dprintf(" und: sp %08x  lr %08x  spsr %08x\n",
		mode_regs.sp_und, mode_regs.lr_und, mode_regs.spsr_und);
	dprintf(" irq: sp %08x  lr %08x  spsr %08x\n",
		mode_regs.sp_irq, mode_regs.lr_irq, mode_regs.spsr_irq);
	dprintf(" fiq: r8 %08x  r9 %08x  r10 %08x  r11 %08x  r12 %08x\n",
		mode_regs.r8_fiq, mode_regs.r9_fiq, mode_regs.r10_fiq,
		mode_regs.r11_fiq, mode_regs.r12_fiq);
	dprintf(" fiq: sp %08x  lr %08x  spsr %08x\n",
		mode_regs.sp_fiq, mode_regs.lr_fiq, mode_regs.spsr_fiq);
}

static void dump_irqs(void)
{
	int n;
	dprintf("irqnr       total  since-last   status  name\n");
	for (n = 1; n < NR_IRQS; n++) {
		struct irqaction *act = irq_desc[n].action;
		if (!act && !kstat_irqs(n))
			continue;
		dprintf("%5d: %10u %11u %8x  %s\n", n,
			kstat_irqs(n),
			kstat_irqs(n) - last_irqs[n],
			irq_desc[n].status,
			(act && act->name) ? act->name : "???");
		last_irqs[n] = kstat_irqs(n);
	}
}

static int report_trace(struct stackframe *frame, void *d)
{
	unsigned int *depth = d;

	if (*depth) {
		dprintf("  pc: %p (%pF), lr %p (%pF), sp %p, fp %p\n",
			frame->pc, frame->pc, frame->lr, frame->lr,
			frame->sp, frame->fp);
		(*depth)--;
		return 0;
	}
	dprintf("  ...\n");

	return *depth == 0;
}

struct frame_tail {
	struct frame_tail *fp;
	unsigned long sp;
	unsigned long lr;
} __attribute__((packed));

static struct frame_tail *user_backtrace(struct frame_tail *tail)
{
	struct frame_tail buftail[2];

	/* Also check accessibility of one struct frame_tail beyond */
	if (!access_ok(VERIFY_READ, tail, sizeof(buftail))) {
		dprintf("  invalid frame pointer %p\n", tail);
		return NULL;
	}
	if (__copy_from_user_inatomic(buftail, tail, sizeof(buftail))) {
		dprintf("  failed to copy frame pointer %p\n", tail);
		return NULL;
	}

	dprintf("  %p\n", buftail[0].lr);

	/* frame pointers should strictly progress back up the stack
	 * (towards higher addresses) */
	if (tail >= buftail[0].fp)
		return NULL;

	return buftail[0].fp-1;
}

void dump_stacktrace(struct pt_regs * const regs, unsigned int depth, void *ssp)
{
	struct frame_tail *tail;
	struct thread_info *real_thread_info = (struct thread_info *)
				((unsigned long)ssp & ~(THREAD_SIZE - 1));

	*current_thread_info() = *real_thread_info;

	if (!current)
		dprintf("current NULL\n");
	else
		dprintf("pid: %d  comm: %s\n", current->pid, current->comm);
	dump_regs((unsigned *)regs);

	if (!user_mode(regs)) {
		struct stackframe frame;
		frame.fp = regs->ARM_fp;
		frame.sp = regs->ARM_sp;
		frame.lr = regs->ARM_lr;
		frame.pc = regs->ARM_pc;
		dprintf("  pc: %p (%pF), lr %p (%pF), sp %p, fp %p\n",
			regs->ARM_pc, regs->ARM_pc, regs->ARM_lr, regs->ARM_lr,
			regs->ARM_sp, regs->ARM_fp);
		walk_stackframe(&frame, report_trace, &depth);
		return;
	}

	tail = ((struct frame_tail *) regs->ARM_fp) - 1;
	while (depth-- && tail && !((unsigned long) tail & 3))
		tail = user_backtrace(tail);
}

static void debug_exec(const char *cmd, unsigned *regs, void *svc_sp)
{
	if (!strcmp(cmd, "pc")) {
		dprintf(" pc %08x cpsr %08x mode %s\n",
			regs[15], regs[16], mode_name(regs[16]));
	} else if (!strcmp(cmd, "regs")) {
		dump_regs(regs);
	} else if (!strcmp(cmd, "allregs")) {
		dump_allregs(regs);
	} else if (!strcmp(cmd, "bt")) {
		dump_stacktrace((struct pt_regs *)regs, 100, svc_sp);
	} else if (!strcmp(cmd, "reboot")) {
		arch_reset(0, 0);
	} else if (!strcmp(cmd, "irqs")) {
		dump_irqs();
	} else if (!strcmp(cmd, "kmsg")) {
		dump_kernel_log();
	} else if (!strcmp(cmd, "version")) {
		dprintf("%s\n", linux_banner);
	} else if (!strcmp(cmd, "sleep")) {
		no_sleep = false;
	} else if (!strcmp(cmd, "nosleep")) {
		no_sleep = true;
	} else {
		if (debug_busy) {
			dprintf("command processor busy. trying to abort.\n");
			debug_abort = -1;
		} else {
			strcpy(debug_cmd, cmd);
			debug_busy = 1;
		}

		init_data->force_irq(init_data->signal_irq);

		return;
	}
	debug_prompt();
}

static void sleep_timer_expired(unsigned long data)
{
	if (uart_clk_enabled && !no_sleep) {
		if (debug_enable) {
			debug_enable = 0;
			debug_printf_nfiq(NULL,
					"suspending fiq debugger\n");
		}
		ignore_next_wakeup_irq = true;
		clk_disable(init_data->uart_clk);
		uart_clk_enabled = false;
		enable_wakeup_irq(init_data->wakeup_irq);
		set_irq_wake(init_data->wakeup_irq, 1);
	}
	wake_unlock(&debugger_wake_lock);
}

static irqreturn_t wakeup_irq_handler(int irq, void *dev)
{
	debug_puts("WAKEUP\n");
	if (ignore_next_wakeup_irq)
		ignore_next_wakeup_irq = false;
	else if (!uart_clk_enabled) {
		wake_lock(&debugger_wake_lock);
		clk_enable(init_data->uart_clk);
		uart_clk_enabled = true;
		set_irq_wake(irq, 0);
		disable_wakeup_irq(irq);
		mod_timer(&sleep_timer, jiffies + HZ / 2);
	}
	return IRQ_HANDLED;
}

static irqreturn_t debug_irq(int irq, void *dev)
{
	if (init_data->force_irq_ack)
		init_data->force_irq_ack(init_data->signal_irq);

	if (!no_sleep) {
		wake_lock(&debugger_wake_lock);
		mod_timer(&sleep_timer, jiffies + HZ * 5);
	}
	if (debug_busy) {
		struct kdbg_ctxt ctxt;

		ctxt.printf = debug_printf_nfiq;
		kernel_debugger(&ctxt, debug_cmd);
		debug_prompt();

		debug_busy = 0;
	}
	return IRQ_HANDLED;
}

static char debug_buf[DEBUG_MAX];
static int debug_count;

static void debug_fiq(void *data, void *regs, void *svc_sp)
{
	int c;
	static int last_c;
	int count = 0;

	while ((c = init_data->uart_getc()) != -1) {
		count++;
		if (!debug_enable) {
			if ((c == 13) || (c == 10)) {
				debug_enable = true;
				debug_count = 0;
				debug_prompt();
			}
		} else if ((c >= ' ') && (c < 127)) {
			if (debug_count < (DEBUG_MAX - 1)) {
				debug_buf[debug_count++] = c;
				init_data->uart_putc(c);
			}
		} else if ((c == 8) || (c == 127)) {
			if (debug_count > 0) {
				debug_count--;
				init_data->uart_putc(8);
				init_data->uart_putc(' ');
				init_data->uart_putc(8);
			}
		} else if ((c == 13) || (c == 10)) {
			if (c == '\r' || (c == '\n' && last_c != '\r')) {
				init_data->uart_putc('\r');
				init_data->uart_putc('\n');
			}
			if (debug_count) {
				debug_buf[debug_count] = 0;
				debug_count = 0;
				debug_exec(debug_buf, regs, svc_sp);
			} else {
				debug_prompt();
			}
		}
		last_c = c;
	}
	init_data->uart_flush();

	/* poke sleep timer if necessary */
	if (debug_enable && !no_sleep)
		init_data->force_irq(init_data->signal_irq);
}

#if defined(CONFIG_FIQ_DEBUGGER_CONSOLE)
static void debug_console_write(struct console *co,
				const char *s, unsigned int count)
{
	unsigned long irq_flags;

	/* disable irq's while TXing outside of FIQ context */
	local_irq_save(irq_flags);
	while (count--) {
		if (*s == '\n')
			init_data->uart_putc('\r');
		init_data->uart_putc(*s++);
	}
	init_data->uart_flush();
	local_irq_restore(irq_flags);
}

static struct console fiq_debugger_console = {
	.name = "debug_console",
	.write = debug_console_write,
	.flags = CON_PRINTBUFFER | CON_ANYTIME | CON_ENABLED,
};
#endif

void fiq_debugger_enable(int enable)
{
	debug_enable = enable;
}

void fiq_debugger_init(const struct fiq_debugger *config)
{
	int ret;

	init_data = config;

	if (!init_data->uart_clk ||
			!init_data->uart_init ||
			!init_data->uart_getc ||
			!init_data->uart_putc ||
			!init_data->uart_flush ||
			!init_data->fiq_set_handler ||
			!init_data->fiq_enable ||
			!init_data->force_irq ||
			!init_data->force_irq_ack)
		return;

	wake_lock_init(&debugger_wake_lock, WAKE_LOCK_SUSPEND, "serial-debug");

	clk_enable(init_data->uart_clk);

	init_data->uart_init();

	debug_printf_nfiq(NULL, "<hit enter %sto activate fiq debugger>\n",
				no_sleep ? "" : "twice ");
	ignore_next_wakeup_irq = !no_sleep;

	init_data->fiq_set_handler(init_data->fiq_irq, debug_fiq, 0);
	init_data->fiq_enable(init_data->fiq_irq, 1);

	clk_disable(init_data->uart_clk);

	ret = request_irq(init_data->signal_irq, debug_irq,
			  IRQF_TRIGGER_RISING, "debug", 0);
	if (ret)
		dprintf("serial_debugger: could not install signal_irq");

	ret = set_irq_wake(init_data->wakeup_irq, 1);
	if (ret)
		dprintf("serial_debugger: could not enable wakeup\n");
	ret = request_irq(init_data->wakeup_irq, wakeup_irq_handler,
			  IRQF_TRIGGER_FALLING | IRQF_DISABLED,
			  "debug-wakeup", 0);
	if (ret)
		dprintf("serial_debugger: could not install wakeup irq\n");
	if (no_sleep)
		wakeup_irq_handler(init_data->wakeup_irq, 0);

#if defined(CONFIG_FIQ_DEBUGGER_CONSOLE)
	register_console(&fiq_debugger_console);
	clk_enable(init_data->uart_clk);
#endif
	debugger_enable = 1;
}

static int fiq_debugger_remove(const char *val, struct kernel_param *kp)
{
	int ret;
	static int pre_stat = 1;
	ret = param_set_bool(val, kp);
	if (ret)
		return ret;

	if (pre_stat == *(int *)kp->arg)
		return 0;

	pre_stat = *(int *)kp->arg;

	if (*(int *)kp->arg) {
		fiq_debugger_init(init_data);
		printk(KERN_INFO "enable FIQ serial debugger\n");
		return 0;
	}

#if defined(CONFIG_FIQ_DEBUGGER_CONSOLE)
	unregister_console(&fiq_debugger_console);
	clk_disable(init_data->uart_clk);
#endif
	free_irq(init_data->wakeup_irq, 0);
	free_irq(init_data->signal_irq, 0);
	init_data->fiq_enable(init_data->fiq_irq, 0);
	if (uart_clk_enabled)
		clk_disable(init_data->uart_clk);
	wake_lock_destroy(&debugger_wake_lock);
	printk(KERN_INFO "disable FIQ serial debugger\n");
	return 0;
}
module_param_call(enable, fiq_debugger_remove, param_get_bool,
		&debugger_enable, S_IWUSR | S_IRUGO);
