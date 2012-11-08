#include <linux/export.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/stacktrace.h>

#include <asm/stacktrace.h>

#define STACK_MAX(sp) (round_down(sp, THREAD_SIZE) + THREAD_START_SP)

/**
 * sp_addr_valid - verify a stack pointer
 * @sp: current stack pointer
 *
 * Returns true if sp is a pointer inside a memory area that could be a stack.
 * Does not verify that sp is inside an actual stack (i.e. does not check for
 * STACK_MAGIC).
 *
 * If sp_addr_valid(sp) returns true, then the kernel will not fault if it
 * accesses memory in the range
 * [sp, round_down(sp, THREAD_SIZE) + THREAD_START_SP)
 */
bool sp_addr_valid(unsigned long sp)
{
	unsigned long high;
	unsigned int pfn;
	unsigned int start_pfn;
	unsigned int end_pfn;

	if (!IS_ALIGNED(sp, 4))
		return false;

	if ((sp & (THREAD_SIZE - 1)) > THREAD_START_SP)
		return false;

	if ((sp & (THREAD_SIZE - 1)) < sizeof(struct thread_info))
		return false;

	high = STACK_MAX(sp);

	if (!virt_addr_valid(sp) || !virt_addr_valid(high))
		return false;

	start_pfn = page_to_pfn(virt_to_page(sp));
	end_pfn = page_to_pfn(virt_to_page(high));
	for (pfn = start_pfn; pfn <= end_pfn; pfn++)
		if (!pfn_valid(pfn))
			return false;

	return true;
}

/**
 * addr_in_stack - verify a pointer is inside a specified stack
 * @orig_sp: stack pointer at the bottom of the stack
 * @sp: address to be verified
 *
 * Returns true if sp is in the stack bounded at the bottom by orig_sp, in the
 * range [orig_sp, round_down(orig_sp, THREAD_SIZE) + THREAD_START_SP)
 *
 * If orig_sp is valid (see sp_addr_valid), then the kernel will not fault if it
 * accesses a pointer where ptr_in_stack returns true.
 */
bool addr_in_stack(unsigned long orig_sp, unsigned long sp)
{
	return (sp >= orig_sp && sp < STACK_MAX(orig_sp) && IS_ALIGNED(sp, 4));
}

/**
 * sp_in_stack - verify a stack pointer is inside a specified stack
 * @orig_sp: stack pointer at the bottom of the stack
 * @sp: stack pointer to be verified
 *
 * Returns true if sp is in the stack bounded at the bottom by orig_sp, in the
 * range [orig_sp, round_down(orig_sp, THREAD_SIZE) + THREAD_START_SP]
 *
 * If sp_in_stack returns true,
 * addr_in_stack(vsp, x) == addr_in_stack(orig_sp, x)
 */
bool sp_in_stack(unsigned long orig_sp, unsigned long sp)
{
	return (sp >= orig_sp && sp <= STACK_MAX(orig_sp) && IS_ALIGNED(sp, 4));
}


#if defined(CONFIG_FRAME_POINTER) && !defined(CONFIG_ARM_UNWIND)
/*
 * Unwind the current stack frame and store the new register values in the
 * structure passed as argument. Unwinding is equivalent to a function return,
 * hence the new PC value rather than LR should be used for backtrace.
 *
 * With framepointer enabled, a simple function prologue looks like this:
 *	mov	ip, sp
 *	stmdb	sp!, {fp, ip, lr, pc}
 *	sub	fp, ip, #4
 *
 * A simple function epilogue looks like this:
 *	ldm	sp, {fp, sp, pc}
 *
 * Note that with framepointer enabled, even the leaf functions have the same
 * prologue and epilogue, therefore we can ignore the LR value in this case.
 */
int notrace unwind_frame(struct stackframe *frame, int depth)
{
	unsigned long fp = frame->fp;
	unsigned long sp = frame->sp;

	if (!sp_addr_valid(sp))
		return -EINVAL;

	/* Check current frame pointer is within the stack bounds. */
	if (!addr_in_stack(sp, fp))
		return -EINVAL;

	if (fp < 12 || !addr_in_stack(sp, fp - 12))
		return -EINVAL;

	/* restore the registers from the stack frame */
	frame->fp = *(unsigned long *)(fp - 12);
	frame->sp = *(unsigned long *)(fp - 8);
	frame->pc = *(unsigned long *)(fp - 4);

	/* Ensure the next stack pointer is in the same stack */
	if (!sp_in_stack(sp, frame->sp))
		return -EINVAL;

	/*
	 * Ensure the next stack pointer is above this frame to guarantee
	 * bounded execution.
	 */
	if (frame->sp < fp)
		return -EINVAL;

	return 0;
}
#endif

void notrace walk_stackframe(struct stackframe *frame,
		     int (*fn)(struct stackframe *, void *), void *data)
{
	int depth = 0;

	while (1) {
		int ret;

		if (fn(frame, data))
			break;
		ret = unwind_frame(frame, depth++);
		if (ret < 0)
			break;
	}
}
EXPORT_SYMBOL(walk_stackframe);

#ifdef CONFIG_STACKTRACE
struct stack_trace_data {
	struct stack_trace *trace;
	unsigned int no_sched_functions;
	unsigned int skip;
};

static int save_trace(struct stackframe *frame, void *d)
{
	struct stack_trace_data *data = d;
	struct stack_trace *trace = data->trace;
	unsigned long addr = frame->pc;

	if (data->no_sched_functions && in_sched_functions(addr))
		return 0;
	if (data->skip) {
		data->skip--;
		return 0;
	}

	trace->entries[trace->nr_entries++] = addr;

	return trace->nr_entries >= trace->max_entries;
}

void save_stack_trace_tsk(struct task_struct *tsk, struct stack_trace *trace)
{
	struct stack_trace_data data;
	struct stackframe frame;

	data.trace = trace;
	data.skip = trace->skip;

	if (tsk != current) {
		data.no_sched_functions = 1;
		frame.fp = thread_saved_fp(tsk);
		frame.sp = thread_saved_sp(tsk);
		frame.lr = 0;		/* recovered from the stack */
		frame.pc = thread_saved_pc(tsk);
	} else {
		register unsigned long current_sp asm ("sp");

		data.no_sched_functions = 0;
		frame.fp = (unsigned long)__builtin_frame_address(0);
		frame.sp = current_sp;
		frame.lr = (unsigned long)__builtin_return_address(0);
		frame.pc = (unsigned long)save_stack_trace_tsk;
	}

	walk_stackframe(&frame, save_trace, &data);
	if (trace->nr_entries < trace->max_entries)
		trace->entries[trace->nr_entries++] = ULONG_MAX;
}

void save_stack_trace(struct stack_trace *trace)
{
	save_stack_trace_tsk(current, trace);
}
EXPORT_SYMBOL_GPL(save_stack_trace);
#endif
