#ifndef __ASM_STACKTRACE_H
#define __ASM_STACKTRACE_H

struct stackframe {
	unsigned long fp;
	unsigned long sp;
	unsigned long lr;
	unsigned long pc;
};

extern int unwind_frame(struct stackframe *frame);
extern void walk_stackframe(struct stackframe *frame,
			    int (*fn)(struct stackframe *, void *), void *data);

bool sp_addr_valid(unsigned long sp);
bool addr_in_stack(unsigned long orig_sp, unsigned long vsp);
bool sp_in_stack(unsigned long orig_sp, unsigned long vsp);

#endif	/* __ASM_STACKTRACE_H */
