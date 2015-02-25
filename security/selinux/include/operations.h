#ifndef _SELINUX_OPERATION_H
#define _SELINUX_OPERATION_H

struct operation_decision *operation_decision_alloc(u8 specified);

int operation_in_range(struct operation *op, u16 cmd);

void operation_populate(struct operation_decision *od,
		struct operation_decision *local_od);

void operation_free(struct operation_decision *od);

void copy_operation_to_local(struct operation_decision *local_od,
		struct operation_decision *od, u32 requested);

int operation_audit(u32 ssid, u32 tsid, u16 tclass,
			u32 requested, struct av_decision *avd,
			struct operation_decision *od,
			u32 cmd, int result,
			struct common_audit_data *ad);

void sel_operation_init(void);

#endif
