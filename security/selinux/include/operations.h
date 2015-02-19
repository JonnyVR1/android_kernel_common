
#ifndef _SELINUX_OPERATION_H
#define _SELINUX_OPERATION_H
int operation_has_perm(u32 ssid, u32 tsid, u16 tclass,
		u32 cmd, struct common_audit_data *ad, struct file *file);
#endif
