#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/percpu.h>
#include <net/sock.h>
#include <linux/un.h>
#include <net/af_unix.h>
#include <linux/ip.h>
#include <linux/audit.h>
#include "avc.h"
#include "security.h"
#include "operations.h"

static struct kmem_cache *operation_decision_cachep;
static struct kmem_cache *operation_cachep;

void operation_free(struct operation_decision *od)
{
	if (!od)
		return;
	if (od->allowed)
		kmem_cache_free(operation_cachep, od->allowed);
	if (od->auditallow)
		kmem_cache_free(operation_cachep, od->auditallow);
	if (od->auditdeny)
		kmem_cache_free(operation_cachep, od->auditdeny);
	kmem_cache_free(operation_decision_cachep, od);
}

struct operation_decision *operation_decision_alloc(
		u8 specified)
{
	struct operation_decision *od;
	od = kmem_cache_zalloc(operation_decision_cachep,
				GFP_ATOMIC | __GFP_NOMEMALLOC);
	if (!od)
		goto out;

	if (specified & OPERATION_ALLOWED) {
		od->allowed = kmem_cache_zalloc(
			operation_cachep, GFP_ATOMIC | __GFP_NOMEMALLOC);
		if (!od->allowed)
			goto free_od;
	} else {
		od->allowed = NULL;
	}
	if (specified & OPERATION_AUDITALLOW) {
		od->auditallow = kmem_cache_zalloc(
			operation_cachep, GFP_ATOMIC | __GFP_NOMEMALLOC);
		if (!od->auditallow)
			goto free_allowed;

	} else {
		od->auditallow = NULL;
	}
	if (specified & OPERATION_AUDITDENY) {
		od->auditdeny = kmem_cache_zalloc(
			operation_cachep, GFP_ATOMIC | __GFP_NOMEMALLOC);
		if (!od->auditdeny)
			goto free_auditallow;

	} else {
		od->auditdeny = NULL;
	}
	return od;

free_auditallow:
	if (od->auditallow)
		kmem_cache_free(operation_cachep, od->auditallow);
free_allowed:
	if (od->allowed)
		kmem_cache_free(operation_cachep, od->allowed);
free_od:
	kmem_cache_free(operation_decision_cachep, od);
out:
	return NULL;
}
void operation_populate(struct operation_decision *od,
		struct operation_decision *local_od)
{
	if (!od)
		return;
	od->specified = local_od->specified;
	if (od->specified & OPERATION_ALLOWED)
		*(od->allowed) = *(local_od->allowed);
	if (od->specified & OPERATION_AUDITALLOW)
		*(od->auditallow) = *(local_od->auditallow);
	if (od->specified & OPERATION_AUDITDENY)
		*(od->auditdeny) = *(local_od->auditdeny);
}

inline void copy_operation_to_local(struct operation_decision *local_od,
		struct operation_decision *od, u32 requested)
{
	/* copying for non ioctl requests wastes cycles */
	if (!(requested & FILE__IOCTL))
		return;

	local_od->specified = od->specified;
	if (od->specified & OPERATION_ALLOWED)
		*(local_od->allowed) = *(od->allowed);
	if (od->specified & OPERATION_AUDITALLOW)
		*(local_od->auditallow) = *(od->auditallow);
	if (od->specified & OPERATION_AUDITDENY)
		*(local_od->auditdeny) = *(od->auditdeny);
}

inline int operation_in_range(struct operation *op, u16 cmd)
{
	u16 i;
	/* no ranges included, only consider av_decision */
	if (!op->len)
		return 1;
	for (i = 0; i < op->len; i++) {
		if ((cmd >= op->range[i].low)
				&& (cmd <= op->range[i].high)) {
			return 1;
		/* return false if range already above current range.
		 * This assumes ranges have been sorted !*/
		} else if (cmd < op->range[i].low) {
			return 0;
		}
	}
	/* not in range */
	return 0;
}

static inline u32 operation_audit_required(u32 requested,
			      struct av_decision *avd,
				  struct operation_decision *od,
				  u32 cmd,
			      int result,
			      u32 *deniedp)
{
	u32 denied, audited;
	denied = requested & ~avd->allowed;
	if (unlikely(denied)) {
		if (!operation_in_range(od->auditdeny, (u16) cmd))
			avd->auditdeny |= requested;
		audited = denied & avd->auditdeny;
	} else if (result) {
		audited = denied = requested;
	} else {
		if (!operation_in_range(od->auditallow, (u16) cmd))
			avd->auditallow &= ~(requested);
		audited = requested & avd->auditallow;
	}

	*deniedp = denied;
	return audited;
}

inline int operation_audit(u32 ssid, u32 tsid, u16 tclass,
			u32 requested, struct av_decision *avd,
			struct operation_decision *od,
			u32 cmd, int result,
			struct common_audit_data *ad)
{
	u32 audited, denied;
	audited = operation_audit_required(
			requested, avd, od, cmd, result, &denied);
	if (likely(!audited))
		return 0;
	return slow_avc_audit(ssid, tsid, tclass, requested,
			audited, denied, result, ad, 0);
}

void sel_operation_init(void)
{
	operation_decision_cachep = kmem_cache_create("operation_decision",
			sizeof(struct operation_decision), 0, SLAB_PANIC, NULL);
	operation_cachep = kmem_cache_create("operation",
			sizeof(struct operation), 0, SLAB_PANIC, NULL);
}


