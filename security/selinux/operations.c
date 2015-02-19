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

#define OPERATION_CACHE_SLOTS		64
#define OPERATION_CACHE_RECLAIM		16

#define OPERATION_ALLOWED 1
#define OPERATION_AUDITALLOW 2
#define OPERATION_AUDITDENY 4

struct operation_entry {
	u32			ssid;
	u32			tsid;
	u16			tclass;
	struct operation_decision od;
};

struct operation_node {
	struct operation_entry	oe;
	struct hlist_node	list;
	struct rcu_head		rhead;
};

struct operation_cache {
	struct hlist_head	slots[OPERATION_CACHE_SLOTS];
	spinlock_t		slots_lock[OPERATION_CACHE_SLOTS];
	atomic_t		lru_hint;
	atomic_t		active_nodes;
};

static struct operation_cache operation_cache;
static struct kmem_cache *operation_node_cachep;
static struct kmem_cache *operation_cachep;

static inline int operation_hash(u32 ssid, u32 tsid, u16 tclass)
{
	return (ssid ^ (tsid<<2) ^ (tclass<<4)) & (OPERATION_CACHE_SLOTS - 1);
}

static void operation_node_free(struct rcu_head *rhead)
{
	struct operation_node *node = container_of(
			rhead, struct operation_node, rhead);
	if (node->oe.od.allowed)
		kmem_cache_free(operation_cachep, node->oe.od.allowed);
	if (node->oe.od.auditallow)
		kmem_cache_free(operation_cachep, node->oe.od.auditallow);
	if (node->oe.od.auditdeny)
		kmem_cache_free(operation_cachep, node->oe.od.auditdeny);
	kmem_cache_free(operation_node_cachep, node);
}

static void operation_node_delete(struct operation_node *node)
{
	hlist_del_rcu(&node->list);
	call_rcu(&node->rhead, operation_node_free);
	atomic_dec(&operation_cache.active_nodes);
}

static void operation_node_replace(struct operation_node *new,
			struct operation_node *old)
{
	hlist_replace_rcu(&old->list, &new->list);
	call_rcu(&old->rhead, operation_node_free);
	atomic_dec(&operation_cache.active_nodes);
}

static inline int operation_reclaim_node(void)
{
	struct operation_node *node;
	int hvalue, try, ecx;
	unsigned long flags;
	struct hlist_head *head;
	spinlock_t *lock;

	for (try = 0, ecx = 0; try < OPERATION_CACHE_SLOTS; try++) {
		hvalue = atomic_inc_return(&operation_cache.lru_hint)
						& (OPERATION_CACHE_SLOTS - 1);
		head = &operation_cache.slots[hvalue];
		lock = &operation_cache.slots_lock[hvalue];

		if (!spin_trylock_irqsave(lock, flags))
			continue;

		rcu_read_lock();
		hlist_for_each_entry(node, head, list) {
			operation_node_delete(node);
			ecx++;
			if (ecx >= OPERATION_CACHE_RECLAIM) {
				rcu_read_unlock();
				spin_unlock_irqrestore(lock, flags);
				goto out;
			}
		}
		rcu_read_unlock();
		spin_unlock_irqrestore(lock, flags);
	}
out:
	return ecx;
}

static struct operation_node *operation_alloc_node(u8 specified)
{
	struct operation_node *node;

	node = kmem_cache_zalloc(operation_node_cachep,
				GFP_ATOMIC | __GFP_NOMEMALLOC);
	if (!node)
		goto out;

	if (specified & OPERATION_ALLOWED) {
		node->oe.od.allowed = kmem_cache_zalloc(
			operation_cachep, GFP_ATOMIC | __GFP_NOMEMALLOC);
		if (!node->oe.od.allowed)
			goto free_node;
	} else {
		node->oe.od.allowed = NULL;
	}
	if (specified & OPERATION_AUDITALLOW) {
		node->oe.od.auditallow = kmem_cache_zalloc(
			operation_cachep, GFP_ATOMIC | __GFP_NOMEMALLOC);
		if (!node->oe.od.auditallow)
			goto free_allowed;

	} else {
		node->oe.od.auditallow = NULL;
	}
	if (specified & OPERATION_AUDITDENY) {
		node->oe.od.auditdeny = kmem_cache_zalloc(
			operation_cachep, GFP_ATOMIC | __GFP_NOMEMALLOC);
		if (!node->oe.od.auditdeny)
			goto free_auditallow;

	} else {
		node->oe.od.auditdeny = NULL;
	}

	INIT_HLIST_NODE(&node->list);

	if (atomic_inc_return(&operation_cache.active_nodes)
				> OPERATION_CACHE_SLOTS)
		operation_reclaim_node();

	return node;

free_auditallow:
	if (node->oe.od.auditallow)
		kmem_cache_free(operation_cachep, node->oe.od.auditallow);
free_allowed:
	if (node->oe.od.allowed)
		kmem_cache_free(operation_cachep, node->oe.od.allowed);
free_node:
	kmem_cache_free(operation_node_cachep, node);
out:
	return node;
}

static void operation_node_populate(struct operation_node *node,
					u32 ssid, u32 tsid, u16 tclass,
		struct operation_decision *od)
{
	node->oe.ssid = ssid;
	node->oe.tsid = tsid;
	node->oe.tclass = tclass;
	node->oe.od.av = od->av;
	node->oe.od.specified = od->specified;
	if (od->specified & OPERATION_ALLOWED)
		*(node->oe.od.allowed) = *(od->allowed);
	if (od->specified & OPERATION_AUDITALLOW)
		*(node->oe.od.auditallow) = *(od->auditallow);
	if (od->specified & OPERATION_AUDITDENY)
		*(node->oe.od.auditdeny) = *(od->auditdeny);
}

static inline struct operation_node *operation_search_node(
					u32 ssid, u32 tsid, u16 tclass)
{
	struct operation_node *node, *ret = NULL;
	int hvalue;
	struct hlist_head *head;

	hvalue = operation_hash(ssid, tsid, tclass);
	head = &operation_cache.slots[hvalue];
	hlist_for_each_entry_rcu(node, head, list) {
		if (ssid == node->oe.ssid &&
		    tclass == node->oe.tclass &&
		    tsid == node->oe.tsid) {
			ret = node;
			break;
		}
	}

	return ret;
}

static struct operation_node *operation_lookup(
					u32 ssid, u32 tsid, u16 tclass)
{
	struct operation_node *node;
	node = operation_search_node(ssid, tsid, tclass);
	return node;
}

static struct operation_node *operation_insert(
					u32 ssid, u32 tsid, u16 tclass,
		struct operation_decision *od)
{
	struct operation_node *pos, *node = NULL;
	int hvalue;
	unsigned long flag;

	node = operation_alloc_node(od->specified);
	if (node) {
		struct hlist_head *head;
		spinlock_t *lock;

		hvalue = operation_hash(ssid, tsid, tclass);
		operation_node_populate(node, ssid, tsid, tclass, od);

		head = &operation_cache.slots[hvalue];
		lock = &operation_cache.slots_lock[hvalue];

		spin_lock_irqsave(lock, flag);
		hlist_for_each_entry(pos, head, list) {
			if (pos->oe.ssid == ssid &&
			    pos->oe.tsid == tsid &&
			    pos->oe.tclass == tclass) {
				operation_node_replace(node, pos);
				goto found;
			}
		}
		hlist_add_head_rcu(&node->list, head);
found:
		spin_unlock_irqrestore(lock, flag);
	}
	return node;
}

/**
 * operations_flush - Flush the cache
 */
static void operation_flush(void)
{
	struct hlist_head *head;
	struct operation_node *node;
	spinlock_t *lock;
	unsigned long flag;
	int i;

	for (i = 0; i < OPERATION_CACHE_SLOTS; i++) {
		head = &operation_cache.slots[i];
		lock = &operation_cache.slots_lock[i];

		spin_lock_irqsave(lock, flag);
		/*
		 * With preemptable RCU, the outer spinlock does not
		 * prevent RCU grace periods from ending.
		 */
		rcu_read_lock();
		hlist_for_each_entry(node, head, list)
			operation_node_delete(node);
		rcu_read_unlock();
		spin_unlock_irqrestore(lock, flag);
	}
}

static noinline struct operation_node *operation_compute_av(
			u32 ssid, u32 tsid,	u16 tclass,
			struct operation_decision *od)
{
	rcu_read_unlock();
	security_compute_operation(ssid, tsid, tclass, od);
	rcu_read_lock();
	return operation_insert(ssid, tsid, tclass, od);
}

static void init_operation_decision(struct operation_decision *od)
{
	od->specified = 0;
	od->av = 0;
	od->allowed->len = 0;
	od->auditallow->len = 0;
	od->auditdeny->len = 0;
}

static void operation_decision_copy_to_local(
		struct operation_decision *local,
		struct operation_decision *od)
{
	if (od->allowed)
		*(local->allowed) = *(od->allowed);
	if (od->auditallow)
		*(local->auditallow) = *(od->auditallow);
	if (od->auditdeny)
		*(local->auditdeny) = *(od->auditdeny);
	local->av = od->av;
	local->specified = od->specified;
	local->flags = od->flags;
}

static inline int operation_in_range(struct operation *op, u16 cmd)
{
	u16 i;
	if (op->len > 0) {
		for (i = 0; i < op->len; i++) {
			if ((cmd >= op->range[i].low)
					&& (cmd <= op->range[i].high)) {
				return 1;
			/* return false if range already above current range.
			 * This assumes ranges have been sorted ! */
			} else if (cmd < op->range[i].low) {
				return 0;
			}
		}
	/* no ranges included, only consider av_decision */
	} else {
		return 1;
	}
	/* not in range */
	return 0;
}

static inline u32 operation_audit_required(
		struct operation_decision *od,
		int result,
		u16 cmd,
		u32 *deniedp)
{
	u32 denied = 0, audited = 0;
	if (!(OPERATION_ALLOWED & od->av))
		denied = FILE__IOCTL;
	if (unlikely(denied)) {
		/* first check if an auditdeny */
		if (OPERATION_AUDITDENY & od->av) {
			/* if ranges are defined, search auditdeny for cmd */
			if (!operation_in_range(od->auditdeny, cmd))
				audited = FILE__IOCTL;
		} else {
			audited = FILE__IOCTL;
		}
	} else if (result) {
		audited = denied = FILE__IOCTL;
	/* else allowed, check if auditallow requested */
	} else {
		if (OPERATION_AUDITALLOW & od->av) {
			audited = FILE__IOCTL;
			if (!operation_in_range(od->auditallow, cmd))
				audited = 0;
		}
	}
	*deniedp = denied;
	return audited;
}

static inline int operation_audit(u32 ssid, u32 tsid, u16 tclass,
			int result,
			struct operation_decision *od,
			u32 cmd,
			struct common_audit_data *ad)
{
	u32 audited, denied;
	audited = operation_audit_required(od, result, cmd, &denied);
	if (likely(!audited))
		return 0;
	return slow_avc_audit(ssid, tsid, tclass, FILE__IOCTL,
			audited, denied, result, ad, 0);
}

/**
 * operation_has_perm - Check permissions
 * @ssid: source security identifier
 * @tsid: target security identifier
 * @tclass: target security class
 * @cmd: ioctl command
 * @ad: audit data
 * @file: the file descriptor being accessed
 *
 * Check to determine whether FILE__IOCTL permission is granted and check if
 * the command that is being executed is for the SID pair (@ssid, @tsid),
 * interpreting the permissions based on @tclass, and call the security
 * server on a cache miss to obtain a new decision and add it to the cache.
 * Return a copy of the decisions in avd and command ranges in od
 * Return %0 if the FILE__IOCTL permission is granted,
 * -%EACCES if denied
 */
int operation_has_perm(u32 ssid, u32 tsid, u16 tclass, u32 cmd,
		struct common_audit_data *ad, struct file *file)
{
	struct operation_node *node;
	struct operation_decision od;
	struct operation allowed, auditallow, auditdeny;
	int rc = 0;
	int rc2 = 0;
	u32 denied = 0;
	od.allowed = &allowed;
	od.auditallow = &auditallow;
	od.auditdeny = &auditdeny;

	init_operation_decision(&od);

	rcu_read_lock();

	node = operation_lookup(ssid, tsid, tclass);
	if (unlikely(!node))
		node = operation_compute_av(ssid, tsid, tclass, &od);
	else
		operation_decision_copy_to_local(&od, &node->oe.od);

	if (!(OPERATION_ALLOWED & od.av)) {
		rc = -EACCES;
		goto audit;
	}
	/* search through ranges */
	if (!operation_in_range(od.allowed, (u16) cmd)) {
		rc = -EACCES;
		od.av &= ~OPERATION_ALLOWED;
	}
audit:
	rcu_read_unlock();
	rc2 = operation_audit(ssid, tsid, tclass, rc,
			&od, (u16) cmd, ad);
	if (rc2)
		return rc2;
	return rc;
}

static int operation_avc_callback(u32 event)
{
	if (event == AVC_CALLBACK_RESET)
		operation_flush();
	return 0;
}

/**
 * Initialize operation cache.
 */
static __init int sel_operation_init(void)
{
	int i;
	int ret;

	if (!selinux_enabled)
		return 0;

	for (i = 0; i < OPERATION_CACHE_SLOTS; i++) {
		INIT_HLIST_HEAD(&operation_cache.slots[i]);
		spin_lock_init(&operation_cache.slots_lock[i]);
	}
	atomic_set(&operation_cache.active_nodes, 0);
	atomic_set(&operation_cache.lru_hint, 0);

	operation_node_cachep = kmem_cache_create("operation_node",
			sizeof(struct operation_node), 0, SLAB_PANIC, NULL);
	operation_cachep = kmem_cache_create("operation",
			sizeof(struct operation), 0, SLAB_PANIC, NULL);

	ret = avc_add_callback(operation_avc_callback, AVC_CALLBACK_RESET);
	if (ret != 0)
		panic("avc_add_callback() failed, error %d\n", ret);
	return ret;
}

__initcall(sel_operation_init);
