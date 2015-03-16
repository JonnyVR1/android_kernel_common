/*
 * Implementation of the kernel access vector cache (AVC).
 *
 * Authors:  Stephen Smalley, <sds@epoch.ncsc.mil>
 *	     James Morris <jmorris@redhat.com>
 *
 * Update:   KaiGai, Kohei <kaigai@ak.jp.nec.com>
 *	Replaced the avc_lock spinlock by RCU.
 *
 * Copyright (C) 2003 Red Hat, Inc., James Morris <jmorris@redhat.com>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License version 2,
 *	as published by the Free Software Foundation.
 */
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
#include <linux/ipv6.h>
#include <net/ipv6.h>
#include "avc.h"
#include "avc_ss.h"
#include "classmap.h"

#define AVC_CACHE_SLOTS			512
#define AVC_DEF_CACHE_THRESHOLD		512
#define AVC_CACHE_RECLAIM		16

#ifdef CONFIG_SECURITY_SELINUX_AVC_STATS
#define avc_cache_stats_incr(field)	this_cpu_inc(avc_cache_stats.field)
#else
#define avc_cache_stats_incr(field)	do {} while (0)
#endif

struct avc_entry {
	u32			ssid;
	u32			tsid;
	u16			tclass;
	struct av_decision	avd;
	struct operations	*ops;
};

struct avc_node {
	struct avc_entry	ae;
	struct hlist_node	list; /* anchored in avc_cache->slots[i] */
	struct rcu_head		rhead;
};

struct avc_cache {
	struct hlist_head	slots[AVC_CACHE_SLOTS]; /* head for avc_node->list */
	spinlock_t		slots_lock[AVC_CACHE_SLOTS]; /* lock for writes */
	atomic_t		lru_hint;	/* LRU hint for reclaim scan */
	atomic_t		active_nodes;
	u32			latest_notif;	/* latest revocation notification */
};

struct avc_callback_node {
	int (*callback) (u32 event);
	u32 events;
	struct avc_callback_node *next;
};

/* Exported via selinufs */
unsigned int avc_cache_threshold = AVC_DEF_CACHE_THRESHOLD;

#ifdef CONFIG_SECURITY_SELINUX_AVC_STATS
DEFINE_PER_CPU(struct avc_cache_stats, avc_cache_stats) = { 0 };
#endif

static struct avc_cache avc_cache;
static struct avc_callback_node *avc_callbacks;
static struct kmem_cache *avc_node_cachep;
static struct kmem_cache *avc_operation_decision_cachep;
static struct kmem_cache *avc_operations_cachep;
static struct kmem_cache *avc_operation_perm_cachep;

static inline int avc_hash(u32 ssid, u32 tsid, u16 tclass)
{
	return (ssid ^ (tsid<<2) ^ (tclass<<4)) & (AVC_CACHE_SLOTS - 1);
}

/**
 * avc_dump_av - Display an access vector in human-readable form.
 * @tclass: target security class
 * @av: access vector
 */
static void avc_dump_av(struct audit_buffer *ab, u16 tclass, u32 av)
{
	const char **perms;
	int i, perm;

	if (av == 0) {
		audit_log_format(ab, " null");
		return;
	}

	perms = secclass_map[tclass-1].perms;

	audit_log_format(ab, " {");
	i = 0;
	perm = 1;
	while (i < (sizeof(av) * 8)) {
		if ((perm & av) && perms[i]) {
			audit_log_format(ab, " %s", perms[i]);
			av &= ~perm;
		}
		i++;
		perm <<= 1;
	}

	if (av)
		audit_log_format(ab, " 0x%x", av);

	audit_log_format(ab, " }");
}

/**
 * avc_dump_query - Display a SID pair and a class in human-readable form.
 * @ssid: source security identifier
 * @tsid: target security identifier
 * @tclass: target security class
 */
static void avc_dump_query(struct audit_buffer *ab, u32 ssid, u32 tsid, u16 tclass)
{
	int rc;
	char *scontext;
	u32 scontext_len;

	rc = security_sid_to_context(ssid, &scontext, &scontext_len);
	if (rc)
		audit_log_format(ab, "ssid=%d", ssid);
	else {
		audit_log_format(ab, "scontext=%s", scontext);
		kfree(scontext);
	}

	rc = security_sid_to_context(tsid, &scontext, &scontext_len);
	if (rc)
		audit_log_format(ab, " tsid=%d", tsid);
	else {
		audit_log_format(ab, " tcontext=%s", scontext);
		kfree(scontext);
	}

	BUG_ON(tclass >= ARRAY_SIZE(secclass_map));
	audit_log_format(ab, " tclass=%s", secclass_map[tclass-1].name);
}

/**
 * avc_init - Initialize the AVC.
 *
 * Initialize the access vector cache.
 */
void __init avc_init(void)
{
	int i;

	for (i = 0; i < AVC_CACHE_SLOTS; i++) {
		INIT_HLIST_HEAD(&avc_cache.slots[i]);
		spin_lock_init(&avc_cache.slots_lock[i]);
	}
	atomic_set(&avc_cache.active_nodes, 0);
	atomic_set(&avc_cache.lru_hint, 0);

	avc_node_cachep = kmem_cache_create("avc_node", sizeof(struct avc_node),
					     0, SLAB_PANIC, NULL);
	avc_operations_cachep = kmem_cache_create(
			"avc_operations", sizeof(struct operations),
			0, SLAB_PANIC, NULL);
	avc_operation_decision_cachep = kmem_cache_create(
			"avc_operation_decision", sizeof(struct operation_decision),
			0, SLAB_PANIC, NULL);
	avc_operation_perm_cachep = kmem_cache_create(
			"avc_operation", sizeof(struct operation_perm),
			0, SLAB_PANIC, NULL);

	audit_log(current->audit_context, GFP_KERNEL, AUDIT_KERNEL, "AVC INITIALIZED\n");
}

int avc_get_hash_stats(char *page)
{
	int i, chain_len, max_chain_len, slots_used;
	struct avc_node *node;
	struct hlist_head *head;

	rcu_read_lock();

	slots_used = 0;
	max_chain_len = 0;
	for (i = 0; i < AVC_CACHE_SLOTS; i++) {
		head = &avc_cache.slots[i];
		if (!hlist_empty(head)) {
			slots_used++;
			chain_len = 0;
			hlist_for_each_entry_rcu(node, head, list)
				chain_len++;
			if (chain_len > max_chain_len)
				max_chain_len = chain_len;
		}
	}

	rcu_read_unlock();

	return scnprintf(page, PAGE_SIZE, "entries: %d\nbuckets used: %d/%d\n"
			 "longest chain: %d\n",
			 atomic_read(&avc_cache.active_nodes),
			 slots_used, AVC_CACHE_SLOTS, max_chain_len);
}

static struct operation_decision *avc_operation_lookup(u8 type, struct operations *ops)
{
	struct operation_decision *od;
	for (od = ops->head; od != NULL; od = od->next) {
		if (od->type == type)
			return od;
	}
	return NULL;
}

static inline int avc_operation_has_perm(struct operation_perm *op, u16 cmd)
{
	u8 num = cmd & 0xff;
	/* if operation_perms is not defined, only consider av_decision */
	if (!op)
		return 0;
	if (op->perms[num >> 5] & 1 << (num & 0x1f))
		return 1;
	return 0;
}

static void avc_operation_allow_perm(struct operations *ops, u16 cmd)
{
	struct operation_decision *od;
	u8 type;
	u8 num;
	type = cmd >> 8;
	num = cmd & 0xff;
	if (!(ops->type[type >> 5] & 1 << (type & 0x1f))) {
		/* add command type permission */
		ops->type[type >> 5] |= 1 << (type & 0x1f);
	} else {
		/* add command number permission */
		od = avc_operation_lookup(type, ops);
		if (od)
			od->allowed->perms[num >> 5] |= 1 << (num & 0x1f);
	}
}

static void avc_operation_decision_free(struct operation_decision *od)
{
	if (od->allowed)
		kmem_cache_free(avc_operation_perm_cachep, od->allowed);
	if (od->auditallow)
		kmem_cache_free(avc_operation_perm_cachep, od->auditallow);
	if (od->auditdeny)
		kmem_cache_free(avc_operation_perm_cachep, od->auditdeny);
	kmem_cache_free(avc_operation_decision_cachep, od);
}

static void avc_operation_free(struct operations *ops)
{
	struct operation_decision *od, *tmp;
	if (!ops)
		return;
	/* free the list of operation_decision structures */
	od = ops->head;
	while (od) {
		tmp = od->next;
		avc_operation_decision_free(od);
		od = tmp;
	}
	kmem_cache_free(avc_operations_cachep, ops);
}

static struct operation_decision *avc_operation_decision_alloc(void)
{
	struct operation_decision *od;
	od = kmem_cache_zalloc(avc_operation_decision_cachep,
				GFP_ATOMIC | __GFP_NOMEMALLOC);
	if (!od)
		return NULL;

	od->allowed = kmem_cache_zalloc(
		avc_operation_perm_cachep, GFP_ATOMIC | __GFP_NOMEMALLOC);
	od->auditallow = kmem_cache_zalloc(
		avc_operation_perm_cachep, GFP_ATOMIC | __GFP_NOMEMALLOC);
	od->auditdeny = kmem_cache_zalloc(
		avc_operation_perm_cachep, GFP_ATOMIC | __GFP_NOMEMALLOC);
	if (!od->allowed || !od->auditallow || !od->auditdeny) {
		avc_operation_decision_free(od);
		return NULL;
	}
	return od;
}

static void avc_copy_operation_decision(struct operation_decision *dest,
					struct operation_decision *src)
{
	dest->type = src->type;
	dest->specified = src->specified;
	if (dest->specified & OPERATION_ALLOWED)
		memcpy(&dest->allowed->perms[0], &src->allowed->perms[0], sizeof(u32)*8);
	if (dest->specified & OPERATION_AUDITALLOW)
		memcpy(&dest->auditallow->perms[0], &src->auditallow->perms[0], sizeof(u32)*8);
	if (dest->specified & OPERATION_AUDITDENY)
		memcpy(&dest->auditdeny->perms[0], &src->auditdeny->perms[0], sizeof(u32)*8);
	/*
	 * This will when in permissive mode. Set specified to
	 * allowed so that the empty dest->allowed structure is retained to
	 * later be populated with granted permissions.
	 */
	if (!dest->specified)
		dest->specified |= OPERATION_ALLOWED;
}

static void avc_operation_free_unused(struct operation_decision *od)
{
	if (!(od->specified & OPERATION_ALLOWED)) {
		kmem_cache_free(avc_operation_perm_cachep, od->allowed);
		od->allowed = NULL;
	}
	if (!(od->specified & OPERATION_AUDITALLOW)) {
		kmem_cache_free(avc_operation_perm_cachep, od->auditallow);
		od->auditallow = NULL;
	}
	if (!(od->specified & OPERATION_AUDITDENY)) {
		kmem_cache_free(avc_operation_perm_cachep, od->auditdeny);
		od->auditdeny = NULL;
	}
}

static void avc_add_operation(struct avc_node *node, struct operation_decision *od)
{
	struct operation_decision *tmp;
	node->ae.ops->len += 1;
	/*
	 * the last item in the list has been allocated for this
	 * operation_decision
	 */
	tmp = node->ae.ops->head;
	while (tmp->next != NULL)
		tmp = tmp->next;

	avc_copy_operation_decision(tmp, od);
	avc_operation_free_unused(tmp);
}

static void avc_operation_populate(struct operations *dest, struct operations *src)
{
	struct operation_decision *dest_od;
	struct operation_decision *src_od;
	memcpy(&dest->type[0], &src->type[0], sizeof(u32)*8);
	dest->len = src->len;
	dest_od = dest->head;
	src_od = src->head;
	while (dest_od && src_od) {
		avc_copy_operation_decision(dest_od, src_od);
		avc_operation_free_unused(dest_od);
		dest_od = dest_od->next;
		src_od = src_od->next;
	}
}

static u32 avc_operation_audit_required(u32 requested,
					struct av_decision *avd,
					struct operation_decision *od,
					u16 cmd,
					int result,
					u32 *deniedp)
{
	u32 denied, audited;
	denied = requested & ~avd->allowed;
	if (unlikely(denied)) {
		audited = denied & avd->auditdeny;
		if (audited && od && avc_operation_has_perm(od->auditdeny, cmd))
			audited &= ~requested;
	} else if (result) {
		audited = denied = requested;
	} else {
		audited = requested & avd->auditallow;
		if (audited && od && !avc_operation_has_perm(od->auditallow, cmd))
			audited &= ~requested;
	}

	*deniedp = denied;
	return audited;
}

static int avc_operation_audit(u32 ssid, u32 tsid, u16 tclass,
				u32 requested, struct av_decision *avd,
				struct operation_decision *od,
				u16 cmd, int result,
				struct common_audit_data *ad)
{
	u32 audited, denied;
	audited = avc_operation_audit_required(
			requested, avd, od, cmd, result, &denied);
	if (likely(!audited))
		return 0;
	return slow_avc_audit(ssid, tsid, tclass, requested,
			audited, denied, result, ad, 0);
}

static void avc_node_free(struct rcu_head *rhead)
{
	struct avc_node *node = container_of(rhead, struct avc_node, rhead);
	avc_operation_free(node->ae.ops);
	kmem_cache_free(avc_node_cachep, node);
	avc_cache_stats_incr(frees);
}

static void avc_node_delete(struct avc_node *node)
{
	hlist_del_rcu(&node->list);
	call_rcu(&node->rhead, avc_node_free);
	atomic_dec(&avc_cache.active_nodes);
}

static void avc_node_kill(struct avc_node *node)
{
	avc_operation_free(node->ae.ops);
	kmem_cache_free(avc_node_cachep, node);
	avc_cache_stats_incr(frees);
	atomic_dec(&avc_cache.active_nodes);
}

static void avc_node_replace(struct avc_node *new, struct avc_node *old)
{
	hlist_replace_rcu(&old->list, &new->list);
	call_rcu(&old->rhead, avc_node_free);
	atomic_dec(&avc_cache.active_nodes);
}

static inline int avc_reclaim_node(void)
{
	struct avc_node *node;
	int hvalue, try, ecx;
	unsigned long flags;
	struct hlist_head *head;
	spinlock_t *lock;

	for (try = 0, ecx = 0; try < AVC_CACHE_SLOTS; try++) {
		hvalue = atomic_inc_return(&avc_cache.lru_hint) & (AVC_CACHE_SLOTS - 1);
		head = &avc_cache.slots[hvalue];
		lock = &avc_cache.slots_lock[hvalue];

		if (!spin_trylock_irqsave(lock, flags))
			continue;

		rcu_read_lock();
		hlist_for_each_entry(node, head, list) {
			avc_node_delete(node);
			avc_cache_stats_incr(reclaims);
			ecx++;
			if (ecx >= AVC_CACHE_RECLAIM) {
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

static struct operations *avc_operations_alloc(u8 operations_len)
{
	struct operations *ops;
	struct operation_decision *od;
	struct operation_decision *tmp;
	int i;
	int chain_len;

	/*
	 * for operations_len = 1, only allocate operations structure for the type
	 * permissions
	 */
	if (operations_len == 0)
		return NULL;
	chain_len = operations_len - 1;
	ops = kmem_cache_zalloc(avc_operations_cachep, GFP_ATOMIC|__GFP_NOMEMALLOC);
	if (!ops)
		return ops;
	for (i = 0; i < chain_len; i++) {
		od = avc_operation_decision_alloc();
		if (!od)
			goto error;
		if (!ops->head) {
			ops->head = od;
			tmp = od;
		} else {
			tmp->next = od;
			tmp = tmp->next;
		}
	}
	return ops;

error:
	avc_operation_free(ops);
	return NULL;
}

static struct avc_node *avc_alloc_node(u8 operations_len)
{
	struct avc_node *node;
	struct operations *ops;

	node = kmem_cache_zalloc(avc_node_cachep, GFP_ATOMIC|__GFP_NOMEMALLOC);
	if (!node)
		goto out;

	if (operations_len) {
		ops = avc_operations_alloc(operations_len);
		if (!ops) {
			kmem_cache_free(avc_node_cachep, node);
			node = NULL;
			goto out;
		}
		node->ae.ops = ops;
	}


	INIT_HLIST_NODE(&node->list);
	avc_cache_stats_incr(allocations);

	if (atomic_inc_return(&avc_cache.active_nodes) > avc_cache_threshold)
		avc_reclaim_node();

out:
	return node;

}

static void avc_node_populate(struct avc_node *node, u32 ssid, u32 tsid,
				u16 tclass, struct av_decision *avd,
				struct operations *ops)
{
	node->ae.ssid = ssid;
	node->ae.tsid = tsid;
	node->ae.tclass = tclass;
	memcpy(&node->ae.avd, avd, sizeof(node->ae.avd));
	if (node->ae.ops)
		avc_operation_populate(node->ae.ops, ops);
}

static inline struct avc_node *avc_search_node(u32 ssid, u32 tsid, u16 tclass)
{
	struct avc_node *node, *ret = NULL;
	int hvalue;
	struct hlist_head *head;

	hvalue = avc_hash(ssid, tsid, tclass);
	head = &avc_cache.slots[hvalue];
	hlist_for_each_entry_rcu(node, head, list) {
		if (ssid == node->ae.ssid &&
		    tclass == node->ae.tclass &&
		    tsid == node->ae.tsid) {
			ret = node;
			break;
		}
	}

	return ret;
}

/**
 * avc_lookup - Look up an AVC entry.
 * @ssid: source security identifier
 * @tsid: target security identifier
 * @tclass: target security class
 *
 * Look up an AVC entry that is valid for the
 * (@ssid, @tsid), interpreting the permissions
 * based on @tclass.  If a valid AVC entry exists,
 * then this function returns the avc_node.
 * Otherwise, this function returns NULL.
 */
static struct avc_node *avc_lookup(u32 ssid, u32 tsid, u16 tclass)
{
	struct avc_node *node;

	avc_cache_stats_incr(lookups);
	node = avc_search_node(ssid, tsid, tclass);

	if (node)
		return node;

	avc_cache_stats_incr(misses);
	return NULL;
}

static int avc_latest_notif_update(int seqno, int is_insert)
{
	int ret = 0;
	static DEFINE_SPINLOCK(notif_lock);
	unsigned long flag;

	spin_lock_irqsave(&notif_lock, flag);
	if (is_insert) {
		if (seqno < avc_cache.latest_notif) {
			printk(KERN_WARNING "SELinux: avc:  seqno %d < latest_notif %d\n",
			       seqno, avc_cache.latest_notif);
			ret = -EAGAIN;
		}
	} else {
		if (seqno > avc_cache.latest_notif)
			avc_cache.latest_notif = seqno;
	}
	spin_unlock_irqrestore(&notif_lock, flag);

	return ret;
}

/**
 * avc_insert - Insert an AVC entry.
 * @ssid: source security identifier
 * @tsid: target security identifier
 * @tclass: target security class
 * @avd: resulting av decision
 * @ops: resulting operations decisions
 *
 * Insert an AVC entry for the SID pair
 * (@ssid, @tsid) and class @tclass.
 * The access vectors and the sequence number are
 * normally provided by the security server in
 * response to a security_compute_av() call.  If the
 * sequence number @avd->seqno is not less than the latest
 * revocation notification, then the function copies
 * the access vectors into a cache entry, returns
 * avc_node inserted. Otherwise, this function returns NULL.
 */
static struct avc_node *avc_insert(u32 ssid, u32 tsid, u16 tclass,
				struct av_decision *avd,
				struct operations *ops)
{
	struct avc_node *pos, *node = NULL;
	int hvalue;
	unsigned long flag;

	if (avc_latest_notif_update(avd->seqno, 1))
		goto out;

	node = avc_alloc_node(ops->len);
	if (node) {
		struct hlist_head *head;
		spinlock_t *lock;

		hvalue = avc_hash(ssid, tsid, tclass);
		avc_node_populate(node, ssid, tsid, tclass, avd, ops);

		head = &avc_cache.slots[hvalue];
		lock = &avc_cache.slots_lock[hvalue];

		spin_lock_irqsave(lock, flag);
		hlist_for_each_entry(pos, head, list) {
			if (pos->ae.ssid == ssid &&
			    pos->ae.tsid == tsid &&
			    pos->ae.tclass == tclass) {
				avc_node_replace(node, pos);
				goto found;
			}
		}
		hlist_add_head_rcu(&node->list, head);
found:
		spin_unlock_irqrestore(lock, flag);
	}
out:
	return node;
}

/**
 * avc_audit_pre_callback - SELinux specific information
 * will be called by generic audit code
 * @ab: the audit buffer
 * @a: audit_data
 */
static void avc_audit_pre_callback(struct audit_buffer *ab, void *a)
{
	struct common_audit_data *ad = a;
	audit_log_format(ab, "avc:  %s ",
			 ad->selinux_audit_data->denied ? "denied" : "granted");
	avc_dump_av(ab, ad->selinux_audit_data->tclass,
			ad->selinux_audit_data->audited);
	audit_log_format(ab, " for ");
}

/**
 * avc_audit_post_callback - SELinux specific information
 * will be called by generic audit code
 * @ab: the audit buffer
 * @a: audit_data
 */
static void avc_audit_post_callback(struct audit_buffer *ab, void *a)
{
	struct common_audit_data *ad = a;
	audit_log_format(ab, " ");
	avc_dump_query(ab, ad->selinux_audit_data->ssid,
			   ad->selinux_audit_data->tsid,
			   ad->selinux_audit_data->tclass);
	if (ad->selinux_audit_data->denied) {
		audit_log_format(ab, " permissive=%u",
				 ad->selinux_audit_data->result ? 0 : 1);
	}
}

/* This is the slow part of avc audit with big stack footprint */
noinline int slow_avc_audit(u32 ssid, u32 tsid, u16 tclass,
		u32 requested, u32 audited, u32 denied, int result,
		struct common_audit_data *a,
		unsigned flags)
{
	struct common_audit_data stack_data;
	struct selinux_audit_data sad;

	if (!a) {
		a = &stack_data;
		a->type = LSM_AUDIT_DATA_NONE;
	}

	/*
	 * When in a RCU walk do the audit on the RCU retry.  This is because
	 * the collection of the dname in an inode audit message is not RCU
	 * safe.  Note this may drop some audits when the situation changes
	 * during retry. However this is logically just as if the operation
	 * happened a little later.
	 */
	if ((a->type == LSM_AUDIT_DATA_INODE) &&
	    (flags & MAY_NOT_BLOCK))
		return -ECHILD;

	sad.tclass = tclass;
	sad.requested = requested;
	sad.ssid = ssid;
	sad.tsid = tsid;
	sad.audited = audited;
	sad.denied = denied;
	sad.result = result;

	a->selinux_audit_data = &sad;

	common_lsm_audit(a, avc_audit_pre_callback, avc_audit_post_callback);
	return 0;
}

/**
 * avc_add_callback - Register a callback for security events.
 * @callback: callback function
 * @events: security events
 *
 * Register a callback function for events in the set @events.
 * Returns %0 on success or -%ENOMEM if insufficient memory
 * exists to add the callback.
 */
int __init avc_add_callback(int (*callback)(u32 event), u32 events)
{
	struct avc_callback_node *c;
	int rc = 0;

	c = kmalloc(sizeof(*c), GFP_KERNEL);
	if (!c) {
		rc = -ENOMEM;
		goto out;
	}

	c->callback = callback;
	c->events = events;
	c->next = avc_callbacks;
	avc_callbacks = c;
out:
	return rc;
}

static inline int avc_sidcmp(u32 x, u32 y)
{
	return (x == y || x == SECSID_WILD || y == SECSID_WILD);
}

/**
 * avc_update_node Update an AVC entry
 * @event : Updating event
 * @perms : Permission mask bits
 * @ssid,@tsid,@tclass : identifier of an AVC entry
 * @seqno : sequence number when decision was made
 * @operations_len : The numver of operation_decision fields to allocate
 * @od: operation_decision to be added to the node
 *
 * if a valid AVC entry doesn't exist,this function returns -ENOENT.
 * if kmalloc() called internal returns NULL, this function returns -ENOMEM.
 * otherwise, this function updates the AVC entry. The original AVC-entry object
 * will release later by RCU.
 */
static int avc_update_node(u32 event, u32 perms, u16 cmd, u32 ssid, u32 tsid,
			u16 tclass, u32 seqno, u8 operations_len,
			struct operation_decision *od)
{
	int hvalue, rc = 0;
	unsigned long flag;
	struct avc_node *pos, *node, *orig = NULL;
	struct hlist_head *head;
	spinlock_t *lock;

	node = avc_alloc_node(operations_len);
	if (!node) {
		rc = -ENOMEM;
		goto out;
	}

	/* Lock the target slot */
	hvalue = avc_hash(ssid, tsid, tclass);

	head = &avc_cache.slots[hvalue];
	lock = &avc_cache.slots_lock[hvalue];

	spin_lock_irqsave(lock, flag);

	hlist_for_each_entry(pos, head, list) {
		if (ssid == pos->ae.ssid &&
		    tsid == pos->ae.tsid &&
		    tclass == pos->ae.tclass &&
		    seqno == pos->ae.avd.seqno){
			orig = pos;
			break;
		}
	}

	if (!orig) {
		rc = -ENOENT;
		avc_node_kill(node);
		goto out_unlock;
	}

	/*
	 * Copy and replace original node.
	 */

	avc_node_populate(node, ssid, tsid, tclass, &orig->ae.avd, orig->ae.ops);

	/*
	 * if a new operation decision structure has been passed in add it to
	 * the new node
	 */
	if (od)
		avc_add_operation(node, od);

	switch (event) {
	case AVC_CALLBACK_GRANT:
		node->ae.avd.allowed |= perms;
		if (node->ae.ops && cmd)
			avc_operation_allow_perm(node->ae.ops, cmd);
		break;
	case AVC_CALLBACK_TRY_REVOKE:
	case AVC_CALLBACK_REVOKE:
		node->ae.avd.allowed &= ~perms;
		break;
	case AVC_CALLBACK_AUDITALLOW_ENABLE:
		node->ae.avd.auditallow |= perms;
		break;
	case AVC_CALLBACK_AUDITALLOW_DISABLE:
		node->ae.avd.auditallow &= ~perms;
		break;
	case AVC_CALLBACK_AUDITDENY_ENABLE:
		node->ae.avd.auditdeny |= perms;
		break;
	case AVC_CALLBACK_AUDITDENY_DISABLE:
		node->ae.avd.auditdeny &= ~perms;
		break;
	}
	avc_node_replace(node, orig);
out_unlock:
	spin_unlock_irqrestore(lock, flag);
out:
	return rc;
}

/**
 * avc_flush - Flush the cache
 */
static void avc_flush(void)
{
	struct hlist_head *head;
	struct avc_node *node;
	spinlock_t *lock;
	unsigned long flag;
	int i;

	for (i = 0; i < AVC_CACHE_SLOTS; i++) {
		head = &avc_cache.slots[i];
		lock = &avc_cache.slots_lock[i];

		spin_lock_irqsave(lock, flag);
		/*
		 * With preemptable RCU, the outer spinlock does not
		 * prevent RCU grace periods from ending.
		 */
		rcu_read_lock();
		hlist_for_each_entry(node, head, list)
			avc_node_delete(node);
		rcu_read_unlock();
		spin_unlock_irqrestore(lock, flag);
	}
}

/**
 * avc_ss_reset - Flush the cache and revalidate migrated permissions.
 * @seqno: policy sequence number
 */
int avc_ss_reset(u32 seqno)
{
	struct avc_callback_node *c;
	int rc = 0, tmprc;

	avc_flush();

	for (c = avc_callbacks; c; c = c->next) {
		if (c->events & AVC_CALLBACK_RESET) {
			tmprc = c->callback(AVC_CALLBACK_RESET);
			/* save the first error encountered for the return
			   value and continue processing the callbacks */
			if (!rc)
				rc = tmprc;
		}
	}

	avc_latest_notif_update(seqno, 0);
	return rc;
}

/*
 * Slow-path helper function for avc_has_perm_noaudit,
 * when the avc_node lookup fails. We get called with
 * the RCU read lock held, and need to return with it
 * still held, but drop if for the security compute.
 *
 * Don't inline this, since it's the slow-path and just
 * results in a bigger stack frame.
 */
static noinline struct avc_node *avc_compute_av(u32 ssid, u32 tsid,
			 u16 tclass, struct av_decision *avd,
			 struct operations *ops)
{
	rcu_read_unlock();
	security_compute_av(ssid, tsid, tclass, avd, ops);
	rcu_read_lock();
	return avc_insert(ssid, tsid, tclass, avd, ops);
}

static noinline int avc_denied(u32 ssid, u32 tsid,
				u16 tclass, u32 requested,
				u16 cmd, unsigned flags,
				struct av_decision *avd,
				u8 operations_len)
{
	if (flags & AVC_STRICT)
		return -EACCES;

	if (selinux_enforcing && !(avd->flags & AVD_FLAGS_PERMISSIVE))
		return -EACCES;

	avc_update_node(AVC_CALLBACK_GRANT, requested, cmd, ssid,
				tsid, tclass, avd->seqno, operations_len, NULL);
	return 0;
}

inline void avc_lookup_decision(u32 ssid, u32 tsid,
				u16 tclass, u32 requested,
				struct av_decision *avd,
				struct operations *ops)
{
	struct avc_node *node;

	node = avc_lookup(ssid, tsid, tclass);
	if (unlikely(!node)) {
		node = avc_compute_av(ssid, tsid, tclass, avd, ops);
	} else {
		memcpy(avd, &node->ae.avd, sizeof(*avd));
		if (node->ae.ops)
			ops->len = node->ae.ops->len;
		else
			ops->len = 0;
	}
}

/*
 * compute the operation decision, update the avc node with the new
 * information
 */
static int avc_compute_operation(u32 ssid, u32 tsid, u16 tclass, u8 type,
				u16 cmd,
				u32 requested,
				struct av_decision *avd,
				u8 operations_len,
				struct operation_decision *od)
{
	rcu_read_unlock();
	security_compute_operation(ssid, tsid, tclass, type, od);
	rcu_read_lock();
	return avc_update_node(0, requested, cmd, ssid, tsid, tclass, avd->seqno,
			operations_len, od);
}


/*
 * ioctl commands are comprised of four fields, direction, size, type, and
 * number. The avc operation logic filters based on only two of them:
 *
 * type: or code, typically unique to each driver
 * number: or function
 *
 * For example, 0x89 is a socket type, and number 0x27 is the get hardware
 * address function.
 */
inline int avc_has_operation(u32 ssid, u32 tsid, u16 tclass, u32 requested,
			u16 cmd, struct common_audit_data *ad)
{
	struct avc_node *node;
	struct av_decision avd;
	u32 denied;
	struct operations ops;
	struct operation_decision *od = NULL;
	struct operation_decision od_local;
	struct operation_perm allowed;
	struct operation_perm auditallow;
	struct operation_perm auditdeny;
	u8 type = cmd >> 8;
	u8 operations_len = 0;
	int rc = 0, rc2;
	BUG_ON(!requested);

	rcu_read_lock();

	node = avc_lookup(ssid, tsid, tclass);
	if (unlikely(!node)) {
		node = avc_compute_av(ssid, tsid, tclass, &avd, &ops);
	} else {
		memcpy(&avd, &node->ae.avd, sizeof(avd));
		if (node->ae.ops)
			operations_len = node->ae.ops->len;
	}

	/* if operations are not defined, only consider av_decision */
	if (!node->ae.ops)
		goto decision;

	/* check operation type */
	if (!(node->ae.ops->type[type >> 5] & 1 << (type & 0x1f))) {
		avd.allowed &= ~requested;
		goto decision;
	}
	od_local.allowed = &allowed;
	od_local.auditallow = &auditallow;
	od_local.auditdeny = &auditdeny;

	/* check operation number */
	od = avc_operation_lookup(type, node->ae.ops);
	if (unlikely(!od)) {
		operations_len++;
		avc_compute_operation(ssid, tsid, tclass, type,
					cmd, requested, &avd,
					operations_len, &od_local);
	} else {
		avc_copy_operation_decision(&od_local, od);
	}
	od = &od_local;

	if (!avc_operation_has_perm(od->allowed, cmd))
		avd.allowed &= ~requested;

decision:
	denied = requested & ~(avd.allowed);
	if (unlikely(denied))
		rc = avc_denied(ssid, tsid, tclass, requested, cmd, 0,
				&avd, operations_len);

	rcu_read_unlock();

	rc2 = avc_operation_audit(ssid, tsid, tclass, requested,
			&avd, od, cmd, rc, ad);
	if (rc2)
		return rc2;
	return rc;
}

/**
 * avc_has_perm_noaudit - Check permissions but perform no auditing.
 * @ssid: source security identifier
 * @tsid: target security identifier
 * @tclass: target security class
 * @requested: requested permissions, interpreted based on @tclass
 * @flags:  AVC_STRICT or 0
 * @avd: access vector decisions
 *
 * Check the AVC to determine whether the @requested permissions are granted
 * for the SID pair (@ssid, @tsid), interpreting the permissions
 * based on @tclass, and call the security server on a cache miss to obtain
 * a new decision and add it to the cache.  Return a copy of the decisions
 * in @avd.  Return %0 if all @requested permissions are granted,
 * -%EACCES if any permissions are denied, or another -errno upon
 * other errors.  This function is typically called by avc_has_perm(),
 * but may also be called directly to separate permission checking from
 * auditing, e.g. in cases where a lock must be held for the check but
 * should be released for the auditing.
 */
inline int avc_has_perm_noaudit(u32 ssid, u32 tsid,
			 u16 tclass, u32 requested,
			 unsigned flags,
			 struct av_decision *avd)
{
	struct operations ops;
	int rc = 0;
	u32 denied;

	BUG_ON(!requested);

	rcu_read_lock();

	avc_lookup_decision(ssid, tsid, tclass, requested,
			avd, &ops);

	denied = requested & ~(avd->allowed);
	if (unlikely(denied))
		rc = avc_denied(ssid, tsid, tclass, requested, 0, flags,
				avd, ops.len);

	rcu_read_unlock();
	return rc;
}

/**
 * avc_has_perm - Check permissions and perform any appropriate auditing.
 * @ssid: source security identifier
 * @tsid: target security identifier
 * @tclass: target security class
 * @requested: requested permissions, interpreted based on @tclass
 * @auditdata: auxiliary audit data
 * @flags: VFS walk flags
 *
 * Check the AVC to determine whether the @requested permissions are granted
 * for the SID pair (@ssid, @tsid), interpreting the permissions
 * based on @tclass, and call the security server on a cache miss to obtain
 * a new decision and add it to the cache.  Audit the granting or denial of
 * permissions in accordance with the policy.  Return %0 if all @requested
 * permissions are granted, -%EACCES if any permissions are denied, or
 * another -errno upon other errors.
 */
int avc_has_perm_flags(u32 ssid, u32 tsid, u16 tclass,
		       u32 requested, struct common_audit_data *auditdata,
		       unsigned flags)
{
	struct av_decision avd;
	int rc, rc2;

	rc = avc_has_perm_noaudit(ssid, tsid, tclass, requested, 0, &avd);

	rc2 = avc_audit(ssid, tsid, tclass, requested, &avd, rc, auditdata,
			flags);
	if (rc2)
		return rc2;
	return rc;
}

u32 avc_policy_seqno(void)
{
	return avc_cache.latest_notif;
}

void avc_disable(void)
{
	/*
	 * If you are looking at this because you have realized that we are
	 * not destroying the avc_node_cachep it might be easy to fix, but
	 * I don't know the memory barrier semantics well enough to know.  It's
	 * possible that some other task dereferenced security_ops when
	 * it still pointed to selinux operations.  If that is the case it's
	 * possible that it is about to use the avc and is about to need the
	 * avc_node_cachep.  I know I could wrap the security.c security_ops call
	 * in an rcu_lock, but seriously, it's not worth it.  Instead I just flush
	 * the cache and get that memory back.
	 */
	if (avc_node_cachep) {
		avc_flush();
		/* kmem_cache_destroy(avc_node_cachep); */
	}
}
