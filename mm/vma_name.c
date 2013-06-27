/*
 * vma_name.c
 *
 * Copyright (C) 2013 Google, Inc.
 *
 * Author: Colin Cross <ccross@android.com>
 *
 * This file creates a cache of strings holding names for VMAs.  If
 * vma_name_get_from_str is called with a string that is already used to
 * name a VMA it is guaranteed to return the existing vma_name struct.  This
 * allows string equality checking by comparing the struct vma_name address.
 * The vma_name structures are stored in an rb tree, with the hash, length,
 * and string used as the key.  The vma_name is refcount protected, and the
 * rbtree is protected by a rwlock.  The write lock is required to decrement
 * any vma_name refcount from 1 to 0.
 */

#include <linux/atomic.h>
#include <linux/dcache.h>  /* for full_name_hash() and struct qstr */
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/mm_types.h>
#include <linux/rbtree.h>
#include <linux/rwlock.h>
#include <linux/slab.h>

static struct rb_root vma_name_cache = RB_ROOT;
static DEFINE_RWLOCK(vma_name_cache_lock);

/* refcounted cached name for one or more VMAs */
struct vma_name {
	struct rb_node rb_node;
	atomic_t refcount;

	unsigned int hash;
	unsigned int name_len;
	char name[0];
};

/**
 * vma_name_get
 *
 * Increment the refcount of an existing vma_name.  No locks are needed because
 * the caller should already be holding a reference, so refcount >= 1.
 */
void vma_name_get(struct vma_name *vma_name)
{
	if (WARN_ON(!vma_name))
		return;

	WARN_ON(!atomic_read(&vma_name->refcount));

	atomic_inc(&vma_name->refcount);
}

/**
 * vma_name_put
 *
 * Decrement the refcount of an existing vma_name and free it if necessary.
 * No locks needed, takes the cache lock if it needs to remove the vma_name from
 * the cache.
 */
void vma_name_put(struct vma_name *vma_name)
{
	int ret;

	if (WARN_ON(!vma_name))
		return;

	WARN_ON(!atomic_read(&vma_name->refcount));

	/* fast path: refcount > 1, decrement and return */
	if (atomic_add_unless(&vma_name->refcount, -1, 1))
		return;

	/* slow path: take the lock, decrement, and erase node if count is 0 */
	write_lock(&vma_name_cache_lock);

	ret = atomic_dec_return(&vma_name->refcount);
	if (ret == 0)
		rb_erase(&vma_name->rb_node, &vma_name_cache);

	write_unlock(&vma_name_cache_lock);

	if (ret == 0)
		kfree(vma_name);
}

/*
 * Find an existing struct vma_name node in the rb tree with matching hash and
 * name.  Returns the existing struct if found, without incrementing the
 * refcount.  If not found, adds new_vma_name to the rb tree if not NULL, and
 * returns new_vma_name.  Can be used to search the tree by passing new_vma_name
 * NULL.  Must be called with the read lock held if new_vma_name is NULL,
 * or the write lock if it is non-NULL.
 */
static struct vma_name *vma_name_tree_find_or_insert(struct qstr *name,
						struct vma_name *new_vma_name)
{
	struct vma_name *vma_name;
	struct rb_node **node = &vma_name_cache.rb_node;
	struct rb_node *parent = NULL;

	while (*node) {
		int cmp;

		vma_name = container_of(*node, struct vma_name, rb_node);

		cmp = name->hash - vma_name->hash;
		if (cmp == 0)
			cmp = name->len - vma_name->name_len;
		if (cmp == 0)
			cmp = strncmp(name->name, vma_name->name, name->len);

		parent = *node;
		if (cmp < 0)
			node = &((*node)->rb_left);
		else if (cmp > 0)
			node = &((*node)->rb_right);
		else
			return vma_name;
	}

	if (new_vma_name) {
		rb_link_node(&new_vma_name->rb_node, parent, node);
		rb_insert_color(&new_vma_name->rb_node, &vma_name_cache);
	}

	return new_vma_name;
}

/*
 * allocate a new vma_name structure and initialize it with the passed in name.
 */
static struct vma_name *vma_name_create(struct qstr *name)
{
	struct vma_name *vma_name;

	vma_name = kmalloc(sizeof(struct vma_name) + name->len + 1, GFP_KERNEL);
	if (!vma_name)
		return NULL;

	memcpy(vma_name->name, name->name, name->len);
	vma_name->name[name->len] = 0;
	vma_name->name_len = name->len;
	vma_name->hash = name->hash;
	atomic_set(&vma_name->refcount, 1);

	return vma_name;
}

/**
 * vma_name_get_from_str
 *
 * Find an existing struct vma_name * with name arg, or create a new one if
 * none exists.  First tries to find an existing one, if that fails then
 * drop the lock, allocate a new one, take the lock, and search again.  If
 * there is still no existing one, add the new one to the list.  Returns
 * NULL on error.
 */
struct vma_name *vma_name_get_from_str(const char *name, size_t name_len)
{
	struct vma_name *vma_name;
	struct vma_name *new_vma_name = NULL;
	struct qstr qstr = QSTR_INIT(name, strnlen(name, name_len));

	if (!qstr.len)
		return NULL;

	qstr.hash = full_name_hash(name, qstr.len);

	/* first look for an existing one */
	read_lock(&vma_name_cache_lock);

	vma_name = vma_name_tree_find_or_insert(&qstr, NULL);
	if (vma_name)
		vma_name_get(vma_name);

	read_unlock(&vma_name_cache_lock);

	if (vma_name)
		return vma_name;

	/* no existing one, allocate a new vma_name without the lock held */
	new_vma_name = vma_name_create(&qstr);
	if (!new_vma_name)
		return NULL;

	/* check again for existing ones that were added while we allocated */
	write_lock(&vma_name_cache_lock);

	vma_name = vma_name_tree_find_or_insert(&qstr, new_vma_name);
	if (vma_name == new_vma_name) {
		/* new node was inserted */
		vma_name = new_vma_name;
	} else {
		/* raced with another insert of the same name */
		vma_name_get(vma_name);
		kfree(new_vma_name);
	}

	write_unlock(&vma_name_cache_lock);

	return vma_name;
}

/**
 * vma_name_str
 *
 * Returns a pointer to the NULL terminated string holding the name of the
 * vma.  Must be called with a reference to the vma_name held.
 */
const char *vma_name_str(struct vma_name *vma_name)
{
	if (WARN_ON(!vma_name))
		return NULL;

	return vma_name->name;
}
