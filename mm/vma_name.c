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
 * The vma_name structures are refcount protected, and the list is protected by
 * a spinlock.
 */

#include <linux/atomic.h>
#include <linux/dcache.h>  /* for full_name_hash() */
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/list.h>
#include <linux/mm_types.h>
#include <linux/rbtree.h>
#include <linux/rwlock.h>
#include <linux/slab.h>

static struct rb_root vma_name_cache = RB_ROOT;
static DEFINE_RWLOCK(vma_name_cache_lock);

/* refcounted cached name for one or more VMAs */
struct vma_name {
	struct rb_node rb_node;
	struct list_head list_node;
	atomic_t refcount;

	unsigned int hash;
	char name[0];
};

/*
 * Increment the refcount on an existing vma_name.
 *
 * Returns 0 on success, negative if the vma_name is going away.
 */
static int __vma_name_get(struct vma_name *vma_name)
{
	if (atomic_inc_not_zero(&vma_name->refcount))
		return 0;

	return -EINVAL;
}

/*
 * Decrement the refcount on an existing vma_name, and free it if the refcount
 * is zero. Takes the list lock if it needs to remove the vma_name from the
 * list.
 */
static void __vma_name_put(struct vma_name *vma_name)
{
	WARN_ON(!atomic_read(&vma_name->refcount));
	if (atomic_dec_and_test(&vma_name->refcount)) {
		write_lock(&vma_name_cache_lock);
		if (!list_empty(&vma_name->list_node)) {
			list_del(&vma_name->list_node);
		} else {
			rb_erase(&vma_name->rb_node, &vma_name_cache);
		}
		write_unlock(&vma_name_cache_lock);
		kfree(vma_name);
	}
}

/*
 * In case of hash collisions, or a vma_name struct that has refcount 0 and is
 * going away, each vma_name node may also be a list head of vma names with the
 * same hash.  Walk the list, including the list head, looking for a matching
 * name and refcount > 0, and return the existing  struct with refcount
 * incremented if found, or NULL if not found.
 * Must be called with the list read or write lock held.
 */
static struct vma_name *vma_name_list_search(struct vma_name *vma_name,
					     const char *name, size_t len)
{
	struct list_head *head = &vma_name->list_node;

	if (!strncmp(vma_name->name, name, len))
		return vma_name;

	list_for_each_entry(vma_name, head, list_node)
		if (!strncmp(vma_name->name, name, len))
			if (!__vma_name_get(vma_name))
				return vma_name;

	return NULL;
}

/*
 * Find an existing struct vma_name node in the rb tree with matching hash.
 * Returns the existing struct without incrementing the refcount if found.
 * If not found, adds new_vma_name to the rb tree if not NULL, and returns
 * new_vma_name.  Can be used to search the tree by passing new_vma_name NULL.
 * Must be called with the list read or write lock held.
 */
static struct vma_name *vma_name_tree_search_or_insert(unsigned int hash,
						struct vma_name *new_vma_name)
{
	struct vma_name *vma_name_head;
	struct rb_node **node = &vma_name_cache.rb_node;
	struct rb_node *parent = NULL;

	while (*node) {
		vma_name_head = container_of(*node, struct vma_name, rb_node);

		parent = *node;
		if (hash < vma_name_head->hash)
			node = &((*node)->rb_left);
		else if (hash > vma_name_head->hash)
			node = &((*node)->rb_right);
		else
			return vma_name_head;
	}

	if (new_vma_name) {
		rb_link_node(&new_vma_name->rb_node, parent, node);
		rb_insert_color(&new_vma_name->rb_node, &vma_name_cache);
	}

	return new_vma_name;
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
	int len;
	struct vma_name *vma_name_head;
	struct vma_name *vma_name = NULL;
	struct vma_name *new_vma_name = NULL;
	unsigned int hash;

	len = strnlen(name, name_len);
	if (!len)
		return NULL;

	hash = full_name_hash(name, len);

	/* first look for an existing one */
	read_lock(&vma_name_cache_lock);

	vma_name_head = vma_name_tree_search_or_insert(hash, NULL);
	if (vma_name_head)
		vma_name = vma_name_list_search(vma_name_head, name, len);

	read_unlock(&vma_name_cache_lock);

	if (vma_name)
		return vma_name;

	/* no existing one, allocate a new vma_name without the lock held */
	new_vma_name = kzalloc(sizeof(struct vma_name) + len + 1, GFP_KERNEL);
	if (!new_vma_name)
		return NULL;

	INIT_LIST_HEAD(&new_vma_name->list_node);
	memcpy(new_vma_name->name, name, len);
	new_vma_name->name[len] = 0;
	atomic_set(&new_vma_name->refcount, 1);

	/* check again for existing ones that were added while we allocated */
	write_lock(&vma_name_cache_lock);

	vma_name_head = vma_name_tree_search_or_insert(hash, new_vma_name);
	if (vma_name_head == new_vma_name) {
		/* new node was inserted */
		vma_name = new_vma_name;
	} else {
		/* matching node found, node was not inserted */
		vma_name = vma_name_list_search(vma_name_head, name, len);

		if (vma_name) {
			/* exact match exists, free the new one */
			kfree(new_vma_name);
		} else {
			/* hash collision, add node to the end of the list */
			list_add_tail(&new_vma_name->list_node,
				      &vma_name_head->list_node);
			vma_name = new_vma_name;
		}
	}

	write_unlock(&vma_name_cache_lock);
	return vma_name;
}

/**
 * vma_name_get
 *
 * Increment the refcount of an existing vma_name.  No locks are needed because
 * the caller should already be holding a reference, so refcount >= 1.
 */
void vma_name_get(struct vma_name *vma_name)
{
	int ret;

	if (WARN_ON(!vma_name))
		return;

	ret = __vma_name_get(vma_name);
	/* Should never fail, the caller should already have a reference */
	WARN_ON(ret);
}

/**
 * vma_name_put
 *
 * Decrement the refcount of an existing vma_name and free it if necessary.
 * No locks needed, __vma_name_put will take the list lock if necessary.
 */
void vma_name_put(struct vma_name *vma_name)
{
	if (WARN_ON(!vma_name))
		return;

	/* vma_name_get returned an error, nothing to do */
	if (IS_ERR(vma_name))
		return;

	__vma_name_put(vma_name);
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
