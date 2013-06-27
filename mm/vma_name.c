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
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/list.h>
#include <linux/mm_types.h>
#include <linux/rwlock.h>
#include <linux/slab.h>

static LIST_HEAD(vma_name_list);
static DEFINE_RWLOCK(vma_name_list_lock);

/* refcounted cached name for one or more VMAs */
struct vma_name {
	struct list_head node;
	atomic_t refcount;

	int name_len;
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
		write_lock(&vma_name_list_lock);
		list_del(&vma_name->node);
		write_unlock(&vma_name_list_lock);
		kfree(vma_name);
	}
}

/*
 * Find an existing struct vma_name * with name arg and refcount > 0. Returns
 * the existing struct with refcount incremented if found, NULL if not found.
 * Must be called with the list lock held.
 */
static struct vma_name *__vma_name_get_from_str(const char *name, size_t len)
{
	struct vma_name *vma_name;

	list_for_each_entry(vma_name, &vma_name_list, node)
		if (vma_name->name_len == len &&
		    strncmp(name, vma_name->name, len) == 0)
			if (!__vma_name_get(vma_name))
				return vma_name;

	return NULL;
}

/**
 * vma_name_get_from_str
 *
 * Find an existing struct vma_name * with name arg, or create a new one if
 * none exists.  First tries to find an existing one, if that fails then
 * drop the lock, allocate a new one, take the lock, and search again.  If
 * there is still no existing one, add the new one to the list.
 */
struct vma_name *vma_name_get_from_str(const char *arg)
{
	int len;
	struct vma_name *vma_name;
	struct vma_name *new_vma_name = NULL;

	len = strnlen(arg, NAME_MAX);

	/* first look for an existing one */
	read_lock(&vma_name_list_lock);

	vma_name = __vma_name_get_from_str(arg, len);
	if (vma_name)
		goto out;

	read_unlock(&vma_name_list_lock);

	/* no existing one, allocate a new vma_name without the lock held */
	new_vma_name = kzalloc(sizeof(struct vma_name) + len + 1, GFP_KERNEL);
	INIT_LIST_HEAD(&new_vma_name->node);
	memcpy(new_vma_name->name, arg, len);
	new_vma_name->name[len] = 0;
	new_vma_name->name_len = len;
	atomic_set(&new_vma_name->refcount, 1);

	/* check again for existing ones that were added while we allocated */
	write_lock(&vma_name_list_lock);

	vma_name = __vma_name_get_from_str(arg, len);
	if (vma_name) {
		kfree(new_vma_name);
		goto out;
	}

	/* still not there, add the newly created one */
	list_add(&new_vma_name->node, &vma_name_list);
	vma_name = new_vma_name;

out:
	write_unlock(&vma_name_list_lock);
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
