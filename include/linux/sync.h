/*
 * include/linux/sync.h
 *
 * Copyright (C) 2012 Google, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef _LINUX_SYNC_H
#define _LINUX_SYNC_H

#include <linux/types.h>
#ifdef __KERNEL__

#include <linux/kref.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/wait.h>

struct sync_obj;
struct sync_pt;

struct sync_obj_ops {
	/*
	 * return 1 if signaled
	 * return 0 if not signaled
	 * return <0 on error
	 */
	int (*test)(struct sync_pt *pt);

	/* return:
	 *  -1 if a will signal before b
	 *   0 if a and b will signal at the same time
	 *   1 if a will signal after b
	 */
	int (* compare)(struct sync_pt *a, struct sync_pt *b);

	void (* release_obj)(struct sync_obj *sync_obj);

	void (* release_pt)(struct sync_pt *sync_pt);
};

struct sync_obj {
	struct			sync_obj_ops *ops;

	struct kref		kref;
	bool			destroyed;
	wait_queue_head_t	wq;

	struct list_head	async_wait_list;
	spinlock_t		async_wait_lock;
};

struct sync_pt {
	struct sync_obj		*parent;
	struct file		*file;
};

struct sync_pt_callback {
	struct list_head	list;
	struct sync_pt		*pt;
	void (*callback)(struct sync_pt_callback *);
};

static inline void sync_pt_callback_init(struct sync_pt_callback *cb,
					 void (*callback)(struct sync_pt_callback *))
{
	cb->callback = callback;
}


int sync_pt_wait(struct sync_pt *sync_pt);

/* returns:
 *  -1 if a will signal before b
 *   0 if a and b will signal at the same time
 *   1 if a will signal after b
 *
 *  -2 if a and b are children of different sync_objs
 */
static inline int sync_pt_compare(struct sync_pt *a, struct sync_pt *b)
{
	if (a->parent != b->parent)
		return -2;

	return a->parent->ops->compare(a, b);
}

struct sync_pt *sync_pt_create(struct sync_obj *parent, int size);
struct sync_pt *sync_pt_get(int fd);

/* returns an fd in the current processes file table pointing to this
 * sync_pt.  If you need to "uninstall" the fd before returning it to
 * user space (i.e. error condtions) call sys_close() on the fd
 */
int sync_pt_install(struct sync_pt *pt);
void sync_pt_put(struct sync_pt *pt);


struct sync_obj *sync_obj_create(struct sync_obj_ops *ops, int size);

/*
 * tears down a sync object.  Won't actually be released until all
 * it's sync_pt children are released
 */
void sync_obj_destroy(struct sync_obj *obj);

/* call this when the sync obj's value has changed or an error condtion is
 * present.  All waiters will be notified.
 */
void sync_obj_signal(struct sync_obj *obj);

#endif /* __KERNEL__ */

#define SYNC_IOC_MAGIC		'S'

#define SYNC_IOC_WAIT		_IO(SYNC_IOC_MAGIC, 0)


#endif /* _LINUX_SYNC_H */
