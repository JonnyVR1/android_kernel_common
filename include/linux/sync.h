/*
 * include/linux/sync.h
 *
 * Copyright (C) 2012 Google, Inc.
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

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/wait.h>

struct sync_obj;
struct sync_pt;
struct sync_fence;

struct sync_obj_ops {
	const char *	name;

	/* required */
	struct sync_pt *(* dup)(struct sync_pt *pt);

	/* required
	 *
	 * return:
	 *   1 if signaled
	 *   0 if not signaled
	 *  <0 on error
	 */
	int (*test)(struct sync_pt *pt);

	/* required
	 *
	 * return:
	 *  -1 if a will signal before b
	 *   0 if a and b will signal at the same time
	 *   1 if a will signal after b
	 */
	int (* compare)(struct sync_pt *a, struct sync_pt *b);

	/* optional */
	void (* free_pt)(struct sync_pt *sync_pt);

	/* optional */
	void (* release_obj)(struct sync_obj *sync_obj);

};

struct sync_obj {
	const struct sync_obj_ops	*ops;

	bool			destroyed;

	struct list_head	child_list_head;
	spinlock_t		child_list_lock;

	struct list_head	active_list_head;
	spinlock_t		active_list_lock;
};

struct sync_pt {
	struct sync_obj		*parent;
	struct list_head	child_list;

	struct list_head	active_list;

	struct sync_fence	*fence;
	struct list_head	pt_list;

	int			status; /* protected by parent->active_list_lock */
};

struct sync_fence {
	struct file		*file;

	/* this list is immutable once the fence is created */
	struct list_head	pt_list_head;

	struct list_head	waiter_list_head;
	spinlock_t		waiter_list_lock; /* also protects signaled */
	int			status;

	wait_queue_head_t	wq;
};

struct sync_fence_waiter {
	struct list_head	waiter_list;

	void (*callback)(struct sync_fence *, void *data);
	void *callback_data;
};

struct sync_obj *sync_obj_create(const struct sync_obj_ops *ops, int size);
void sync_obj_destroy(struct sync_obj *obj);
void sync_obj_signal(struct sync_obj *obj);

struct sync_pt *sync_pt_create(struct sync_obj *parent, int size);
void sync_pt_free(struct sync_pt *pt);

struct sync_fence *sync_fence_create(struct sync_pt *pt);
struct sync_fence *sync_fence_merge(struct sync_fence *a, struct sync_fence *b);
struct sync_fence *sync_fence_fdget(int fd);
void sync_fence_put(struct sync_fence *fence);
void sync_fence_install(struct sync_fence *fence, int fd);

/* returns 1 if fence has already signaled */
int sync_fence_wait_async(struct sync_fence *fence,
			  void (*callback)(struct sync_fence *, void *data),
			  void *callback_data);
int sync_fence_wait(struct sync_fence *fence, long timeout);

#endif /* __KERNEL__ */

#define SYNC_IOC_MAGIC		'S'

/* pass timeout in msecs.  zero for infinte timeout */
#define SYNC_IOC_WAIT		_IOW(SYNC_IOC_MAGIC, 0, __u32)
#define SYNC_IOC_MERGE		_IOWR(SYNC_IOC_MAGIC, 1, __u32)

#endif /* _LINUX_SYNC_H */
