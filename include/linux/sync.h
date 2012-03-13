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

/**
 * struct sync_obj_ops - sync object implementation ops
 * @name:		name of the implentation
 * @dup:		duplicate a sync_pt
 * @has_signaled:	returns:
 *			  1 if pt has signaled
 *			  0 if pt has not signaled
 *			 <0 on error
 * @compare:		returns:
 *			  1 if b will signal before a
 *			  0 if a and b will signal at the same time
 *			 -1 if a will signabl before b
 * @free_pt:		called before sync_pt is freed
 * @release_obj:	called before sync_obj is freed
 */
struct sync_obj_ops {
	const char * name;

	/* required */
	struct sync_pt *(*dup)(struct sync_pt *pt);

	/* required */
	int (*has_signaled)(struct sync_pt *pt);

	/* required */
	int (*compare)(struct sync_pt *a, struct sync_pt *b);

	/* optional */
	void (*free_pt)(struct sync_pt *sync_pt);

	/* optional */
	void (*release_obj)(struct sync_obj *sync_obj);
};

/**
 * struct sync_obj - sync object
 * @ops:		ops that define the implementaiton of the sync_obj
 * @destoryed:		set when sync_obj is destroyed
 * @child_list_head:	list of children sync_pts for this sync_obj
 * @child_list_lock:	lock protecting @child_list_head, destroyed, and
 *			  sync_pt.status
 * @active_list_head:	list of active (unsignaled/errored) sync_pts
 */
struct sync_obj {
	const struct sync_obj_ops	*ops;

	bool			destroyed; /* protected by child_list_lock */

	struct list_head	child_list_head;
	spinlock_t		child_list_lock;

	struct list_head	active_list_head;
	spinlock_t		active_list_lock;
};

/**
 * struct sync_pt - sync point
 * @parent:		sync_obj to which this sync_pt belongs
 * @child_list:		membership in sync_obj.child_list_head
 * @active_list:	membership in sync_obj.active_list_head
 * @fence:		sync_fence to which the sync_pt belongs
 * @pt_list:		membership in sync_fence.pt_list_head
 * @status:		1: signaled, 0:active, <0: error
 */
struct sync_pt {
	struct sync_obj		*parent;
	struct list_head	child_list;

	struct list_head	active_list;

	struct sync_fence	*fence;
	struct list_head	pt_list;

	int			status; /* protected by parent->active_list_lock */
};

/**
 * struct sync_fence - sync fence
 * @file:		file representing this fence
 * @pt_list_head:	list of sync_pts in ths fence.  immutable once fence
 *			  is created
 * @waiter_list_head:	list of asynchronous waiters on this fence
 * @waiter_list_lock:	lock protecting @waiter_list_head and @status
 * @status:		1: signaled, 0:active, <0: error
 *
 * @wq:			wait queue for fence signaling
 */
struct sync_fence {
	struct file		*file;

	/* this list is immutable once the fence is created */
	struct list_head	pt_list_head;

	struct list_head	waiter_list_head;
	spinlock_t		waiter_list_lock; /* also protects status */
	int			status;

	wait_queue_head_t	wq;
};

/**
 * struct sync_fence_waiter - metadata for asynchronous waiter on a fence
 * @waiter_list:	membership in sync_fence.waiter_list_head
 * @callback:		function pointer to call when fence signals
 * @callback_data:	pointer to pass to @callback
 */
struct sync_fence_waiter {
	struct list_head	waiter_list;

	void (*callback)(struct sync_fence *fence, void *data);
	void *callback_data;
};

/*
 * API for sync_obj implementers
 */

/**
 * sync_obj_create() - creates a sync object
 * @ops:	specifies the implemention ops for the object
 * @size:	size to allocate for this obj
 *
 * Creates a new sync_obj which will use the implemetation specified by
 * @ops.  @size bytes will be allocated allowing for implemntation specific
 * data to be kept after the generic sync_obj stuct.
 */
struct sync_obj *sync_obj_create(const struct sync_obj_ops *ops, int size);


/**
 * sync_obj_destory() - destorys a sync object
 * @obj:	sync_obj to destroy
 *
 * A sync implemntation should call this when the @obj is going away
 * (i.e. module unload.)  @obj won't actually be freed until all its childern
 * sync_pts are freed.
 */
void sync_obj_destroy(struct sync_obj *obj);

/**
 * sync_obj_signal() - signal a status change on a sync_obj
 * @obj:	sync_obj to signal
 *
 * A sync implemntation should call this any time one of it's sync_pts
 * has signaled or has an error condition.
 */
void sync_obj_signal(struct sync_obj *obj);

/**
 * sync_pt_create() - creates a sync pt
 * @parent:	sync_pt's parent sync_obj
 * @size:	size to allocate for this pt
 *
 * Creates a new sync_pt as a chiled of @parent.  @size bytes will be
 * allocated allowing for implemntation specific data to be kept after
 * the generic sync_obj stuct.
 */
struct sync_pt *sync_pt_create(struct sync_obj *parent, int size);

/**
 * sync_pt_free() - frees a sync pt
 * @pt:		sync_pt to free
 *
 * This should only be called on sync_pts which have been created but
 * not added to a fence.
 */
void sync_pt_free(struct sync_pt *pt);

/**
 * sync_fence_create() - creates a sync fence
 * @pt:		sync_pt to add to the fence
 *
 * Creates a fence containg @pt.  Once this is called, the fence takes
 * ownership of @pt.
 */
struct sync_fence *sync_fence_create(struct sync_pt *pt);

/*
 * API for sync_fence consumers
 */

/**
 * sync_fence_merge() - merge two fences
 * @a:		fence a
 * @b:		fence b
 *
 * Creates a new fence which contains copies of all the sync_pts in both
 * @a and @b.  @a and @b remain valid, independant fences.
 */
struct sync_fence *sync_fence_merge(struct sync_fence *a, struct sync_fence *b);

/**
 * sync_fence_fdget() - get a fence from an fd
 * @fd:		fd referencing a fence
 *
 * Ensures @fd references a valid fence, increments the refcount of the backing
 * file, and returns the fence.
 */
struct sync_fence *sync_fence_fdget(int fd);

/**
 * sync_fence_put() - puts a refernnce of a sync fence
 * @fence:	fence to put
 *
 * Puts a reference on @fence.  If this is the last reference, the fence and
 * all it's sync_pts will be freed
 */
void sync_fence_put(struct sync_fence *fence);

/**
 * sync_fence_install() - installs a fence into a file descriptor
 * @fence:	fence to instal
 * @fd:		file descriptor in which to install the fence
 *
 * Installs @fence into @fd.  @fd's should be acquired through get_unused_fd().
 */
void sync_fence_install(struct sync_fence *fence, int fd);

/**
 * sync_fence_wait_async() - registers and async wait on the fence
 * @fence:		fence to wait on
 * @callback:		callback
 * @callback_data	data to pass to the callback
 *
 * Returns 1 if @fence has already signaled.
 *
 * Registers a callback to be called when @fence signals or has an error
 */
int sync_fence_wait_async(struct sync_fence *fence,
			  void (*callback)(struct sync_fence *, void *data),
			  void *callback_data);

/**
 * sync_fence_wait() - wait on fence
 * @fence:	fence to wait on
 * @tiemout:	timeout in ms
 *
 * Wait for @fence to be signaled or have an error.  Wait's indefintly
 * if @timeout = 0
 */
int sync_fence_wait(struct sync_fence *fence, long timeout);

#endif /* __KERNEL__ */

#define SYNC_IOC_MAGIC		'>'

/**
 * DOC: SYNC_IOC_WAIT - wait for a fence to signal
 *
 * pass timeout in miliseconds.
 */
#define SYNC_IOC_WAIT		_IOW(SYNC_IOC_MAGIC, 0, __u32)

/**
 * DOC: SYNC_IOC_MERGE - merge two fences
 *
 * Pass the ioctl the fd of the second fence.  Creates a new fence containing
 * copies of the sync_pts in both the calling fd and passed fd.  Returns the
 * new fence's fd.
 */
#define SYNC_IOC_MERGE		_IOWR(SYNC_IOC_MAGIC, 1, __u32)

#endif /* _LINUX_SYNC_H */
