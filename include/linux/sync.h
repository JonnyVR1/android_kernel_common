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

struct sync_obj;
struct sync_pt;

struct sync_obj_ops {
	/* wait synchronously until sync_pt is signaled */
	int (* wait)(struct sync_pt *sync_pt);

	/* return:
	 *  -1 if a will signal before b
	 *   0 if a and b will signal at the same time
	 *   1 if a will signal after b
	 */
	int (* compare)(struct sync_pt *a, struct sync_pt *b);

	void (* release)(struct sync_pt *sync_pt);

	/* TODO: async api */
	/* maybe implement an is atomic comaptabile */
};

struct sync_obj {
	struct	sync_obj_ops *ops;
};

struct sync_pt {
	struct sync_obj		*parent;
	struct file		*file;
};


static inline int sync_pt_wait(struct sync_pt *sync_pt)
{
	return sync_pt->parent->ops->wait(sync_pt);
}

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
int sync_pt_install(struct sync_pt *pt);
void sync_pt_put(struct sync_pt *pt);

#endif /* __KERNEL__ */

#define SYNC_IOC_MAGIC		'S'

#define SYNC_IOC_WAIT		_IO(SYNC_IOC_MAGIC, 0)


#endif /* _LINUX_SYNC_H */
