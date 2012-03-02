/*
 * drivers/base/sync.c
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

#include <linux/file.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/sync.h>

#include <linux/anon_inodes.h>

static void sync_obj_free(struct kref *kref)
{
	struct sync_obj* obj = container_of(kref, struct sync_obj, kref);

	if(obj->ops->release_obj)
		obj->ops->release_obj(obj);

	kfree(obj);
}

static void sync_obj_get(struct sync_obj *obj)
{
	kref_get(&obj->kref);
}

static void sync_obj_put(struct sync_obj *obj)
{
	kref_put(&obj->kref, sync_obj_free);
}



static int sync_pt_release(struct inode *inode, struct file *file)
{
	struct sync_pt *pt = file->private_data;

	if (pt->parent->ops->release_pt)
		pt->parent->ops->release_pt(pt);

	sync_obj_put(pt->parent);
	kfree(pt);

	return 0;
}

static long sync_pt_ioctl(struct file *file, unsigned int cmd,
			  unsigned long arg)
{
	struct sync_pt *pt = file->private_data;
	switch (cmd) {
	case SYNC_IOC_WAIT:
		return sync_pt_wait(pt);

	default:
		return -ENOTTY;
	}
}

static struct file_operations sync_pt_fops = {
	.release = sync_pt_release,
	.unlocked_ioctl = sync_pt_ioctl,
};

struct sync_pt *sync_pt_create(struct sync_obj *parent, int size)
{
	struct sync_pt *pt;

	if (parent->destroyed)
		return NULL;

	if (size < sizeof(struct sync_pt))
		return NULL;

	pt = kzalloc(size, GFP_KERNEL);
	if (pt == NULL)
		return NULL;

	pt->file = anon_inode_getfile("sync_pt", &sync_pt_fops, pt, 0);
	if (pt->file == NULL)
		goto err;

	pt->parent = parent;

	sync_obj_get(parent);

	return pt;

err:
	kfree(pt);
	return NULL;
}

static int sync_pt_test(struct sync_pt *pt) {
	struct sync_obj *obj = pt->parent;
	int ret;

	ret = obj->ops->test(pt);

	if (ret != 0)
		return ret;

	if (obj->destroyed)
		return -ENOENT;

	return 0;
}

int sync_pt_wait(struct sync_pt *pt)
{
	struct sync_obj *obj = pt->parent;
	int err;
	int ret;

	err = wait_event_interruptible(obj->wq, (ret = sync_pt_test(pt)));
	if (err < 0)
		return err;

	if (ret < 0)
		return ret;

	return 0;
}

int sync_pt_wait_async(struct sync_pt *pt, struct sync_pt_callback *cb)
{
	struct sync_obj *obj = pt->parent;
	unsigned long flags;
	int err;

	spin_lock_irqsave(&obj->async_wait_lock, flags);

	err = sync_pt_test(pt);
	if (err < 0)
		goto err;

	if (err > 0) {
		err = -ETIME;
		goto err;
	}

	cb->pt = pt;
	list_add_tail(&cb->list, &obj->async_wait_list);

	spin_unlock_irqrestore(&obj->async_wait_lock, flags);

err:
	return err;
}

struct sync_pt *sync_pt_get(int fd)
{
	struct file *file = fget(fd);

	if (file == NULL)
		return NULL;

	if (file->f_op != &sync_pt_fops)
		goto err;

	return file->private_data;

err:
	fput(file);
	return NULL;
}

int sync_pt_install(struct sync_pt *pt)
{
	int fd = get_unused_fd();
	if (fd < 0)
		return fd;

	fd_install(fd, pt->file);
	return fd;
}

void sync_pt_put(struct sync_pt *pt)
{
	fput(pt->file);
}

struct sync_obj *sync_obj_create(struct sync_obj_ops *ops, int size)
{
	struct sync_obj *obj;

	if (size < sizeof(struct sync_obj))
		return NULL;

	obj = kzalloc(size, GFP_KERNEL);
	if (obj == NULL)
		return NULL;

	obj->ops = ops;
	init_waitqueue_head(&obj->wq);
	kref_init(&obj->kref);

	INIT_LIST_HEAD(&obj->async_wait_list);
	spin_lock_init(&obj->async_wait_lock);

	return obj;
}

void sync_obj_destroy(struct sync_obj *obj)
{
	obj->destroyed = true;
	wake_up(&obj->wq);
	sync_obj_put(obj);
}

void sync_obj_signal(struct sync_obj *obj)
{
	unsigned long flags;
	LIST_HEAD(signaled_pts);
	struct list_head *cb_head, *n;

	spin_lock_irqsave(&obj->async_wait_lock, flags);

	list_for_each_safe(cb_head, n, &obj->async_wait_list) {
		struct sync_pt_callback *cb =
			container_of(cb_head, struct sync_pt_callback, list);

		if (obj->ops->test(cb->pt))
			list_move(&cb->list, &signaled_pts);
	}

	spin_unlock_irqrestore(&obj->async_wait_lock, flags);

	list_for_each_safe(cb_head, n, &signaled_pts) {
		struct sync_pt_callback *cb =
			container_of(cb_head, struct sync_pt_callback, list);

		cb->callback(cb);

		/* not strictly neccssary but leaves cb->list poisoned */
		list_del(cb_head);
	}

	wake_up(&obj->wq);
}
