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

#include <linux/kernel.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sw_sync.h>
#include <linux/uaccess.h>

static void sw_sync_obj_free(struct kref *kref)
{
	struct sw_sync_obj* obj = container_of(kref, struct sw_sync_obj, kref);
	kfree(obj);
}

static void sw_sync_obj_get(struct sw_sync_obj *obj)
{
	kref_get(&obj->kref);
}

static void sw_sync_obj_put(struct sw_sync_obj *obj)
{
	kref_put(&obj->kref, sw_sync_obj_free);
}

static int sw_sync_pt_wait(struct sync_pt *sync_pt)
{
	struct sw_sync_pt *pt = (struct sw_sync_pt *)sync_pt;
	struct sw_sync_obj *obj = (struct sw_sync_obj *)sync_pt->parent;
	int err;

	/* TODO: deal with wrapping */
	err = wait_event_interruptible(obj->wq, (obj->value >= pt->value) || obj->destroyed);
	if (err < 0)
		return err;

	if (obj->destroyed)
		return -ENOENT;

	return 0;
}

static int sw_sync_pt_compare(struct sync_pt *a, struct sync_pt *b)
{
	struct sw_sync_pt *pt_a = (struct sw_sync_pt *)a;
	struct sw_sync_pt *pt_b = (struct sw_sync_pt *)b;
	int diff = pt_a->value - pt_b->value;
	/* TODO: deal with wrapping */
	return clamp(diff, -1, 1);
}

static void sw_sync_pt_release(struct sync_pt *sync_pt)
{
	struct sw_sync_obj *obj = (struct sw_sync_obj *)sync_pt->parent;

	sw_sync_obj_put(obj);
}

struct sync_obj_ops sw_sync_obj_ops = {
	.wait = sw_sync_pt_wait,
	.compare = sw_sync_pt_compare,
	.release = sw_sync_pt_release,
};

struct sw_sync_obj *sw_sync_obj_create(void)
{
	struct sw_sync_obj *obj;

	obj = kzalloc(sizeof(struct sw_sync_obj), GFP_KERNEL);
	if (obj == NULL)
		return NULL;

	init_waitqueue_head(&obj->wq);
	kref_init(&obj->kref);

	return obj;
}

void sw_sync_obj_destroy(struct sw_sync_obj *obj)
{
	obj->destroyed = true;
	wake_up(&obj->wq);
	sw_sync_obj_put(obj);
}

void sw_sync_obj_inc(struct sw_sync_obj *obj, u32 inc)
{
	/* TODO: deal with wrapping */
	obj->value += inc;

	wake_up(&obj->wq);
}

struct sw_sync_pt *sw_sync_pt_create(struct sw_sync_obj *obj, u32 value)
{
	struct sw_sync_pt *pt = (struct sw_sync_pt *)
		sync_pt_create(&obj->obj, sizeof(struct sw_sync_obj));

	if (pt == NULL)
		return NULL;
	sw_sync_obj_get(obj);
	pt->value = value;

	return pt;
}

#ifdef CONFIG_SW_SYNC_USER
/* *WARNING*
 *
 * improper use of this can result in deadlocking kernel drivers from userspace.
 */

/* opening sw_sync create a new sync obj */
int sw_sync_open(struct inode *inode, struct file *file)
{
	struct sw_sync_obj *obj;

	obj = sw_sync_obj_create();
	if (obj == NULL)
		return -ENOMEM;

	file->private_data = obj;

	return 0;
}

int sw_sync_release(struct inode *inode, struct file *file)
{
	struct sw_sync_obj *obj = file->private_data;
	sw_sync_obj_put(obj);
	return 0;
}

long sw_sync_ioctl_create_pt(struct sw_sync_obj *obj, unsigned long arg)
{
	int fd = get_unused_fd();
	int err = 0;
	u32 value;
	struct sw_sync_pt *pt;

	if (fd < 0)
		return fd;

	if (copy_from_user(&value, (void __user*)arg, sizeof(value))) {
		err = -EFAULT;
		goto err_put_fd;
	}

	pt = sw_sync_pt_create(obj, value);
	if (pt == NULL) {
		err = -ENOMEM;
		goto err_put_fd;
	}

	fd_install(fd, pt->pt.file);

	return fd;

err_put_fd:
	put_unused_fd(fd);
	return err;
}

long sw_sync_ioctl_inc(struct sw_sync_obj *obj, unsigned long arg)
{
	u32 value;

	if (copy_from_user(&value, (void __user*)arg, sizeof(value)))
		return -EFAULT;

	sw_sync_obj_inc(obj, value);

	return 0;
}

long sw_sync_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct sw_sync_obj *obj = file->private_data;

	switch (cmd) {
	case SW_SYNC_IOC_CREATE_PT:
		return sw_sync_ioctl_create_pt(obj, arg);

	case SW_SYNC_IOC_INC:
		return sw_sync_ioctl_inc(obj, arg);

	default:
		return -ENOTTY;
	}
}

static struct file_operations sw_sync_fops = {
	.owner = THIS_MODULE,
	.open = sw_sync_open,
	.release = sw_sync_release,
	.unlocked_ioctl = sw_sync_ioctl,
};

static struct miscdevice sw_sync_dev = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= "sw_sync",
	.fops	= &sw_sync_fops,
};

int __init sw_sync_device_init(void)
{
	return misc_register(&sw_sync_dev);
}

void __exit sw_sync_device_remove(void)
{
	misc_deregister(&sw_sync_dev);
}

module_init(sw_sync_device_init);
module_exit(sw_sync_device_remove);

#endif /* CONFIG_SW_SYNC_USER */
