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
#include <linux/slab.h>
#include <linux/sync.h>

#include <linux/anon_inodes.h>

int sync_pt_release(struct inode *inode, struct file *file)
{
	struct sync_pt *pt = file->private_data;

	if (pt->parent->ops->release)
		pt->parent->ops->release(pt);

	kfree(pt);

	return 0;
}

long sync_pt_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
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

	if (size < sizeof(struct sync_pt))
		return NULL;

	pt = kzalloc(size, GFP_KERNEL);
	if (pt == NULL)
		return NULL;

	pt->file = anon_inode_getfile("sync_pt", &sync_pt_fops, pt, 0);
	if (pt->file == NULL)
		goto err;

	pt->parent = parent;

	return pt;

err:
	kfree(pt);
	return NULL;
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
