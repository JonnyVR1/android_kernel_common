/*
 * Copyright 2014  Google, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include "internal.h"

static loff_t pmsg_lseek(struct file *file, loff_t offset, int orig)
{
	return file->f_pos = 0;
}

static ssize_t write_pmsg(struct file *file, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	size_t i;

	if (!count)
		return 0;

	if (!access_ok(VERIFY_READ, buf, count))
		return -EFAULT;

	for (i = 0; i < count; ) {
		size_t c = min(count - i, psinfo->bufsize);
		unsigned long flags;
		u64 id;
		long ret;

		if (!oops_in_progress)
			spin_lock_irqsave(&psinfo->buf_lock, flags);
		else if (!spin_trylock_irqsave(&psinfo->buf_lock, flags))
			break;

		ret = copy_from_user(psinfo->buf, buf + i, c);
		if (ret < 0) {
			spin_unlock_irqrestore(&psinfo->buf_lock, flags);
			return ret;
		}
		psinfo->write(PSTORE_TYPE_PMSG, 0, &id, 0, 0, c, psinfo);
		spin_unlock_irqrestore(&psinfo->buf_lock, flags);

		i += c;
	}
	return count;
}

static const struct file_operations pmsg_fops = {
	.llseek		= pmsg_lseek,
	.write		= write_pmsg,
};

static struct cdev pmsg_cdev;
static struct class *pmsg_class;
static dev_t pmsg_dev;
#define PMSG_NAME "pmsg"

static char *pmsg_devnode(struct device *dev, umode_t *mode)
{
	if (mode)
		*mode = 0220;
	return NULL;
}

void pstore_register_pmsg(void)
{
	struct device *pmsg_device;

	if (alloc_chrdev_region(&pmsg_dev, 0, 1, PMSG_NAME) < 0) {
		pr_err(KERN_ERR "alloc_chrdev_region() failed for pmsg\n");
		goto err;
	}

	cdev_init(&pmsg_cdev, &pmsg_fops);
	pmsg_cdev.owner = THIS_MODULE;

	if (cdev_add(&pmsg_cdev, pmsg_dev, 1) < 0) {
		pr_err(KERN_ERR "cdev_add() failed for pmsg\n");
		goto err_cdev;
	}

	pmsg_class = class_create(THIS_MODULE, PMSG_NAME);
	if (IS_ERR(pmsg_class)) {
		pr_err(KERN_ERR "pmsg: device class file already in use\n");
		goto err_class;
	}
	pmsg_class->devnode = pmsg_devnode;

	pmsg_device = device_create(pmsg_class, NULL, pmsg_dev, NULL,
					"%s%d", PMSG_NAME, 0);
	if (IS_ERR(pmsg_device)) {
		pr_err(KERN_ERR "pmsg: failed to create device\n");
		goto err_device;
	}
	return;

err_device:
	class_destroy(pmsg_class);
err_class:
	cdev_del(&pmsg_cdev);
err_cdev:
	unregister_chrdev_region(pmsg_dev, 1);
err:
	return;
}

#if 0
void pstore_unregister_pmsg(void)
{
	device_destroy(pmsg_class, pmsg_dev);
	class_destroy(pmsg_class);
	cdev_del(&pmsg_cdev);
	unregister_chrdev_region(pmsg_dev, 1);
}
#endif
