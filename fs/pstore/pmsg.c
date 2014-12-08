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

static ssize_t read_pmsg(struct file *file, char __user *buf,
			 size_t count, loff_t *ppos)
{
	return 0;
}

static ssize_t write_pmsg(struct file *file, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	size_t written;
	size_t c;
	const char __user *s;
	const char __user *e;

	if (!count)
		return 0;

	if (!access_ok(VERIFY_READ, buf, count))
		return -EFAULT;

	written = 0;
	c = count;
	s = buf;
	e = s + c;

	while (s < e) {
		unsigned long flags;
		u64 id;
		long ret;

		if (c > psinfo->bufsize)
			c = psinfo->bufsize;

		if (!oops_in_progress)
			spin_lock_irqsave(&psinfo->buf_lock, flags);
		else if (!spin_trylock_irqsave(&psinfo->buf_lock, flags))
			break;

		ret = copy_from_user(psinfo->buf, s, c);
		if (ret < 0) {
			spin_unlock_irqrestore(&psinfo->buf_lock, flags);
			return ret;
		}
		psinfo->write(PSTORE_TYPE_PMSG, 0, &id, 0, 0, c, psinfo);
		spin_unlock_irqrestore(&psinfo->buf_lock, flags);

		s += c;
		c = e - s;
	}
	return count;
}

static const struct file_operations pmsg_fops = {
	.llseek		= pmsg_lseek,
	.read		= read_pmsg,
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

int pstore_register_pmsg(void)
{
	int result;

	result = alloc_chrdev_region(&pmsg_dev, 0, 1, PMSG_NAME);
	if (result < 0) {
		pr_err(KERN_ERR "alloc_chrdev_region() failed for pmsg\n");
		return -ENODEV;
	}

	cdev_init(&pmsg_cdev, &pmsg_fops);
	pmsg_cdev.owner = THIS_MODULE;
	result = cdev_add(&pmsg_cdev, pmsg_dev, 1);

	if (result < 0) {
		unregister_chrdev_region(pmsg_dev, 1);
		pr_err(KERN_ERR "cdev_add() failed for pmsg\n");
		return -ENODEV;
	}

	pmsg_class = class_create(THIS_MODULE, PMSG_NAME);
	if (IS_ERR(pmsg_class)) {
		cdev_del(&pmsg_cdev);
		unregister_chrdev_region(pmsg_dev, 1);
		pr_err(KERN_ERR "pmsg: device class file already in use\n");
		return PTR_ERR(pmsg_class);
	}
	pmsg_class->devnode = pmsg_devnode;

	device_create(pmsg_class, NULL, pmsg_dev, NULL, "%s%d", PMSG_NAME, 0);
	return 0;
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
