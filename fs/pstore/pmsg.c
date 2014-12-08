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
		char buffer[512];
		size_t c = min(count - i, sizeof(buffer));
		u64 id;
		long ret;

		ret = __copy_from_user(buffer, buf + i, c);
		if (ret != 0)
			return -EFAULT;
		psinfo->write_buf(PSTORE_TYPE_PMSG, 0, &id, 0, buffer, c,
				  psinfo);

		i += c;
	}
	return count;
}

static const struct file_operations pmsg_fops = {
	.owner		= THIS_MODULE,
	.llseek		= pmsg_lseek,
	.write		= write_pmsg,
};

static struct class *pmsg_class;
static int pmsg_major;
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

	pmsg_major = register_chrdev(0, PMSG_NAME, &pmsg_fops);
	if (pmsg_major < 0) {
		pr_err(KERN_ERR "register_chrdev failed for pmsg\n");
		goto err;
	}

	pmsg_class = class_create(THIS_MODULE, PMSG_NAME);
	if (IS_ERR(pmsg_class)) {
		pr_err(KERN_ERR "pmsg: device class file already in use\n");
		goto err_class;
	}
	pmsg_class->devnode = pmsg_devnode;

	pmsg_device = device_create(pmsg_class, NULL, MKDEV(pmsg_major, 0),
					NULL, "%s%d", PMSG_NAME, 0);
	if (IS_ERR(pmsg_device)) {
		pr_err(KERN_ERR "pmsg: failed to create device\n");
		goto err_device;
	}
	return;

err_device:
	class_destroy(pmsg_class);
err_class:
	unregister_chrdev(pmsg_major, PMSG_NAME);
err:
	return;
}
