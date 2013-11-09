/*
 *
 * Copyright (C) 2013 Google, Inc.
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

#define pr_fmt(fmt) "ion-test: " fmt

#include <linux/compat.h>

#include "ion.h"

struct compat_ion_test_rw_data {
	compat_uptr_t ptr;
	compat_u64 offset;
	compat_u64 size;
	compat_int_t write;
};

#define COMPAT_ION_IOC_TEST_DMA_MAPPING \
		_IOW(ION_IOC_MAGIC, 0xf1, struct compat_ion_test_rw_data)
#define COMPAT_ION_IOC_TEST_KERNEL_MAPPING \
		_IOW(ION_IOC_MAGIC, 0xf2, struct compat_ion_test_rw_data)

static int compat_get_ion_test_rw_data(
			struct compat_ion_test_rw_data __user *data32,
			struct ion_test_rw_data __user *data)
{
	compat_uptr_t p;
	compat_u64 u;
	compat_int_t i;
	int err;

	err = get_user(p, &data32->ptr);
	err |= put_user(p, &data->ptr);
	err |= get_user(u, &data32->offset);
	err |= put_user(u, &data->offset);
	err |= get_user(u, &data32->size);
	err |= put_user(u, &data->size);
	err |= get_user(i, &data32->write);
	err |= put_user(i, &data->write);

	return err;
}

static int compat_put_ion_test_rw_data(
			struct compat_ion_test_rw_data __user *data32,
			struct ion_test_rw_data __user *data)
{
	compat_uptr_t p;
	compat_u64 u;
	compat_int_t i;
	int err;

	err = get_user(p, &data->ptr);
	err |= put_user(p, &data32->ptr);
	err |= get_user(u, &data->offset);
	err |= put_user(u, &data32->offset);
	err |= get_user(u, &data->size);
	err |= put_user(u, &data32->size);
	err |= get_user(i, &data->write);
	err |= put_user(i, &data32->write);

	return err;
}

long compat_ion_test_ioctl(struct file *filp, unsigned int cmd,
						unsigned long arg)
{
	long ret;

	if (!filp->f_op || !filp->f_op->unlocked_ioctl)
		return -ENOTTY;

	switch (cmd) {
	case COMPAT_ION_IOC_TEST_DMA_MAPPING:
	case COMPAT_ION_IOC_TEST_KERNEL_MAPPING:
	{
		struct compat_ion_test_rw_data __user *data32;
		struct ion_test_rw_data __user *data;
		unsigned int new_cmd;
		new_cmd = _IOW(_IOC_TYPE(cmd), _IOC_NR(cmd), sizeof(*data));

		data32 = compat_ptr(arg);
		data = compat_alloc_user_space(sizeof(*data));
		if (data == NULL)
			return -EFAULT;

		ret = compat_get_ion_test_rw_data(data32, data);
		if (ret)
			return ret;
		ret = filp->f_op->unlocked_ioctl(filp, new_cmd,
							(unsigned long)data);
		if (ret)
			return ret;

		ret = compat_put_ion_test_rw_data(data32, data);
		break;
	}
	default:
		ret = filp->f_op->unlocked_ioctl(filp, cmd, arg);
	return ret;
}
