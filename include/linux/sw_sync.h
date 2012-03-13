/*
 * include/linux/sw_sync.h
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

#ifndef _LINUX_SW_SYNC_H
#define _LINUX_SW_SYNC_H

#include <linux/types.h>

#ifdef __KERNEL__

#include <linux/sync.h>

struct sw_sync_obj {
	struct	sync_obj	obj;

	u32			value;
};

struct sw_sync_pt {
	struct sync_pt		pt;

	u32			value;
};

struct sw_sync_obj *sw_sync_obj_create(void);
void sw_sync_obj_inc(struct sw_sync_obj *obj, u32 inc);

struct sync_pt *sw_sync_pt_create(struct sw_sync_obj *obj, u32 value);

#endif /* __KERNEL __ */

#define SW_SYNC_IOC_MAGIC	'W'

#define SW_SYNC_IOC_CREATE_FENCE	_IOWR(SW_SYNC_IOC_MAGIC, 0, __u32)
#define SW_SYNC_IOC_INC			_IOW(SW_SYNC_IOC_MAGIC, 1, __u32)


#endif /* _LINUX_SW_SYNC_H */
