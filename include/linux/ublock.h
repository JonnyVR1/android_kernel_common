/*
 * drivers/block/ublock.c
 *
 * Copyright (C) 2010 Google, Inc.
 *
 * Author:
 *     Thomas Tuttle <ttuttle@google.com>
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

#ifndef __UBLOCK_H_
#define __UBLOCK_H_

#include <linux/types.h>

#define UBLOCK_VERSION 0

enum {
	UBLOCK_INIT_IN = 0,
	UBLOCK_INIT_OUT,
	UBLOCK_READY_IN,
	UBLOCK_READY_OUT,
	UBLOCK_READ_IN,
	UBLOCK_READ_OUT,
	UBLOCK_WRITE_IN,
	UBLOCK_WRITE_OUT
};

struct ublock_in_header {
	__u32 seq;
	__u32 opcode;
};

struct ublock_out_header {
	__u32 seq;
	__u32 opcode;
};

struct ublock_init_in {
	__u32 version;
	__u32 max_buf;
	__u32 index;
};

struct ublock_init_out {
	__u32 version;
	__u32 max_buf;
	__u64 size;
};

struct ublock_ready_in {
	__u32 _unused;
};

struct ublock_ready_out {
	__u32 _unused;
};

struct ublock_read_in {
	__u64 offset;
	__u64 length;
};

struct ublock_read_out {
	__s32 status;
	__u8 data[];
};

struct ublock_write_in {
	__u64 offset;
	__u64 length;
	__u8 data[];
};

struct ublock_write_out {
	__s32 status;
};

#endif
