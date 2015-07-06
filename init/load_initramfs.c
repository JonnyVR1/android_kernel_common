/*
 * init/load_initramfs.c
 *
 * Copyright (C) 2015, Google
 * Rom Lemarchand <romlem@android.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
#include <linux/init.h>
#include <linux/initramfs.h>

static int __initdata do_skip_initramfs;

static int __init skip_initramfs_param(char *str)
{
	if (*str)
		return 0;
	do_skip_initramfs = 1;
	return 1;
}
__setup("skip_initramfs", skip_initramfs_param);

static int __init load_rootfs(void)
{
	if (do_skip_initramfs)
		return default_rootfs();

	return populate_rootfs();
}
rootfs_initcall(load_rootfs);
