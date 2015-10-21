/*
 * Copyright (C) 2015 Google, Inc.
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

#include <linux/device-mapper.h>

#include "do_mounts_verity.h"

#ifdef CONFIG_ROOTDEV_ANDROID_VERITY
struct dm_setup_verity *
(*const get_verity_args)(const char *rootdev) __initconst
= verity_run_setup;
#endif

int __init dm_run_setup(const char *rootdev)
{
	struct mapped_device *md = NULL;
	struct dm_table *table = NULL;
	struct dm_setup_target *target;
	char *uuid;
	fmode_t fmode = FMODE_READ;
	struct dm_setup_verity *dm_setup_args;

	/* Finish parsing the targets. */
	dm_setup_args = get_verity_args(rootdev);
	if (IS_ERR_OR_NULL(dm_setup_args))
		goto parse_fail;

	uuid = dm_setup_args->uuid;

	if (dm_create(dm_setup_args->minor, &md)) {
		pr_init_err("failed to create the device");
		goto dm_create_fail;
	}
	pr_init_info("created device '%s'", dm_device_name(md));

	/* In addition to flagging the table below, the disk must be
	 * set explicitly ro/rw.
	 */
	set_disk_ro(dm_disk(md), dm_setup_args->ro);

	if (!dm_setup_args->ro)
		fmode |= FMODE_WRITE;
	if (dm_table_create(&table, fmode, dm_setup_args->target_count, md)) {
		pr_init_err("failed to create the table");
		goto dm_table_create_fail;
	}

	target = dm_setup_args->target;
	while (target) {
		pr_init_debug("adding target %llu %llu %s %s\n",
			(unsigned long long) target->begin,
			(unsigned long long) target->length, target->type,
			target->params);
		if (dm_table_add_target(table, target->type, target->begin,
					target->length, target->params)) {
			pr_init_err("failed to add the target to the table");
			goto add_target_fail;
		}
		target = target->next;
	}

	if (dm_table_complete(table)) {
		pr_init_err("failed to complete the table");
		goto table_complete_fail;
	}

	/* Suspend the device so that we can bind it to the table. */
	if (dm_suspend(md, 0)) {
		pr_init_err("failed to suspend the device pre-bind");
		goto suspend_fail;
	}

	/* Bind the table to the device. This is the only way to associate
	 * md->map with the table and set the disk capacity directly.
	 */
	if (dm_swap_table(md, table)) {  /* should return NULL. */
		pr_init_err("failed to bind the device to the table");
		goto table_bind_fail;
	}

	/* Finally, resume and the device should be ready. */
	if (dm_resume(md)) {
		pr_init_err("failed to resume the device");
		goto resume_fail;
	}

	/* Export the dm device via the ioctl interface */
	if (!strcmp(DM_NO_UUID, dm_setup_args->uuid))
		uuid = NULL;
	if (dm_ioctl_export(md, dm_setup_args->name, uuid)) {
		pr_init_err("failed to export device with given name and uuid");
		goto export_fail;
	}
	pr_init_info("dm: dm-%d is ready\n", dm_setup_args->minor);

	if (dm_setup_args->verity_setup_done)
		dm_setup_args->verity_setup_done(false);
	return 0;

export_fail:
resume_fail:
table_bind_fail:
suspend_fail:
table_complete_fail:
add_target_fail:
	dm_table_put(table);
dm_table_create_fail:
	dm_put(md);
dm_create_fail:
	if (dm_setup_args->verity_setup_done)
		dm_setup_args->verity_setup_done(true);
parse_fail:
	pr_init_err("dm: root dev verity setup failed\n");
	return -ENODEV;
}
