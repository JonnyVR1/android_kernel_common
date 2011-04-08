/*
 * drivers/gpu/ion/ion_mapper.c
 *
 * Copyright (C) 2011 Google, Inc.
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

#include <linux/err.h>
#include <linux/ion.h>
#include "ion_priv.h"

struct ion_mapper *ion_system_mapper_create(void);
void ion_system_mapper_destroy(struct ion_mapper *);

struct ion_mapper *ion_mapper_create(enum ion_mapper_type type)
{
	struct ion_mapper *mapper = NULL;

	switch (type) {
	case ION_SYSTEM_MAPPER:
		mapper = ion_system_mapper_create();
		break;
	default:
		pr_err("%s: invalid mapper type %d.\n", __func__, type);
		return ERR_PTR(-EINVAL);
	}
	return mapper;
}

void ion_mapper_destroy(struct ion_mapper *mapper)
{
	if (!mapper)
		return;

	switch (mapper->type) {
	case ION_SYSTEM_MAPPER:
		ion_system_mapper_destroy(mapper);
		break;
	default:
		pr_err("%s: invalid mapper type %d.\n", __func__, mapper->type);
	}
}
