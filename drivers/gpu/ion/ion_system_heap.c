/*
 * drivers/gpu/ion/ion_system_heap.c
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
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include "ion_priv.h"

static int ion_vmalloc_heap_allocate(struct ion_heap *heap,
				     struct ion_buffer *buffer,
				     unsigned long len, unsigned long align,
				     unsigned long flags)
{
	buffer->priv = vmalloc_user(len);
	if (!buffer->priv)
		return -ENOMEM;
	return 0;
}

void ion_vmalloc_heap_free(struct ion_buffer *buffer)
{
	vfree(buffer->priv);
}

static struct ion_heap_ops vmalloc_ops = {
	.allocate = ion_vmalloc_heap_allocate,
	.free = ion_vmalloc_heap_free,
};

struct ion_heap *ion_vmalloc_heap_create(void)
{
	struct ion_heap *heap;

	heap = kzalloc(sizeof(struct ion_heap), GFP_KERNEL);
	if (!heap)
		return ERR_PTR(-ENOMEM);
	heap->ops = &vmalloc_ops;
	heap->type = ION_HEAP_VMALLOC;
	return heap;
}

void ion_vmalloc_heap_destroy(struct ion_heap *heap)
{
	kfree(heap);
}

static int ion_kmalloc_heap_allocate(struct ion_heap *heap,
				     struct ion_buffer *buffer,
				     unsigned long len, unsigned long align,
				     unsigned long flags)
{
	buffer->priv = kzalloc(len, GFP_KERNEL);
	if (!buffer->priv)
		return -ENOMEM;
	return 0;

}

void ion_kmalloc_heap_free(struct ion_buffer *buffer)
{
	kfree(buffer->priv);
}

static struct ion_heap_ops kmalloc_ops = {
	.allocate = ion_kmalloc_heap_allocate,
	.free = ion_kmalloc_heap_free,
};

struct ion_heap *ion_kmalloc_heap_create(void)
{
	struct ion_heap *heap;

	heap = kzalloc(sizeof(struct ion_heap), GFP_KERNEL);
	if (!heap)
		return ERR_PTR(-ENOMEM);
	heap->ops = &kmalloc_ops;
	heap->type = ION_HEAP_KMALLOC;
	return heap;
}

void ion_kmalloc_heap_destroy(struct ion_heap *heap)
{
	kfree(heap);
}

