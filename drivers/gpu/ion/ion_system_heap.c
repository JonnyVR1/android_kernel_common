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

#include <asm/page.h>
#include <linux/dma-mapping.h>
#include <linux/err.h>
#include <linux/highmem.h>
#include <linux/ion.h>
#include <linux/mm.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include "ion_priv.h"

static unsigned int orders[] = {8, 4, 0};
static int num_orders = ARRAY_SIZE(orders);
static unsigned int order_to_size(int order)
{
	return (1 << (order)) * PAGE_SIZE;
}

struct ion_system_heap {
	struct ion_heap heap;
	struct ion_mem_pool **pools;
};

struct page_info {
	struct page *page;
	unsigned long size;
	struct list_head list;
};

void *ion_mem_pool_alloc_page_array(struct ion_mem_pool *pool)
{
	unsigned int order = (unsigned int)pool->priv;
	struct page *page = alloc_pages(pool->gfp_mask, order);

	if (!page)
		return NULL;
	dma_map_page(NULL, page, 0, order_to_size(order), DMA_BIDIRECTIONAL);
	split_page(page, order);
	return page;
}

void ion_mem_pool_free_page_array(struct ion_mem_pool *pool, struct page *page)
{
	unsigned int order = (unsigned int)pool->priv;
	int i;

	for (i = 0; i < (1 << order); i++)
		__free_page(page + i);
}

static struct page_info *alloc_largest_available(struct ion_system_heap *heap,
						 unsigned long size)
{
	struct page *page;
	struct page_info *info;
	int i;

	for (i = 0; i < num_orders; i++) {
		if (size < order_to_size(orders[i]))
			continue;
		page = ion_mem_pool_alloc(heap->pools[i]);
		if (!page)
			continue;
		info = kmalloc(sizeof(struct page_info), GFP_KERNEL);
		info->page = page;
		info->size = order_to_size(orders[i]);
		return info;
	}
	return NULL;
}

static void ion_system_heap_free_pagelist(struct list_head *pages,
					  struct ion_system_heap *heap)
{
	struct page_info *info;
	int i = 0;

	while (!list_empty(pages)) {
		info = list_first_entry(pages, struct page_info, list);
		for (i = 0; i < num_orders; i++) {
			struct page *page = info->page;
			unsigned int size = order_to_size(orders[i]);
			if (info->size < size) {
				continue;
			} else if (info->size > size) {
				info->page += (size / PAGE_SIZE);
				info->size = info->size - size;
			} else {
				list_del(&info->list);
				kfree(info);
			}
			ion_mem_pool_free(heap->pools[i], page);
			break;
		}
	}
}

static int ion_system_heap_allocate(struct ion_heap *heap,
				     struct ion_buffer *buffer,
				     unsigned long size, unsigned long align,
				     unsigned long flags)
{
	struct ion_system_heap *sys_heap = container_of(heap,
							struct ion_system_heap,
							heap);
	struct sg_table *table;
	struct scatterlist *sg;
	int ret;
	struct list_head pages;
	struct page_info *info, *tmp_info;
	int i;
	long size_remaining = PAGE_ALIGN(size);

	INIT_LIST_HEAD(&pages);
	while (size_remaining > 0) {
		info = alloc_largest_available(sys_heap, size_remaining);
		if (!info)
			goto err;
		list_add_tail(&info->list, &pages);
		size_remaining -= info->size;
	}

	table = kmalloc(sizeof(struct sg_table), GFP_KERNEL);
	if (!table)
		goto err;

	ret = sg_alloc_table(table, PAGE_ALIGN(size) / PAGE_SIZE, GFP_KERNEL);
	if (ret)
		goto err1;

	sg = table->sgl;
	list_for_each_entry_safe(info, tmp_info, &pages, list) {
		struct page *page = info->page;
		for (i = 0; i < info->size / PAGE_SIZE; i++) {
			sg_set_page(sg, page + i, PAGE_SIZE, 0);
			sg = sg_next(sg);
		}
		list_del(&info->list);
		kfree(info);
	}

	dma_sync_sg_for_device(NULL, table->sgl, table->nents,
			       DMA_BIDIRECTIONAL);

	buffer->priv_virt = table;
	return 0;
err1:
	kfree(table);
err:
	ion_system_heap_free_pagelist(&pages, sys_heap);
	return -ENOMEM;
}

void ion_system_heap_free(struct ion_buffer *buffer)
{
	struct ion_heap *heap = buffer->heap;
	struct ion_system_heap *sys_heap = container_of(heap,
							struct ion_system_heap,
							heap);
	struct sg_table *table = buffer->priv_virt;
	struct scatterlist *sg = table->sgl;
	struct list_head pages;
	int i, j;
	INIT_LIST_HEAD(&pages);

	for_each_sg(table->sgl, sg, table->nents, i) {
		for (j = 0; j < sg_dma_len(sg) / PAGE_SIZE; j++) {
			struct page *page = sg_page(sg) + j;
			void *addr = vmap(&page, 1, VM_MAP,
					  pgprot_writecombine(PAGE_KERNEL));
			memset(addr, 0, PAGE_SIZE);
			vunmap(addr);
		}
	}

	sg = table->sgl;

	while (sg) {
		struct page_info *info;

		info = kmalloc(sizeof(struct page_info), GFP_KERNEL);
		info->page = sg_page(sg);
		info->size = sg_dma_len(sg);
		while(sg_next(sg) &&
		      sg_phys(sg) + sg_dma_len(sg) == sg_phys(sg_next(sg))) {
			sg = sg_next(sg);
			info->size += sg_dma_len(sg);
		}
		list_add(&info->list, &pages);
		sg = sg_next(sg);
	}
	ion_system_heap_free_pagelist(&pages, sys_heap);
	sg_free_table(table);
	kfree(table);
}

struct sg_table *ion_system_heap_map_dma(struct ion_heap *heap,
					 struct ion_buffer *buffer)
{
	return buffer->priv_virt;
}

void ion_system_heap_unmap_dma(struct ion_heap *heap,
			       struct ion_buffer *buffer)
{
	return;
}

void *ion_system_heap_map_kernel(struct ion_heap *heap,
				 struct ion_buffer *buffer)
{
	struct scatterlist *sg;
	int i, j;
	void *vaddr;
	pgprot_t pgprot;
	struct sg_table *table = buffer->priv_virt;
	int npages = PAGE_ALIGN(buffer->size) / PAGE_SIZE;
	struct page **pages = kzalloc(sizeof(struct page *) * npages,
				     GFP_KERNEL);
	struct page **tmp = pages;

	if (buffer->flags & ION_FLAG_CACHED)
		pgprot = PAGE_KERNEL;
	else
		pgprot = pgprot_writecombine(PAGE_KERNEL);

	for_each_sg(table->sgl, sg, table->nents, i) {
		int npages_this_entry = PAGE_ALIGN(sg_dma_len(sg)) / PAGE_SIZE;
		struct page *page = sg_page(sg);
		BUG_ON(i >= npages);
		for (j = 0; j < npages_this_entry; j++) {
			*(tmp++) = page++;
		}
	}
	vaddr = vmap(pages, npages, VM_MAP, pgprot);
	kfree(pages);

	return vaddr;
}

void ion_system_heap_unmap_kernel(struct ion_heap *heap,
				  struct ion_buffer *buffer)
{
	vunmap(buffer->vaddr);
}

int ion_system_heap_map_user(struct ion_heap *heap, struct ion_buffer *buffer,
			     struct vm_area_struct *vma)
{
	struct sg_table *table = buffer->priv_virt;
	unsigned long addr = vma->vm_start;
	unsigned long offset = vma->vm_pgoff;
	struct scatterlist *sg;
	int i;

	for_each_sg(table->sgl, sg, table->nents, i) {
		if (offset) {
			offset--;
			continue;
		}
		remap_pfn_range(vma, addr, page_to_pfn(sg_page(sg)),
				sg_dma_len(sg), vma->vm_page_prot);
		addr += sg_dma_len(sg);
	}
	return 0;
}

static struct ion_heap_ops system_heap_ops = {
	.allocate = ion_system_heap_allocate,
	.free = ion_system_heap_free,
	.map_dma = ion_system_heap_map_dma,
	.unmap_dma = ion_system_heap_unmap_dma,
	.map_kernel = ion_system_heap_map_kernel,
	.unmap_kernel = ion_system_heap_unmap_kernel,
	.map_user = ion_system_heap_map_user,
};

struct ion_heap *ion_system_heap_create(struct ion_platform_heap *unused)
{
	struct ion_system_heap *heap;
	int i;

	heap = kzalloc(sizeof(struct ion_system_heap), GFP_KERNEL);
	if (!heap)
		return ERR_PTR(-ENOMEM);
	heap->heap.ops = &system_heap_ops;
	heap->heap.type = ION_HEAP_TYPE_SYSTEM;
	heap->pools = kzalloc(sizeof(struct ion_mem_pool *) * num_orders,
			      GFP_KERNEL);
	if (!heap->pools)
		goto err_alloc_pools;
	for (i = 0; i < num_orders; i++) {
		struct ion_mem_pool *pool;
		pool = ion_mem_pool_create(ion_mem_pool_alloc_page_array,
					   ion_mem_pool_free_page_array,
					   GFP_HIGHUSER | __GFP_ZERO |
					   __GFP_NOWARN | __GFP_NORETRY,
					   (void *)orders[i]);
		if (!pool)
			goto err_create_pool;
		heap->pools[i] = pool;
	}
	return &heap->heap;
err_create_pool:
	for (i = 0; i < num_orders; i++)
		ion_mem_pool_destroy(heap->pools[i]);
	kfree(heap->pools);
err_alloc_pools:
	kfree(heap);
	return ERR_PTR(-ENOMEM);
}

void ion_system_heap_destroy(struct ion_heap *heap)
{
	struct ion_system_heap *sys_heap = container_of(heap,
							struct ion_system_heap,
							heap);
	int i;

	for (i = 0; i < num_orders; i++)
		ion_mem_pool_destroy(sys_heap->pools[i]);
	kfree(sys_heap->pools);
	kfree(sys_heap);
}

static int ion_system_contig_heap_allocate(struct ion_heap *heap,
					   struct ion_buffer *buffer,
					   unsigned long len,
					   unsigned long align,
					   unsigned long flags)
{
	buffer->priv_virt = kzalloc(len, GFP_KERNEL);
	if (!buffer->priv_virt)
		return -ENOMEM;
	return 0;
}

void ion_system_contig_heap_free(struct ion_buffer *buffer)
{
	kfree(buffer->priv_virt);
}

static int ion_system_contig_heap_phys(struct ion_heap *heap,
				       struct ion_buffer *buffer,
				       ion_phys_addr_t *addr, size_t *len)
{
	*addr = virt_to_phys(buffer->priv_virt);
	*len = buffer->size;
	return 0;
}

struct sg_table *ion_system_contig_heap_map_dma(struct ion_heap *heap,
						struct ion_buffer *buffer)
{
	struct sg_table *table;
	int ret;

	table = kzalloc(sizeof(struct sg_table), GFP_KERNEL);
	if (!table)
		return ERR_PTR(-ENOMEM);
	ret = sg_alloc_table(table, 1, GFP_KERNEL);
	if (ret) {
		kfree(table);
		return ERR_PTR(ret);
	}
	sg_set_page(table->sgl, virt_to_page(buffer->priv_virt), buffer->size,
		    0);
	return table;
}

void ion_system_contig_heap_unmap_dma(struct ion_heap *heap,
				      struct ion_buffer *buffer)
{
	sg_free_table(buffer->sg_table);
	kfree(buffer->sg_table);
}

int ion_system_contig_heap_map_user(struct ion_heap *heap,
				    struct ion_buffer *buffer,
				    struct vm_area_struct *vma)
{
	unsigned long pfn = __phys_to_pfn(virt_to_phys(buffer->priv_virt));
	return remap_pfn_range(vma, vma->vm_start, pfn + vma->vm_pgoff,
			       vma->vm_end - vma->vm_start,
			       vma->vm_page_prot);

}

static struct ion_heap_ops kmalloc_ops = {
	.allocate = ion_system_contig_heap_allocate,
	.free = ion_system_contig_heap_free,
	.phys = ion_system_contig_heap_phys,
	.map_dma = ion_system_contig_heap_map_dma,
	.unmap_dma = ion_system_contig_heap_unmap_dma,
	.map_kernel = ion_system_heap_map_kernel,
	.unmap_kernel = ion_system_heap_unmap_kernel,
	.map_user = ion_system_contig_heap_map_user,
};

struct ion_heap *ion_system_contig_heap_create(struct ion_platform_heap *unused)
{
	struct ion_heap *heap;

	heap = kzalloc(sizeof(struct ion_heap), GFP_KERNEL);
	if (!heap)
		return ERR_PTR(-ENOMEM);
	heap->ops = &kmalloc_ops;
	heap->type = ION_HEAP_TYPE_SYSTEM_CONTIG;
	return heap;
}

void ion_system_contig_heap_destroy(struct ion_heap *heap)
{
	kfree(heap);
}

