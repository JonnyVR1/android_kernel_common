/*
 * drivers/gpu/ion/ion_mem_pool.c
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
#define DEBUG

#include <linux/dma-mapping.h>
#include <linux/err.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/shrinker.h>
#include "ion_priv.h"

struct ion_mem_pool_item {
	struct page *page;
	struct list_head list;
};

void *ion_mem_pool_alloc_pages(struct ion_mem_pool *pool)
{
	unsigned int order = (unsigned int)pool->priv;
	struct page *page = alloc_pages(pool->gfp_mask, order);

	if (!page)
		return NULL;
	dma_map_page(NULL, page, 0, (1 << order) * PAGE_SIZE,
		     DMA_BIDIRECTIONAL);
	return page;
}

void ion_mem_pool_free_pages(struct ion_mem_pool *pool, struct page *page)
{
	unsigned int order = (unsigned int)pool->priv;
	__free_pages(page, order);
}

static int ion_mem_pool_add(struct ion_mem_pool *pool, struct page *page)
{
	struct ion_mem_pool_item *item;

	item = kmalloc(sizeof(struct ion_mem_pool_item), GFP_KERNEL);
	if (!item)
		return -ENOMEM;
	item->page = page;
	list_add(&item->list, &pool->items);
	pool->count++;
	return 0;
}

static struct page *ion_mem_pool_remove(struct ion_mem_pool *pool)
{
	struct ion_mem_pool_item *item;
	struct page *page;

	BUG_ON(!pool->count);
	BUG_ON(list_empty(&pool->items));

	item = list_first_entry(&pool->items, struct ion_mem_pool_item, list);
	list_del(&item->list);
	page = item->page;
	kfree(item);
	pool->count--;
	return page;
}

void *ion_mem_pool_alloc(struct ion_mem_pool *pool)
{
	struct page *page = NULL;

	BUG_ON(!pool);

	mutex_lock(&pool->mutex);
	if (pool->count)
		page = ion_mem_pool_remove(pool);
	else
		page = pool->alloc(pool);
	mutex_unlock(&pool->mutex);

	return page;
}

void ion_mem_pool_free(struct ion_mem_pool *pool, struct page* page)
{
	int ret;

	mutex_lock(&pool->mutex);
	ret = ion_mem_pool_add(pool, page);
	mutex_unlock(&pool->mutex);
}

static int ion_mem_pool_shrink(struct shrinker *shrinker,
				 struct shrink_control *sc)
{
	struct ion_mem_pool *pool = container_of(shrinker,
						 struct ion_mem_pool,
						 shrinker);
	struct page *page;
	int i;

	if (sc->nr_to_scan == 0)
		return pool->count;

	mutex_lock(&pool->mutex);
	for (i = 0; i < sc->nr_to_scan && pool->count; i++) {
		page = ion_mem_pool_remove(pool);
		pool->free(pool, page);
	}
	mutex_unlock(&pool->mutex);

	return pool->count;
}

struct ion_mem_pool *ion_mem_pool_create(
	void *(*alloc)(struct ion_mem_pool *pool),
	void (*free)(struct ion_mem_pool *pool, struct page *page),
	gfp_t gfp_mask, void *priv)
{
	struct ion_mem_pool *pool = kmalloc(sizeof(struct ion_mem_pool),
					     GFP_KERNEL);
	if (!pool)
		return NULL;
	pool->count = 0;
	INIT_LIST_HEAD(&pool->items);
	pool->shrinker.shrink = ion_mem_pool_shrink;
	pool->shrinker.seeks = DEFAULT_SEEKS * 16;
	pool->shrinker.batch = 0;
	register_shrinker(&pool->shrinker);
	pool->alloc = alloc;
	pool->free = free;
	pool->gfp_mask = gfp_mask;
	pool->priv = priv;
	mutex_init(&pool->mutex);

	return pool;
}

void ion_mem_pool_destroy(struct ion_mem_pool *pool)
{
	kfree(pool);
}

