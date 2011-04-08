#include <linux/err.h>
#include <linux/ion.h>
#include "ion_priv.h"

struct ion_heap *ion_kmalloc_heap_create(struct ion_platform_heap *);
void ion_kmalloc_heap_destroy(struct ion_heap *);

struct ion_heap *ion_vmalloc_heap_create(struct ion_platform_heap *);
void ion_vmalloc_heap_destroy(struct ion_heap *);

struct ion_heap *ion_heap_create(struct ion_platform_heap *heap_data)
{
	struct ion_heap *heap = NULL;

	switch (heap_data->type) {
	case ION_HEAP_KMALLOC:
		heap = ion_vmalloc_heap_create(heap_data);
		break;
	case ION_HEAP_VMALLOC:
		heap = ion_vmalloc_heap_create(heap_data);
		break;
	default:
		pr_err("%s: Invalid heap type %d\n", __func__,
		       heap_data->type);
		return ERR_PTR(-EINVAL);
	}
	if (IS_ERR_OR_NULL(heap))
		pr_err("%s: error creating heap %s type %d base %lu size %u\n",
		       __func__, heap_data->name, heap_data->type,
		       heap_data->base, heap_data->size);

	heap->name = heap_data->name;
	return heap;
}

void ion_heap_destroy(struct ion_heap *heap)
{
	if (!heap)
		return;

	switch (heap->type) {
	case ION_HEAP_KMALLOC:
		ion_kmalloc_heap_destroy(heap);
		break;
	case ION_HEAP_VMALLOC:
		ion_vmalloc_heap_destroy(heap);
		break;
	default:
		pr_err("%s: Invalid heap type %d\n", __func__,
		       heap->type);
	}
}
