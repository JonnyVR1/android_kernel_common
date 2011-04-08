#ifndef _ION_PRIV_H
#define _ION_PRIV_H

#include <linux/kref.h>
#include <linux/mm_types.h>
#include <linux/mutex.h>
#include <linux/rbtree.h>
#include <linux/ion.h>

struct ion_mapping;

/**
 * struct ion_buffer - metadata for a particular buffer
 * @ref:		refernce count
 * @node:		node in the ion_device buffers tree
 * @dev:		back pointer to the ion_device
 * @heap:		back pointer to the heap the buffer came from
 * @flags:		buffer specific flags
 * @size:		size of the buffer
*/
struct ion_buffer {
	struct kref ref;
	struct rb_node node;
	struct ion_device *dev;
	struct ion_heap *heap;
	unsigned long flags;
	size_t size;
	void *priv;
};

/**
 * struct ion_heap_ops - ops to operate on a given heap
 * @allocate:
 * @free:
 */
struct ion_heap_ops {
	/* allocate memory in the given heap or PTR_ERR on failure */
	int (*allocate) (struct ion_heap *heap,
			 struct ion_buffer *buffer, unsigned long len,
			 unsigned long align, unsigned long flags);
	/* free memory in the given heap */
	void (*free) (struct ion_buffer *buffer);
};

/**
 * struct ion_heap - represents a heap in the system
 * @node:		rb node to put the heap on the device's tree of heaps
 * @dev:		back pointer to the ion_device
 * @type:		type of heap
 * @ops:		ops struct as above
 * @prio:		priority (lower numbers first) of this heap when
 *			allocating.  These are specified by platform data and
 *			MUST be unique
 * @priv:		private data used by the heap implementation
 *
 * Represents a pool of memory from which buffers can be made.  In some
 * systems the only heap is regular system memory allocated via vmalloc.
 * On others, some blocks might require large physically contiguous buffers
 * that are allocated from a specially reserved heap.
 */
struct ion_heap {
	struct rb_node node;
	struct ion_device *dev;
	enum ion_heap_type type;
	struct ion_heap_ops *ops;
	int prio;
	const char *name;
	void *priv;
};

/**
 * ion_mapper_ops - functions to operate on a given mapper
 * @map:		map the buffer into the clients address space
 * @map_user		map the buffer into a vma for userspace
 *			if it is not desirable (or possible) for some clients
 *			to have memory mapped to userspace, this function
 *			can be left unimplemented
 * @unmap		unmap the buffer from the clients address space
 */
struct ion_mapper_ops {
	/* pin a handle, returns physical address or PTR_ERR on failure*/
	void * (*map) (struct ion_mapper *mapper, struct ion_buffer *buffer,
		       struct ion_mapping **mapping);
	int (*map_user) (struct ion_mapper *mapper, struct ion_buffer *buffer,
			 struct vm_area_struct *vma,
			 struct ion_mapping *mapping);
	void (*unmap) (struct ion_mapper *mapper, struct ion_buffer *buffer,
		       struct ion_mapping *mapping);
};

/**
 * ion_mapper - represents a piece of hardware used to create an address space
 * @type		type of mapper
 * @heap_mask:		mask of heaps this mapper is able to access
 * @ops:		mapper operations for this mapper
 * @priv		private data used by the mapper implementation
 *
 * This structure represents a physical piece of hardware that creates
 * mappings such as an iommu, a gart, the cpu mmu, etc.  A given platform
 * must create a mapper for each of these hardware blocks that it will use.
 * These will then be used to create a mapping for an buffer in a given heap
 * into the address space visible by the client.
 * For example: a system might have a camera block that sits behind an iommu
 * that can remap system memory.  In this case the camera would have an
 * ion_client, with an ion_mapper representing that iommu. When ops->map
 * is called, buffers from the system memory heap are mapped into the
 * camera's view via the iommu mapper.
 */
struct ion_mapper {
	enum ion_mapper_type type;
	unsigned int heap_mask;
	struct ion_mapper_ops *ops;
	void *priv;
};

/**
 * ion_device_create - allocates and returns an ion device
 * @mapper:		the mapper to use to map buffers into
 *			userspace -- may vary by platform
 *
 * returns a valid device or -PTR_ERR
 */
struct ion_device *ion_device_create(struct ion_mapper *mapper);

/**
 * ion_device_destroy - free and device and it's resource
 * @dev:		the device
 */
void ion_device_destroy(struct ion_device *dev);

/**
 * XXX
 */
void ion_device_add_heap(struct ion_device *dev, struct ion_heap *heap);

/* CREATE MAPPERS */
struct ion_mapper *ion_mapper_create(enum ion_mapper_type type);
void ion_mapper_destroy(struct ion_mapper *);
/* CREATE HEAPS */
struct ion_heap *ion_heap_create(struct ion_platform_heap *);
void ion_heap_destroy(struct ion_heap *);

#endif /* _ION_PRIV_H */
