#ifndef _LINUX_ION_H
#define _LINUX_ION_H

#include <linux/types.h>

struct ion_handle;
#ifdef __KERNEL__
struct ion_device;
struct ion_heap;
struct ion_mapper;
struct ion_client;
struct ion_buffer;

/**
 * enum ion_heap_types - list of all possible types of heaps
 * @ION_HEAP_VMALLOC:		memory allocated via vmalloc
 * @ION_HEAP_KMALLOC:		memory allocated via kmalloc
 * @ION_HEAP_END:		helper for iterating over heaps
 */
enum ion_heap_type {
	ION_HEAP_VMALLOC,
	ION_HEAP_KMALLOC,
	ION_HEAP_END,
};

#define ION_NUM_HEAPS ION_HEAP_END

enum ion_mapper_type {
	ION_SYSTEM_MAPPER,
	ION_MAPPER_END,
};

#define ION_NUM_MAPPERS ION_MAPPER_END

/**
 * struct ion_platform_heap - defines a heap in the given platform
 * @type:	type of the heap from ion_heap_type enum
 * @prio:	priority of the heap when allocating (lower numbers will be
 * 		allocated from first), MUST be unique
 * @name:	used for debug purposes
 * @base:	base address of heap in physical memory if applicable
 * @size:	size of the heap in bytes if applicable
 *
 * Provided by the board file.
 */
struct ion_platform_heap {
	enum ion_heap_type type;
	unsigned int prio;
	const char *name;
	unsigned long base;
	size_t size;
};

/**
 * struct ion_platform_data - array of platform heaps passed from board file 
 * @heaps:	array of platform_heap structions
 * @nr:		number of structures in the array
 * 
 * Provided by the board file in the form of platform data to a platform device.
 */
struct ion_platform_data {
	int nr;
	struct ion_platform_heap heaps[];
};

/**
 * ion_client_create() -  allocate a client and returns it
 * @dev:	the global ion device
 * @name:	used for debugging
 * @mapper:	a mapper that will be used to map allocation into this clients
 * 		address space, ie iovmm, gart, system etc.
 */
struct ion_client *ion_client_create(struct ion_device *dev, const char* name, 
				     struct ion_mapper *mapper);

/**
 * ion_client_destroy() -  free's a client and all it's handles
 * @client:	the client
 *
 * Free the provided client and all it's resources including
 * any handles it is holding.
 */
void ion_client_destroy(struct ion_client *client);

/**
 * ion_alloc - allocate ion memory
 * @client:	the client
 * @len:	size of the allocation
 * @align:	requested allocation alignment, lots of hardware blocks have
 * 		alignment requirements of some kind
 * @flags:	flags to pass along to heaps
 *
 * Allocate memory in one of the heaps provided in heap mask and return
 * an opaque handle to it.
 */
struct ion_handle *ion_alloc(struct ion_client *client, size_t len,
			     size_t align, unsigned int flags);

/**
 * ion_free - free a handle
 * @client:	the client
 * @handle:	the handle to free
 *
 * Free the provided handle.
 */
void ion_free(struct ion_client *client, struct ion_handle *handle);

/**
 * ion_map() - create mapping for the given handle 
 * @client:	the client
 * @handle:	handle to map
 *
 * Map the given handle into the given client's address space.  
 * First, the handle will be verified to confirm it is actually visible
 * to the provided client.  Then client->mapper->map will be called on the
 * given allocation.  Returns the new physical address of the allocation.
 */
void *ion_map(struct ion_client *client, struct ion_handle *handle);

/**
 * ion_unmap() - destroy the mapping for the handle
 * @client:	the client
 * @handle:	handle to unmap
 *
 * Unmap the given handle from the client's address space.
 */
void ion_unmap(struct ion_client *client, struct ion_handle *handle);


/**
 * ion_share() - given a handle, obtain a buffer to pass to other clients
 * @client:	the client
 * @handle:	the handle to share
 *
 * Given a handle, return a buffer which exists in a global name
 * space and can be passed to other clients.  Should be passed into ion_import
 * to obtain a new handle for this buffer.
 */
struct ion_buffer *ion_share(struct ion_client *client,
			     struct ion_handle *handle);

/**
 * ion_import() - given an buffer in another client, import it
 * @client:	this blocks client
 * @buffer:	the buffer to import (as obtained from ion_share)
 *
 * Given a buffer, add it to the client and return the handle to use to refer 
 * to it further.  This is called to share a handle from one kernel client to
 * another.
 */
struct ion_handle *ion_import(struct ion_client *client,
			      struct ion_buffer *buffer);

/**
 * ion_import_fd() - given an fd obtained via ION_IOC_SHARE ioctl, import it
 * @client:	this blocks client
 * @fd:		the fd
 *
 * A helper function for drivers that will be recieving ion buffers shared
 * with them from userspace.  These buffers are represented by a file
 * descriptor obtained as the return from the ION_IOC_SHARE ioctl.
 * This function coverts that fd into the underlying buffer, and returns
 * the handle to use to refer to it further.
 */
struct ion_handle *ion_import_fd(struct ion_client *client, int fd);
#endif /* __KERNEL__ */

/**
 * DOC: Ion Userspace API
 *
 * create a client by opening /dev/ion
 * most operations handled via following ioctls
 *
 */

/**
 * struct ion_allocation_data - metadata pased from userspace for allocations
 * @len:	size of the allocation
 * @align:	required alignment of the allocation
 * @flags:	flags passed to heap
 * @handle:	pointer that will be populated with a cookie to use to refer
 * 		to this allocation
 *
 * Provided by userspace as an argument to the ioctl
 */
struct ion_allocation_data {
	size_t len;
	size_t align;
	unsigned int flags;
	struct ion_handle *handle;
};

/**
 * struct ion_fd_data - metadata passed to/from userspace for a handle/fd pair
 * @handle:	a handle
 * @fd:		a file descriptor representing that handle
 *
 * For ION_IOC_SHARE or ION_IOC_MAP userspace populates the handle field with
 * the handle returned from ion alloc, and the kernel returns the file
 * descriptor to share or map in the fd field.  For ION_IOC_IMPORT, userspace
 * provides the file descriptor and the kernel returns the handle.
 */
struct ion_fd_data {
	struct ion_handle *handle;
	int fd;
};

/**
 * struct ion_handle_data - a handle passed to/from the kernel
 * @handle:	a handle
 */
struct ion_handle_data {
	struct ion_handle *handle;
};

#define ION_IOC_MAGIC		'I'

/**
 * DOC: ION_IOC_ALLOC - allocate memory
 *
 * Takes an ion_allocation_data struct and returns it with the handle field
 * populated with the opaque handle for the allocation. 
 */
#define ION_IOC_ALLOC		_IOWR(ION_IOC_MAGIC, 0, \
				      struct ion_allocation_data)

/**
 * DOC: ION_IOC_FREE - free memory
 *
 * Takes an ion_handle_data struct and frees the handle.
 */
#define ION_IOC_FREE		_IOWR(ION_IOC_MAGIC, 1, struct ion_handle_data)

/**
 * DOC: ION_IOC_MAP - get a file descriptor to mmap
 *
 * Takes an ion_fd_data struct with the handle field populated with a valid
 * opaque handle.  Returns the struct with the fd field set to a file
 * descriptor open in the current address space.  This file descriptor
 * can then be used as an argument to mmap.
 */
#define ION_IOC_MAP		_IOWR(ION_IOC_MAGIC, 2, struct ion_fd_data)

/**
 * DOC: ION_IOC_SHARE - creates a file descriptor to use to share an allocation
 *
 * Takes an ion_fd_data struct with the handle field populated with a valid
 * opaque handle.  Returns the struct with the fd field set to a file
 * descriptor open in the current address space.  This file descriptor
 * can then be passed to another process.  The corresponding opaque handle can
 * be retrieved via ION_IOC_IMPORT.
 */
#define ION_IOC_SHARE		_IOWR(ION_IOC_MAGIC, 4, struct ion_fd_data)

/**
 * DOC: ION_IOC_IMPORT - imports a shared file descriptor
 *
 * Takes an ion_fd_data struct with the fd field populated with a valid file
 * descriptor obtained from ION_IOC_SHARE and returns the struct with the handle * filed set to the corresponding opaque handle.
 */
#define ION_IOC_IMPORT		_IOWR(ION_IOC_MAGIC, 5, int)

#endif /* _LINUX_ION_H */
