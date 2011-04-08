#include <linux/device.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/anon_inodes.h>
#include <linux/ion.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/rbtree.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/debugfs.h>

#include "ion_priv.h"

struct ion_mapper *user_mapper;
/**
 * struct ion_device - the metadata of the ion device node
 * @dev:		the actual misc device
 * @buffers:	an rb tree of all the existing buffers
 * @lock:		lock protecting the buffers & heaps trees
 * @heaps:		list of all the heaps in the system
 * @user_clients:	list of all the clients created from userspace
 */
struct ion_device {
	struct miscdevice dev;
	struct rb_root buffers;
	struct mutex lock;
	struct rb_root heaps;
	struct rb_root user_clients;
	struct rb_root kernel_clients;
	struct dentry *debug_root;
};

/**
 * struct ion_client - a process/hw block local address space
 * @dev:		backpointer to ion device
 * @handles:		an rb tree of all the handles in this client
 * @lock:		lock protecting the tree of handles
 * @name:		used for debugging
 * @task:		used for debugging
 * @mapper:		the mapper to use to get buffers into
 *			this clients view	
 *
 * A client represents a list of buffers this client may access as
 * well as a mapper to use to map/unmap these buffers into this clients
 * view.
 */
struct ion_client {
	struct kref ref;
	struct rb_node node;
	struct ion_device *dev;
	struct rb_root handles;
	struct ion_mapper *mapper;
	struct mutex lock;
	const char *name;
	struct task_struct *task;
	pid_t pid;
	struct dentry *debug_root;
};

/**
 * ion_handle - a client local reference to an buffer
 * @ref:		reference count
 * @client:		back pointer to the client the buffer resides in
 * @buffer:		poiter to the buffer
 * @node:		node in the client's handle rbtree
 * @map_cnt:		count of times this client has mapped this buffer
 * @mapping:		returned from pin, null until first pin
 */
struct ion_handle {
	struct kref ref;
	struct ion_client *client;
	struct ion_buffer *buffer;
	struct rb_node node;
	unsigned int map_cnt;
	void *mapping;
	void *addr;
};

void ion_buffer_add(struct ion_device *dev,
			struct ion_buffer *buffer)
{
	struct rb_node **p = &dev->buffers.rb_node;
	struct rb_node *parent = NULL;
	struct ion_buffer *entry;

	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct ion_buffer, node);

		if (buffer < entry)
			p = &(*p)->rb_left;
		else if (buffer > entry)
			p = &(*p)->rb_right;
		else
			WARN(1, "%s: buffer already found.", __func__);
	}

	rb_link_node(&buffer->node, parent, p);
	rb_insert_color(&buffer->node, &dev->buffers);
}

struct ion_buffer *ion_buffer_create(struct ion_heap *heap,
					     struct ion_device *dev,
					     unsigned long len,
					     unsigned long align,
					     unsigned long flags)
{
	struct ion_buffer *buffer;
	int ret;

	buffer = kzalloc(sizeof(struct ion_buffer), GFP_KERNEL);
	if (!buffer)
		return ERR_PTR(-ENOMEM);

	buffer->heap = heap;
	kref_init(&buffer->ref);

	ret = heap->ops->allocate(heap, buffer, len, align, flags);
	if (ret)
		return ERR_PTR(ret);
	ion_buffer_add(dev, buffer);
	buffer->dev = dev;
	buffer->size = len;
	return buffer;
}

static void ion_buffer_destroy(struct kref *kref)
{
	struct ion_buffer *buffer = container_of(kref, struct ion_buffer, ref);
	struct ion_device *dev = buffer->dev;

	buffer->heap->ops->free(buffer);
	mutex_lock(&dev->lock);
	rb_erase(&buffer->node, &dev->buffers);
	mutex_unlock(&dev->lock);
	kfree(buffer);
}

static void ion_buffer_get(struct ion_buffer *buffer)
{
	kref_get(&buffer->ref);
}

static int ion_buffer_put(struct ion_buffer *buffer)
{
	return kref_put(&buffer->ref, ion_buffer_destroy);
}

struct ion_handle *ion_handle_create(struct ion_client *client,
				     struct ion_buffer *buffer)
{
	struct ion_handle *handle;

	handle = kzalloc(sizeof(struct ion_handle), GFP_KERNEL);
	if (!handle)
		return ERR_PTR(-ENOMEM);
	kref_init(&handle->ref);
	handle->client = client;
	handle->buffer = buffer;
	handle->map_cnt = 0;
	handle->mapping = NULL;

	return handle;
}

static void ion_handle_destroy(struct kref *kref)
{
	struct ion_handle *handle = container_of(kref, struct ion_handle, ref);
	/* XXX Can a handle be destroyed while it's map count is non-zero?:
	   if (handle->map_cnt)
	   unmap 
	 */
	ion_buffer_put(handle->buffer);
	mutex_lock(&handle->client->lock);
	rb_erase(&handle->node, &handle->client->handles);
	mutex_unlock(&handle->client->lock);
	kfree(handle);
}

static void ion_handle_get(struct ion_handle *handle)
{
	kref_get(&handle->ref);
}

static int ion_handle_put(struct ion_handle *handle)
{
	return kref_put(&handle->ref, ion_handle_destroy);
}

static struct ion_handle *ion_handle_lookup(struct ion_client *client,
					    struct ion_buffer *buffer)
{
	struct rb_node *n;

	for (n = rb_first(&client->handles); n; n = rb_next(n)) {
		struct ion_handle *handle = rb_entry(n, struct ion_handle,
						     node);
		if (handle->buffer == buffer)
			return handle;
	}
	return NULL;
}

bool ion_handle_validate(struct ion_client *client, struct ion_handle *handle)
{
	struct rb_node *n = client->handles.rb_node;

	while (n) {
		struct ion_handle *handle_node = rb_entry(n, struct ion_handle,
							  node);
		if (handle < handle_node)
			n = n->rb_left;
		else if (handle > handle_node)
			n = n->rb_right;
		else
			return true;
	}
	return false;
}

static void ion_handle_add(struct ion_client *client, struct ion_handle *handle)
{
	struct rb_node **p = &client->handles.rb_node;
	struct rb_node *parent = NULL;
	struct ion_handle *entry;

	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct ion_handle, node);

		if (handle < entry)
			p = &(*p)->rb_left;
		else if (handle > entry)
			p = &(*p)->rb_right;
		else
			WARN(1, "%s: buffer already found.", __func__);
	}

	rb_link_node(&handle->node, parent, p);
	rb_insert_color(&handle->node, &client->handles);
}

struct ion_handle *ion_alloc(struct ion_client *client, size_t len,
			     size_t align, unsigned int flags)
{
	struct rb_node *n;
	struct ion_handle *handle;
	struct ion_device *dev = client->dev;
	struct ion_buffer *buffer = NULL;

	/* traverse the list of heaps available in this system in priority
	   order.  If the heap type is a mappable by the mapper, bufferate 
	   from it.  Repeat until buffer has succeeded or all heaps have been
	   tried */
	mutex_lock(&dev->lock);
        for (n = rb_first(&dev->heaps); n != NULL; n = rb_next(n)) {
		struct ion_heap *heap = rb_entry(n, struct ion_heap, node);
		if (!((1 << heap->type) & client->mapper->heap_mask))
			continue;
		buffer = ion_buffer_create(heap, dev, len, align, flags);
		if (!IS_ERR_OR_NULL(buffer))
			break;
        }
	mutex_unlock(&dev->lock);

	if (IS_ERR_OR_NULL(buffer))
		return ERR_PTR(PTR_ERR(buffer));

	handle = ion_handle_create(client, buffer);
	if (IS_ERR_OR_NULL(handle))
		return handle;

	mutex_lock(&client->lock);
	ion_handle_add(client, handle);
	mutex_unlock(&client->lock);

	return handle;
}

void ion_free(struct ion_client *client, struct ion_handle *handle)
{
	ion_handle_put(handle);
}

static void ion_client_get(struct ion_client *client);
static int ion_client_put(struct ion_client *client);

void *ion_map(struct ion_client *client, struct ion_handle *handle)
{
	struct ion_mapping *mapping;
	void *addr;

	mutex_lock(&client->lock);
	if (handle->map_cnt == 0) {
		addr = client->mapper->ops->map(client->mapper,
						handle->buffer,
						&mapping);
		if (IS_ERR_OR_NULL(addr))
			goto end;
		handle->mapping = mapping;
		handle->addr = addr;
	} else {
		addr = handle->addr;
	}
	handle->map_cnt++;
end:
	mutex_unlock(&client->lock);
	return addr;
}

void ion_unmap(struct ion_client *client, struct ion_handle *handle)
{
	mutex_lock(&client->lock);
	if (handle->map_cnt == 1)
		client->mapper->ops->unmap(client->mapper, handle->buffer,
					   handle->mapping);
	handle->map_cnt--;
	mutex_unlock(&client->lock);
}

struct ion_buffer *ion_share(struct ion_client *client,
				 struct ion_handle *handle)
{
	/* don't not take an extra refernce here, the burden is on the caller
	 * to make sure the buffer doesn't go away while it's passing it
	 * to another client -- ion_free should not be called on this handle
	 * until the buffer has been imported into the other client
	 */
	return handle->buffer;
}

struct ion_handle *ion_import(struct ion_client *client,
			      struct ion_buffer *buffer)
{
	struct ion_handle *handle = NULL;

	mutex_lock(&client->lock);
	/* if a handle exists for this buffer just take a reference to it */
	handle = ion_handle_lookup(client, buffer);
	if (!IS_ERR_OR_NULL(handle)) {
		ion_handle_get(handle);
		goto end;
	}
	/* otherwise take a reference to the buffer and stuff it into
	   a new handle */
	ion_buffer_get(buffer);
	handle = ion_handle_create(client, buffer);
	ion_handle_add(client, handle);
end:
	mutex_unlock(&client->lock);
	return handle;
}

static const struct file_operations ion_share_fops;

struct ion_handle *ion_import_fd(struct ion_client *client, int fd)
{
	struct file *file = fget(fd);
	struct ion_handle *handle;

	if (!file) {
		pr_err("%s: imported fd not found in file table.\n", __func__);
		return ERR_PTR(-EINVAL);
	}
	if (file->f_op != &ion_share_fops) {
		pr_err("%s: imported file is not a shared ion file.\n",
		       __func__);
		handle = ERR_PTR(-EINVAL);
		goto end;
	}
	handle = ion_import(client, file->private_data);
end:
	fput(file);
	return handle;
}

static int ion_debug_client_show(struct seq_file *s, void *unused)
{
	struct ion_client *client = s->private;
	struct rb_node *n;
	size_t sizes[ION_NUM_HEAPS] = {0};
	const char *names[ION_NUM_HEAPS] = {0};
	int i;

	mutex_lock(&client->lock);
	for (n = rb_first(&client->handles); n; n = rb_next(n)) {
		struct ion_handle *handle = rb_entry(n, struct ion_handle,
						     node);
		enum ion_heap_type type = handle->buffer->heap->type;

		if (!names[type])
			names[type] = handle->buffer->heap->name;
		sizes[type] += handle->buffer->size;
	}
	mutex_unlock(&client->lock);

	seq_printf(s, "%16.16s: %16.16s\n", "heap_name", "size_in_bytes");
	for (i = 0; i < ION_NUM_HEAPS; i++) {
		if (!names[i])
			continue;
		seq_printf(s, "%16.16s: %16u %d\n", names[i], sizes[i],
			   atomic_read(&client->ref.refcount));
	}
	return 0;
}

static int ion_debug_client_open(struct inode *inode, struct file *file)
{
	return single_open(file, ion_debug_client_show, inode->i_private);
}

static struct file_operations debug_client_fops = {
	.open = ion_debug_client_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

struct ion_client *ion_client_create(struct ion_device *dev,
				     const char *name,
				     struct ion_mapper *mapper)
{
	struct ion_client *client;
	struct task_struct *task;
	struct rb_node **p = &dev->user_clients.rb_node;
	struct rb_node *parent = NULL;
	struct ion_client *entry;
	char debug_name[64];

	client = kzalloc(sizeof(struct ion_client), GFP_KERNEL);
	if (!client)
		return ERR_PTR(-ENOMEM);
	client->dev = dev;
	client->handles = RB_ROOT;
	client->mapper = mapper;
	mutex_init(&client->lock);
	client->name = name;
	get_task_struct(current->group_leader);
	task_lock(current->group_leader);
	client->pid = task_pid_nr(current->group_leader);
	/* don't bother to store task struct for kernel threads,
	   they can't be killed anyway */
	if (current->group_leader->flags & PF_KTHREAD) {
		put_task_struct(current->group_leader);
		task = NULL;
	} else {
		task = current->group_leader;
	}
	task_unlock(current->group_leader);
	client->task = task;
	kref_init(&client->ref);

	mutex_lock(&dev->lock);
	if (task) {
		while (*p) {
			parent = *p;
			entry = rb_entry(parent, struct ion_client, node);

			if (task < entry->task)
				p = &(*p)->rb_left;
			else if (task > entry->task)
				p = &(*p)->rb_right;
		}
		rb_link_node(&client->node, parent, p);
		rb_insert_color(&client->node, &dev->user_clients);
	} else {
		while (*p) {
			parent = *p;
			entry = rb_entry(parent, struct ion_client, node);

			if (client < entry)
				p = &(*p)->rb_left;
			else if (client > entry)
				p = &(*p)->rb_right;
		}
		rb_link_node(&client->node, parent, p);
		rb_insert_color(&client->node, &dev->kernel_clients);
	}

	snprintf(debug_name, 64, "%u", client->pid);
	client->debug_root = debugfs_create_file(debug_name, 0664,
						 dev->debug_root, client,
						 &debug_client_fops);
	mutex_unlock(&dev->lock);

	return client;
}

void ion_client_destroy(struct ion_client *client)
{
	struct ion_device *dev = client->dev;
	struct rb_node *n;

	printk("%s: %d\n", __func__, __LINE__);
	while ((n = rb_first(&client->handles))) {
		struct ion_handle *handle = rb_entry(n, struct ion_handle,
						     node);
		ion_handle_destroy(&handle->ref);
	}
	mutex_lock(&dev->lock);
	if (client->task) {
		rb_erase(&client->node, &dev->user_clients);
		put_task_struct(client->task);
	} else {
		rb_erase(&client->node, &dev->kernel_clients);
	}
	debugfs_remove_recursive(client->debug_root);
	mutex_unlock(&dev->lock);

	kfree(client);
}

static struct ion_client *ion_client_lookup(struct ion_device *dev,
					    struct task_struct *task)
{
	struct rb_node *n = dev->user_clients.rb_node;
	struct ion_client *client;

	mutex_lock(&dev->lock);
	while (n) {
		client = rb_entry(n, struct ion_client, node);
		if (task == client->task) {
			ion_client_get(client);
			mutex_unlock(&dev->lock);
			return client;
		} else if (task < client->task) {
			n = n->rb_left;
		} else if (task > client->task) {
			n = n->rb_right;
		}
	}
	mutex_unlock(&dev->lock);
	return NULL;
}

static void _ion_client_destroy(struct kref *kref)
{
	struct ion_client *client = container_of(kref, struct ion_client, ref);
	ion_client_destroy(client);
}

static void ion_client_get(struct ion_client *client)
{
	kref_get(&client->ref);
}

static int ion_client_put(struct ion_client *client)
{
	return kref_put(&client->ref, _ion_client_destroy);
}

static int ion_share_release(struct inode *inode, struct file* file)
{
	struct ion_buffer *buffer = file->private_data;

	printk("%s: %d\n", __func__, __LINE__);
	/* drop the reference to the buffer -- this prevents the
	   buffer from going away because the client holding it exited
	   while it was being passed */
	ion_buffer_put(buffer);
	return 0;
}

static void ion_vma_open(struct vm_area_struct *vma)
{

	struct ion_buffer *buffer = vma->vm_file->private_data;
	struct ion_handle *handle = vma->vm_private_data;
	struct ion_client *client;

	printk("%s: %d\n", __func__, __LINE__);
	/* check that the client still exists and take a reference so
	   it can't go away until this vma is closed */
	client = ion_client_lookup(buffer->dev, current->group_leader);
	if (IS_ERR_OR_NULL(client)) {
		vma->vm_private_data = NULL;
		return;
	}
	ion_map(handle->client, handle);
	printk("%s: %d client_cnt %d handle_cnt %d handle_map_cnt %d "
	       "alloc_cnt %d\n", __func__, __LINE__, 
	       atomic_read(&client->ref.refcount),
	       atomic_read(&handle->ref.refcount), handle->map_cnt, 
	       atomic_read(&buffer->ref.refcount));
}

static void ion_vma_close(struct vm_area_struct *vma)
{
	struct ion_handle *handle = vma->vm_private_data;
	struct ion_buffer *buffer = vma->vm_file->private_data;
	struct ion_client *client;

	printk("%s: %d\n", __func__, __LINE__);
	/* this indicates the client is gone, nothing to do here */
	if (!handle)
		return;
	client = handle->client;
	printk("%s: %d client_cnt %d handle_cnt %d handle_map_cnt %d "
	       "alloc_cnt %d\n", __func__, __LINE__, 
	       atomic_read(&client->ref.refcount),
	       atomic_read(&handle->ref.refcount), handle->map_cnt, 
	       atomic_read(&buffer->ref.refcount));
	ion_unmap(client, handle);
	ion_handle_put(handle);
	ion_client_put(client);
	printk("%s: %d client_cnt %d handle_cnt %d handle_map_cnt %d "
	       "alloc_cnt %d\n", __func__, __LINE__, 
	       atomic_read(&client->ref.refcount),
	       atomic_read(&handle->ref.refcount), handle->map_cnt, 
	       atomic_read(&buffer->ref.refcount));
}

static struct vm_operations_struct ion_vm_ops = {
	.open = ion_vma_open,
	.close = ion_vma_close,
};

static int ion_share_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct ion_buffer *buffer = file->private_data;
	unsigned long size = vma->vm_end - vma->vm_start;
	struct ion_client *client;
	struct ion_handle *handle;
	void *addr;
	int ret;

	printk("%s: %d\n", __func__, __LINE__);
	/* make sure the client still exists, it's possible for the client to
	   have gone away but the map/share fd still to be around, take
	   a reference to it so it can't go away while this mapping exists */
	client = ion_client_lookup(buffer->dev, current->group_leader);
	if (IS_ERR_OR_NULL(client)) {
		pr_err("%s: trying to mmap an ion handle in a process with no "
		       "ion client\n", __func__);
		return -EINVAL;
	}

	if (!client->mapper->ops->map_user) {
		pr_err("%s: this mapper does not define a method for mapping "
		       "to userspace\n", __func__);
		ret = -EINVAL;
		goto err;
	}

	if ((size > buffer->size) || (size + (vma->vm_pgoff << PAGE_SHIFT) >
				     buffer->size)) {
		pr_err("%s: trying to map larger area than handle has available"
		       "\n", __func__);
		ret = -EINVAL;
		goto err;
	}

	/* find the handle and take a reference to it */
	handle = ion_import(client, buffer);
	/* map the handle into the client */
	addr = ion_map(client, handle);
	if (IS_ERR_OR_NULL(addr)) {
		ret = PTR_ERR(addr);
		goto err1;
	}
		
	/* now map it to userspace */
	ret = client->mapper->ops->map_user(client->mapper, buffer, vma,
					    handle->mapping);
	if (ret) {
		pr_err("%s: failure mapping buffer to userspace\n",
		       __func__);
		goto err2;
	}

	vma->vm_ops = &ion_vm_ops;
	/* move the handle into the vm_private_data so we can access it from
	   vma_open/close */
	vma->vm_private_data = handle;
	printk("%s: %d client_cnt %d handle_cnt %d handle_map_cnt %d "
	       "alloc_cnt %d\n", __func__, __LINE__, 
	       atomic_read(&client->ref.refcount),
	       atomic_read(&handle->ref.refcount), handle->map_cnt, 
	       atomic_read(&buffer->ref.refcount));
	return 0;

err2:
	ion_unmap(client, handle);
err1:
	/* drop the reference to the handle */
	ion_handle_put(handle);
err:
	/* drop the refernce to the client */
	ion_client_put(client);
	return ret;
}

static const struct file_operations ion_share_fops = {
	.owner		= THIS_MODULE,
	.release	= ion_share_release,
	.mmap		= ion_share_mmap,
};

static int ion_ioctl_share(struct file *parent, struct ion_client *client,
			   struct ion_handle *handle)
{
	int fd = get_unused_fd();
	struct file *file;

	if (fd < 0)
		return -ENFILE;

	file = anon_inode_getfile("ion_share_fd", &ion_share_fops,
				  handle->buffer, O_RDWR);
	if (IS_ERR_OR_NULL(file))
		goto err;
	ion_buffer_get(handle->buffer);
	fd_install(fd, file);

	return fd;

err:
	put_unused_fd(fd);
	return -ENFILE;
}

static long ion_ioctl(struct file *filp, unsigned int cmd, 
		      unsigned long arg)
{
	struct ion_client *client = filp->private_data;

	switch(cmd) {
	case ION_IOC_ALLOC:
	{
		struct ion_allocation_data data;
		
		if (copy_from_user(&data, (void __user *)arg, sizeof(data)))
			return -EFAULT;
		data.handle = ion_alloc(client, data.len, data.align,
					     data.flags);
		if (copy_to_user((void __user *)arg, &data, sizeof(data)))
			return -EFAULT;
		break;
	}
	case ION_IOC_FREE:
	{
		struct ion_handle_data data;

		if (copy_from_user(&data, (void __user *)arg,
				   sizeof(struct ion_handle_data)))
			return -EFAULT;
		if (!ion_handle_validate(client, data.handle))
			return -EINVAL;
		ion_free(client, data.handle);
		break;
	}
	case ION_IOC_MAP:
	case ION_IOC_SHARE:
	{
		struct ion_fd_data data;

		if (copy_from_user(&data, (void __user *)arg, sizeof(data)))
			return -EFAULT;
		if (!ion_handle_validate(client, data.handle))
			return -EINVAL;
		data.fd = ion_ioctl_share(filp, client, data.handle);
		if (copy_to_user((void __user *)arg, &data, sizeof(data)))
			return -EFAULT;
		break;
	}
	case ION_IOC_IMPORT:
	{
		struct ion_fd_data data;
		if (copy_from_user(&data, (void __user *)arg,
				   sizeof(struct ion_fd_data)))
			return -EFAULT;

		data.handle = ion_import_fd(client, data.fd);
		if (IS_ERR(data.handle))
			data.handle = NULL;
		if (copy_to_user((void __user *)arg, &data,
				 sizeof(struct ion_fd_data)))
			return -EFAULT;
		break;
	}
	default:
		return -ENOTTY;
	}
	return 0;
}

static int ion_release(struct inode *inode, struct file *file)
{
	struct ion_client *client = file->private_data;

	printk("%s: %d\n", __func__, __LINE__);
	ion_client_put(client);
	return 0;
}

static int ion_open(struct inode *inode, struct file *file)
{
	struct miscdevice *miscdev = file->private_data;
	struct ion_device *dev = container_of(miscdev, struct ion_device, dev);
	struct ion_client *client;

	printk("%s: %d\n", __func__, __LINE__);
	client = ion_client_lookup(dev, current->group_leader);
	if (IS_ERR_OR_NULL(client)) {
		/* XXX: consider replacing "user" with cmdline */
		client = ion_client_create(dev, "user", user_mapper);
		if (IS_ERR_OR_NULL(client))
			return PTR_ERR(client);
	}
	file->private_data = client;

	return 0;
}

static const struct file_operations ion_fops = {
	.owner          = THIS_MODULE,
	.open           = ion_open,
	.release        = ion_release,
	.unlocked_ioctl = ion_ioctl,
};

static size_t ion_debug_heap_total(struct ion_client *client,
				   enum ion_heap_type type)
{
	size_t size = 0;
	struct rb_node *n;

	mutex_lock(&client->lock);
	for (n = rb_first(&client->handles); n; n = rb_next(n)) {
		struct ion_handle *handle = rb_entry(n,
						     struct ion_handle,
						     node);
		if (handle->buffer->heap->type == type)
			size += handle->buffer->size;
	}
	mutex_unlock(&client->lock);
	return size;
}

static int ion_debug_heap_show(struct seq_file *s, void *unused)
{
	struct ion_heap *heap = s->private;
	struct ion_device *dev = heap->dev;
	struct rb_node *n;

	seq_printf(s, "%16.s %16.s %16.s\n", "client", "pid", "size");
	for (n = rb_first(&dev->user_clients); n; n = rb_next(n)) {
		struct ion_client *client = rb_entry(n, struct ion_client,
						     node);
		char task_comm[TASK_COMM_LEN];
		size_t size = ion_debug_heap_total(client, heap->type);
		if (!size)
			continue;

		get_task_comm(task_comm, client->task);
		seq_printf(s, "%16.s %16u %16u\n", task_comm, client->pid,
			   size);
	}

	for (n = rb_first(&dev->kernel_clients); n; n = rb_next(n)) {
		struct ion_client *client = rb_entry(n, struct ion_client,
						     node);
		size_t size = ion_debug_heap_total(client, heap->type);
		if (!size)
			continue;
		seq_printf(s, "%16.s %16u %16u\n", client->name, client->pid,
			   size);
	}
	return 0;
}

static int ion_debug_heap_open(struct inode *inode, struct file *file)
{
	return single_open(file, ion_debug_heap_show, inode->i_private);
}

static struct file_operations debug_heap_fops = {
	.open = ion_debug_heap_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

void ion_device_add_heap(struct ion_device *dev, struct ion_heap *heap)
{
	struct rb_node **p = &dev->heaps.rb_node;
	struct rb_node *parent = NULL;
	struct ion_heap *entry;

	heap->dev = dev;
	mutex_lock(&dev->lock);
	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct ion_heap, node);

		if (heap->prio < entry->prio) {
			p = &(*p)->rb_left;
		} else if (heap->prio > entry->prio) {
			p = &(*p)->rb_right;
		} else {
			pr_err("%s: can not insert multiple heaps with "
				"priority %d\n", __func__, heap->prio);
			goto end;
		}
	}

	rb_link_node(&heap->node, parent, p);
	rb_insert_color(&heap->node, &dev->heaps);
	debugfs_create_file(heap->name, 0664, dev->debug_root, heap,
			    &debug_heap_fops);
end:
	mutex_unlock(&dev->lock);
}

struct ion_device *ion_device_create(struct ion_mapper *mapper)
{
	struct ion_device *idev;
	int ret;

        if (!mapper) {
                pr_err("ion: Unable to initialize ion!\n");
                return ERR_PTR(-EINVAL);
        }

	idev = kzalloc(sizeof(struct ion_device), GFP_KERNEL);
	if (!idev)
		return ERR_PTR(-ENOMEM);

	idev->dev.minor = MISC_DYNAMIC_MINOR;
        idev->dev.name = "ion";
        idev->dev.fops = &ion_fops;
        idev->dev.parent = NULL;
	ret = misc_register(&idev->dev);
	if (ret) {
		pr_err("ion: failed to register misc device.\n");
		return ERR_PTR(ret);
	}

	idev->debug_root = debugfs_create_dir("ion", NULL);
	if (IS_ERR_OR_NULL(idev->debug_root))
		pr_err("ion: failed to create debug files.\n");

	idev->buffers = RB_ROOT;
	mutex_init(&idev->lock);
	idev->heaps = RB_ROOT;
	idev->user_clients = RB_ROOT;
	idev->kernel_clients = RB_ROOT;
	user_mapper = mapper;
	return idev;
}

void ion_device_destroy(struct ion_device *dev)
{
        misc_deregister(&dev->dev);
	/* XXX need to free the heaps and clients ? */
	kfree(dev);
}
