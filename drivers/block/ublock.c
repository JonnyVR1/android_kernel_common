/*
 * drivers/block/ublock.c
 *
 * Copyright (C) 2010 Google, Inc.
 *
 * Author:
 *     Thoams Tuttle <ttuttle@google.com>
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

#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/bug.h>
#include <linux/cdev.h>
#include <linux/completion.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/genhd.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/ublock.h>
#include <linux/workqueue.h>

#define BLOCK_MINORS 16

static struct list_head ub_devices;
static struct mutex ub_devices_lock;

static int ub_block_major;

#define MAX_BUF 65536

#define MAX_FAILURES 10

#define KERNEL_SECTOR_SIZE 512

#define ub_file_dev(file) ((file)->private_data)
#define ub_disk_dev(disk) ((disk)->private_data)
#define ub_bdev_dev(bdev) ub_disk_dev((bdev)->bd_disk)
#define ub_req_dev(req)   ub_disk_dev((req)->rq_disk)

#define DEV_INITED 0x1
#define DEV_DESTROYED 0x2

#define ub_dev_to_dev(ub_dev) (disk_to_dev((ub_dev)->disk))

#define ub_dev_err(ub_dev, ...) \
	dev_err(ub_dev_to_dev((ub_dev)), __VA_ARGS__)
#define ub_dev_warn(ub_dev, ...) \
	dev_warn(ub_dev_to_dev((ub_dev)), __VA_ARGS__)
#define ub_dev_notice(ub_dev, ...) \
	dev_notice(ub_dev_to_dev((ub_dev)), __VA_ARGS__)
#define ub_dev_info(ub_dev, ...) \
	dev_notice(ub_dev_to_dev((ub_dev)), __VA_ARGS__)
#define ub_dev_dbg(ub_dev, ...) \
	dev_dbg(ub_dev_to_dev((ub_dev)), __VA_ARGS__)

struct ub_device {
	struct list_head list;

	int index;
	struct kref refcount;

	int flags;
	spinlock_t flags_lock;
	int fails;

	/* control file */
	struct file *file;

	/* block device */
	struct gendisk *disk;
	struct request_queue *queue;
	spinlock_t queue_lock;

	struct list_head in_queue;
	u64 next_seq;
	int nr_in;
	spinlock_t in_lock; /* protects in_queue, next_seq, nr_in */

	struct completion in_added;

	struct list_head out_list;
	int nr_out;
	struct mutex out_lock; /* protects out_list, nr_out */

	struct work_struct init_work;
	struct work_struct destroy_work;

	u32 max_buf;
};

struct ub_request;

struct ub_request_type {
	u32 in_opcode;
	u32 out_opcode;
	ssize_t (*read_in_fn)(struct ub_device *dev,
			      struct ub_request *req,
			      char *buf,
			      size_t count);
	ssize_t (*write_out_fn)(struct ub_device *dev,
				struct ub_request *req,
				const char __user *buf,
				size_t count);
	void (*terminate_fn)(struct ub_device *dev, struct ub_request *req);
};

struct ub_request {
	struct list_head list;

	const struct ub_request_type *type;

	u32 seq;
	u32 in_opcode;
	u32 out_opcode;

	void *private_data;
};

static struct workqueue_struct *ub_wq;

static struct ub_request *ub_request_alloc(const struct ub_request_type *type)
{
	struct ub_request *req;

	req = kzalloc(sizeof(struct ub_request), GFP_ATOMIC);
	if (req)
		req->type = type;
	return req;
}

static void ub_request_free(struct ub_request *req)
{
	kfree(req);
}

static int ub_enqueue(struct ub_device *dev, struct ub_request *req,
		       int assign_seq)
{
	spin_lock(&dev->flags_lock);

	if (dev->flags & DEV_DESTROYED) {
		spin_unlock(&dev->flags_lock);
		ub_dev_warn(dev, "enqueue: device destroyed\n");
		return -EIO;
	}

	spin_lock(&dev->in_lock);
	spin_unlock(&dev->flags_lock);

	if (assign_seq)
		req->seq = dev->next_seq++;
	list_add_tail(&req->list, &dev->in_queue);
	dev->nr_in++;

	spin_unlock(&dev->in_lock);

	complete(&dev->in_added);

	return 0;
}

static struct ub_request *ub_dequeue(struct ub_device *dev)
{
	struct list_head *pos;
	struct ub_request *req;

	if (wait_for_completion_killable(&dev->in_added) == -ERESTARTSYS) {
		ub_dev_warn(dev, "dequeue interrupted\n");
		return NULL;
	}

	spin_lock(&dev->flags_lock);

	if (dev->flags & DEV_DESTROYED) {
		spin_unlock(&dev->flags_lock);
		ub_dev_warn(dev, "dequeue: device destroyed\n");
		return NULL;
	}

	spin_lock(&dev->in_lock);
	spin_unlock(&dev->flags_lock);

	if (list_empty(&dev->in_queue)) {
		spin_unlock(&dev->in_lock);
		ub_dev_err(dev, "ublock: dequeue: "
			   "completed, but nothing in queue\n");
		return NULL;
	}
	pos = dev->in_queue.next;
	list_del(pos);
	dev->nr_in--;

	spin_unlock(&dev->in_lock);

	req = list_entry(pos, struct ub_request, list);

	return req;
}

/* Must be called with dev->out_lock held. */
static void __ub_put_out(struct ub_device *dev, struct ub_request *req)
{
	list_add(&req->list, &dev->out_list);
	dev->nr_out++;
}

static void ub_put_out(struct ub_device *dev, struct ub_request *req)
{
	mutex_lock(&dev->out_lock);
	__ub_put_out(dev, req);
	mutex_unlock(&dev->out_lock);
}

/* Must be called with dev->out_lock held. */
static struct ub_request *__ub_find_out(struct ub_device *dev, u32 seq)
{
	struct list_head *pos;
	struct ub_request *req;

	list_for_each(pos, &dev->out_list) {
		req = list_entry(pos, struct ub_request, list);
		if (req->seq == seq)
			goto found;
	}
	req = NULL;
found:
	return req;
}

/* Must be called with dev->out_lock held. */
static void __ub_remove_out(struct ub_device *dev, struct ub_request *req)
{
	list_del(&req->list);
	dev->nr_out--;
}

static struct ub_request *ub_get_out(struct ub_device *dev, u32 seq)
{
	struct ub_request *req;

	mutex_lock(&dev->out_lock);
	req = __ub_find_out(dev, seq);
	if (req)
		__ub_remove_out(dev, req);
	mutex_unlock(&dev->out_lock);

	return req;
}

static void ub_free_callback(struct kref *refcount)
{
	struct ub_device *dev =
		container_of(refcount, struct ub_device, refcount);

	kfree(dev);
}

static void ub_get(struct ub_device *dev)
{
	kref_get(&dev->refcount);
}

static void ub_put(struct ub_device *dev)
{
	kref_put(&dev->refcount, &ub_free_callback);
}

static ssize_t ub_init_read_in(struct ub_device *dev, struct ub_request *req,
			       char __user *buf, size_t count)
{
	struct ublock_init_in in;

	if (count < sizeof(in)) {
		ub_dev_warn(dev, "INIT read in: buffer too small "
			    "(expected at least %zu, got %zu\n",
			    sizeof(in), count);
		return -EINVAL;
	}

	in.version = UBLOCK_VERSION;
	in.max_buf = MAX_BUF;
	in.index = dev->index;

	if (copy_to_user(buf, &in, sizeof(in))) {
		ub_dev_warn(dev, "INIT read in: fault copying\n");
		return -EFAULT;
	}

	return sizeof(in);
}

static void ub_init_callback(struct work_struct *work);

static ssize_t ub_init_write_out(struct ub_device *dev, struct ub_request *req,
				 const char __user *buf, size_t count)
{
	struct ublock_init_out out;
	sector_t num_sectors;
	unsigned int max_sectors;

	if (count != sizeof(out)) {
		ub_dev_warn(dev, "INIT write out: size mismatch "
			    "(expected %zu, got %zu)",
			    sizeof(out), count);
		return -EFAULT;
	}
	if (copy_from_user(&out, buf, sizeof(out))) {
		ub_dev_warn(dev, "INIT write out: fault copying\n");
		return -EFAULT;
	}
	if (out.version != UBLOCK_VERSION) {
		ub_dev_warn(dev, "INIT write out: version mismatch\n");
		return -EINVAL;
	}
	if (out.max_buf > MAX_BUF) {
		ub_dev_warn(dev, "INIT write out: max_buf too large\n");
		return -EINVAL;
	}

	dev->max_buf = out.max_buf;
	dev->flags |= DEV_INITED;

	num_sectors = out.size / KERNEL_SECTOR_SIZE;
	ub_dev_info(dev, "setting capacity to %llu sectors\n",
		    (long long unsigned) num_sectors);
	set_capacity(dev->disk, num_sectors);

	max_sectors = out.max_buf / KERNEL_SECTOR_SIZE - 1;
	ub_dev_info(dev, "setting max_sectors to %u sectors\n", max_sectors);
	blk_queue_max_hw_sectors(dev->queue, max_sectors);

	INIT_WORK(&dev->init_work, &ub_init_callback);
	queue_work(ub_wq, &dev->init_work);

	ub_dev_info(dev, "initialized (size=%llu, max_buf=%u)\n",
		    out.size, out.max_buf);

	return sizeof(out);
}

static ssize_t ub_ready_read_in(struct ub_device *dev, struct ub_request *req,
				char __user *buf, size_t count)
{
	struct ublock_ready_in in;

	if (count < sizeof(in)) {
		ub_dev_warn(dev, "READY read in: buffer too small "
			    "(expected at least %zu, got %zu)\n",
			    sizeof(in), count);
		return -EINVAL;
	}

	memset(&in, 0, sizeof(in));

	if (copy_to_user(buf, &in, sizeof(in))) {
		ub_dev_warn(dev, "READY read in: fault copying\n");
		return -EFAULT;
	}

	return sizeof(in);
}

static ssize_t ub_ready_write_out(struct ub_device *dev, struct ub_request *req,
				  const char __user *buf, size_t count)
{
	struct ublock_ready_out out;

	if (count != sizeof(out)) {
		ub_dev_warn(dev, "READY write out: size mismatch "
			    "(expected %zu, got %zu)\n",
			    sizeof(out), count);
		return -EINVAL;
	}

	if (copy_from_user(&out, buf, sizeof(out))) {
		ub_dev_warn(dev, "READY write out: fault copying\n");
		return -EFAULT;
	}

	return sizeof(out);
}

static int ub_transfer(struct request *breq, char __user *ubuf)
{
	struct req_iterator iter;
	struct bio_vec *bvec;
	char *kpage, *kbuf;
	size_t len;
	int result;

	rq_for_each_segment(bvec, breq, iter) {
		kpage = kmap(bvec->bv_page);
		kbuf = kpage + bvec->bv_offset;
		len = bvec->bv_len;
		if (rq_data_dir(breq))
			result = copy_to_user(ubuf, kbuf, len);
		else
			result = copy_from_user(kbuf, ubuf, len);
		kunmap(bvec->bv_page);
		if (result)
			return result;
		ubuf += len;
	}

	return 0;
}

static ssize_t ub_read_read_in(struct ub_device *dev, struct ub_request *req,
			       char __user *buf, size_t count)
{
	struct ublock_read_in in;
	struct request *breq;

	if (count < sizeof(in)) {
		ub_dev_warn(dev, "READ read in: buffer too small "
			    "(expected at least %zu, got %zu)\n",
			    sizeof(in), count);
		return -EINVAL;
	}

	breq = req->private_data;

	in.offset = blk_rq_pos(breq) * KERNEL_SECTOR_SIZE;
	in.length = blk_rq_bytes(breq);

	if (copy_to_user(buf, &in, sizeof(in))) {
		ub_dev_warn(dev, "READ read in: fault copying\n");
		return -EFAULT;
	}

	return sizeof(in);
}

static ssize_t ub_read_write_out(struct ub_device *dev, struct ub_request *req,
				 const char __user *buf, size_t count)
{
	struct ublock_read_out out;
	struct request *breq = req->private_data;
	size_t exp_count;

	if (count < sizeof(out)) {
		ub_dev_warn(dev, "READ write out: buffer too small "
			    "(expected at least %zu, got %zu)\n",
			    sizeof(out), count);
		return -EINVAL;
	}

	if (copy_from_user(&out, buf, sizeof(out))) {
		ub_dev_warn(dev, "READ write out: fault copying result\n");
		return -EFAULT;
	}

	exp_count = sizeof(out) + ((out.status >= 0) ? blk_rq_bytes(breq) : 0);
	if (count != exp_count) {
		ub_dev_warn(dev, "READ write out: size mismatch "
			    "(expected %zu, got %zu)\n", exp_count, count);
		return -EINVAL;
	}

	if ((out.status >= 0) && (ub_transfer(breq, buf + sizeof(out)))) {
		ub_dev_warn(dev, "READ write out: fault copying data\n");
		return -EFAULT;
	}

	blk_end_request_all(breq, (out.status >= 0) ? 0 : out.status);

	return count;
}

static ssize_t ub_write_read_in(struct ub_device *dev, struct ub_request *req,
				char __user *buf, size_t count)
{
	struct ublock_write_in in;
	struct request *breq = req->private_data;

	if (count < sizeof(in) + blk_rq_bytes(breq)) {
		ub_dev_warn(dev, "WRITE read in: buffer too small "
			    "(expected at least %zu, got %zu)\n",
			    sizeof(in), count);
		return -EINVAL;
	}

	in.offset = blk_rq_pos(breq) * KERNEL_SECTOR_SIZE;
	in.length = blk_rq_bytes(breq);

	if (copy_to_user(buf, &in, sizeof(in))) {
		ub_dev_warn(dev, "WRITE read in: fault copying result\n");
		return -EFAULT;
	}

	if (ub_transfer(breq, buf + sizeof(in)) < 0) {
		ub_dev_warn(dev, "WRITE read in: fault copying data\n");
		return -EFAULT;
	}

	return sizeof(in) + blk_rq_bytes(breq);
}

static ssize_t ub_write_write_out(struct ub_device *dev, struct ub_request *req,
				  const char __user *buf, size_t count)
{
	struct ublock_write_out out;
	struct request *breq = req->private_data;

	if (count != sizeof(out)) {
		ub_dev_warn(dev, "WRITE write out: size mismatch "
			    "(expected %zu, got %zu)\n",
			    sizeof(out), count);
		return -EINVAL;
	}

	if (copy_from_user(&out, buf, sizeof(out))) {
		ub_dev_warn(dev, "WRITE write out: fault copying\n");
		return -EFAULT;
	}

	blk_end_request_all(breq, (out.status >= 0) ? 0 : out.status);

	return sizeof(out);
}

static void ub_xfer_terminate(struct ub_device *dev, struct ub_request *req)
{
	blk_end_request_all((struct request *)req->private_data, -EIO);
}

static const struct ub_request_type ub_type_init = {
	.in_opcode = UBLOCK_INIT_IN,
	.out_opcode = UBLOCK_INIT_OUT,
	.read_in_fn = ub_init_read_in,
	.write_out_fn = ub_init_write_out,
	.terminate_fn = NULL
};

static const struct ub_request_type ub_type_ready = {
	.in_opcode = UBLOCK_READY_IN,
	.out_opcode = UBLOCK_READY_OUT,
	.read_in_fn = ub_ready_read_in,
	.write_out_fn = ub_ready_write_out,
	.terminate_fn = NULL
};

static const struct ub_request_type ub_type_read = {
	.in_opcode = UBLOCK_READ_IN,
	.out_opcode = UBLOCK_READ_OUT,
	.read_in_fn = ub_read_read_in,
	.write_out_fn = ub_read_write_out,
	.terminate_fn = ub_xfer_terminate
};

static const struct ub_request_type ub_type_write = {
	.in_opcode = UBLOCK_WRITE_IN,
	.out_opcode = UBLOCK_WRITE_OUT,
	.read_in_fn = ub_write_read_in,
	.write_out_fn = ub_write_write_out,
	.terminate_fn = ub_xfer_terminate
};

static void ub_init_callback(struct work_struct *work)
{
	struct ub_device *dev = container_of(work, struct ub_device, init_work);
	struct ub_request *req = ub_request_alloc(&ub_type_ready);

	dev_info(ub_dev_to_dev(dev), "adding disk\n");

	add_disk(dev->disk);

	dev_info(ub_dev_to_dev(dev), "added disk; enqueuing READY\n");

	if (ub_enqueue(dev, req, 1)) {
		dev_warn(ub_dev_to_dev(dev), "ub_enqueue failed\n");
		return;
	}

	dev_info(ub_dev_to_dev(dev), "enqueued READY\n");
}

static int ub_make_request(struct ub_device *dev, struct request *breq)
{
	struct ub_request *req;

	if (!blk_fs_request(breq)) {
		ub_dev_warn(dev, "skipping non-fs request\n");
		blk_end_request_all(breq, -1);
		return 0;
	}

	if (rq_data_dir(breq))
		req = ub_request_alloc(&ub_type_write);
	else
		req = ub_request_alloc(&ub_type_read);

	if (!req) {
		ub_dev_warn(dev, "couldn't allocate request\n");
		return -ENOMEM;
	}

	req->private_data = breq;
	if (ub_enqueue(dev, req, 1)) {
		ub_dev_warn(dev, "couldn't enqueue request\n");
		ub_xfer_terminate(dev, req);
		ub_request_free(req);
		return -EIO;
	}

	return 0;
}

static ssize_t ub_request_read_in(struct ub_device *dev,
				  struct ub_request *req,
				  char __user *buf,
				  size_t count)
{
	return (req->type->read_in_fn)(dev, req, buf, count);
}

static ssize_t ub_request_write_out(struct ub_device *dev,
				    struct ub_request *req,
				    const char __user *buf,
				    size_t count)
{
	return (req->type->write_out_fn)(dev, req, buf, count);
}

static void ub_request_terminate(struct ub_device *dev, struct ub_request *req)
{
	if (req->type->terminate_fn)
		(req->type->terminate_fn)(dev, req);
}

static int ub_block_open(struct block_device *bdev, fmode_t mode)
{
	ub_get(ub_bdev_dev(bdev));

	return 0;
}

static int ub_block_release(struct gendisk *disk, fmode_t mode)
{
	ub_put(ub_disk_dev(disk));

	return 0;
}

static const struct block_device_operations ub_block_ops = {
	.owner   = THIS_MODULE,
	.open    = &ub_block_open,
	.release = &ub_block_release,
};

static void ub_block_request(struct request_queue *rq)
{
	struct ub_device *dev;
	struct request *req;

	while ((req = blk_fetch_request(rq)) != NULL) {
		dev = ub_req_dev(req);
		ub_make_request(dev, req);
	}
}

/* Must be called with ub_devices_lock held. */
static int __ub_index_used(int index)
{
	struct ub_device *dev;
	struct list_head *pos;

	list_for_each(pos, &ub_devices) {
		dev = list_entry(pos, struct ub_device, list);
		if (dev->index == index)
			return 1;
	}

	return 0;
}

static int __ub_find_free_index(void)
{
	int index;

	for (index = 0; __ub_index_used(index); index++)
		;

	return index;
}

static struct ub_device *ub_create(struct file *file)
{
	struct ub_device *dev;

	dev = kzalloc(sizeof(struct ub_device), GFP_KERNEL);
	if (!dev) {
		pr_warning("ublock: create: couldn't allocate ub_device\n");
		goto enomem;
	}

	dev->disk = alloc_disk(BLOCK_MINORS);
	if (!dev->disk) {
		pr_warning("ublock: create: alloc_disk failed\n");
		goto enomem;
	}

	spin_lock_init(&dev->queue_lock);
	dev->queue = blk_init_queue(&ub_block_request, &dev->queue_lock);
	if (!dev->queue) {
		pr_warning("ublock: create: blk_init_queue_failed\n");
		goto enomem;
	}

	mutex_lock(&ub_devices_lock);
	dev->index = __ub_find_free_index();

	dev->file = file;

	dev->disk->fops = &ub_block_ops;
	dev->disk->major = ub_block_major;
	dev->disk->minors = BLOCK_MINORS;
	dev->disk->first_minor = BLOCK_MINORS * dev->index;
	dev->disk->queue = dev->queue;
	dev->disk->private_data = dev;
	snprintf(dev->disk->disk_name, 32, "ublock%d", dev->index);

	INIT_LIST_HEAD(&dev->in_queue);
	dev->next_seq = 0;
	dev->nr_in = 0;
	spin_lock_init(&dev->in_lock);

	init_completion(&dev->in_added);

	INIT_LIST_HEAD(&dev->out_list);
	dev->nr_out = 0;
	mutex_init(&dev->out_lock);

	dev->max_buf = MAX_BUF;

	kref_init(&dev->refcount);
	dev->flags = 0;
	spin_lock_init(&dev->flags_lock);
	dev->fails = 0;

	list_add(&dev->list, &ub_devices);
	mutex_unlock(&ub_devices_lock);

	ub_dev_info(dev, "created device\n");

	return dev;

enomem:
	if (dev) {
		if (dev->queue)
			blk_cleanup_queue(dev->queue);
		if (dev->disk)
			put_disk(dev->disk);
		kfree(dev);
	}

	return NULL;
}

static void ub_terminate_all(struct ub_device *dev)
{
	struct list_head *pos, *tmp;
	struct ub_request *req;

	mutex_lock(&dev->out_lock);
	spin_lock(&dev->in_lock);

	list_for_each_safe(pos, tmp, &dev->in_queue) {
		req = list_entry(pos, struct ub_request, list);
		ub_request_terminate(dev, req);
		list_del(pos);
		dev->nr_in--;
		ub_request_free(req);
	}

	list_for_each_safe(pos, tmp, &dev->out_list) {
		req = list_entry(pos, struct ub_request, list);
		ub_request_terminate(dev, req);
		__ub_remove_out(dev, req);
		ub_request_free(req);
	}

	spin_unlock(&dev->in_lock);
	mutex_unlock(&dev->out_lock);
}

static void ub_destroy(struct ub_device *dev)
{
	ub_dev_info(dev, "terminating requests\n");

	ub_terminate_all(dev);

	if (dev->flags & DEV_INITED) {
		ub_dev_info(dev, "deleting disk\n");
		del_gendisk(dev->disk);
	}

	ub_dev_info(dev, "cleaning up queue\n");

	blk_cleanup_queue(dev->queue);

	put_disk(dev->disk);

	ub_dev_info(dev, "removing from device list\n");

	mutex_lock(&ub_devices_lock);
	list_del(&dev->list);
	mutex_unlock(&ub_devices_lock);

	ub_dev_info(dev, "destroyed device\n");

	ub_put(dev);
}

static void ub_destroy_callback(struct work_struct *work)
{
	ub_destroy(container_of(work, struct ub_device, destroy_work));
}

static void ub_destroy_later(struct ub_device *dev)
{
	int destroyed;

	spin_lock(&dev->flags_lock);
	destroyed = dev->flags & DEV_DESTROYED;
	dev->flags |= DEV_DESTROYED;
	spin_unlock(&dev->flags_lock);

	if (!destroyed) {
		INIT_WORK(&dev->destroy_work, &ub_destroy_callback);
		queue_work(ub_wq, &dev->destroy_work);
	}
}

static inline void ub_succeed(struct ub_device *dev)
{
	dev->fails = 0;
}

static void ub_fail(struct ub_device *dev)
{
	dev->fails++;
	if (dev->fails >= MAX_FAILURES) {
		ub_dev_warn(dev, "too many failures; destroying\n");
		ub_destroy_later(dev);
	}
}

static loff_t ub_control_llseek(struct file *file, loff_t off, int mode)
{
	return -EIO;
}

static ssize_t ub_control_read(struct file *file,
			       char __user *buf,
			       size_t count,
			       loff_t *off)
{
	struct ub_device *dev = ub_file_dev(file);
	struct ub_request *req;
	struct ublock_in_header in_h;
	ssize_t result;

	req = ub_dequeue(dev);
	if (!req)
		return -EINTR;

	in_h.seq    = req->seq;
	in_h.opcode = req->type->in_opcode;

	if (copy_to_user(buf, &in_h, sizeof(in_h))) {
		ub_dev_warn(dev, "control read: fault copying header\n");
		result = -EFAULT;
		goto error;
	}

	result = ub_request_read_in(dev, req,
				    buf + sizeof(in_h),
				    count - sizeof(in_h));
	if (result < 0) {
		ub_dev_warn(dev, "control read: request read in failed\n");
		goto error;
	}

	ub_put_out(dev, req);
	ub_succeed(dev);

	return sizeof(in_h) + result;

error:
	ub_enqueue(dev, req, 0);
	ub_fail(dev);

	return result;
}

static ssize_t ub_control_write(struct file *file,
				const char __user *buf,
				size_t count,
				loff_t *off)
{
	struct ub_device *dev = file->private_data;
	struct ub_request *req;
	struct ublock_out_header out_h;
	int result;

	req = NULL;

	if (count < sizeof(out_h)) {
		ub_dev_warn(dev, "control write: buffer too small "
			    "(expected at least %zu, got %zu)",
			    sizeof(out_h), count);
		result = -EINVAL;
		goto error;
	}

	if (copy_from_user(&out_h, buf, sizeof(out_h))) {
		ub_dev_warn(dev, "control write: fault copying header\n");
		result = -EFAULT;
		goto error;
	}

	req = ub_get_out(dev, out_h.seq);
	if (!req) {
		ub_dev_warn(dev, "control write: unknown seq (%u)\n",
			    out_h.seq);
		result = -EINVAL;
		goto error;
	}

	if (out_h.opcode != req->type->out_opcode) {
		ub_dev_warn(dev, "control write: opcode mismatch "
			    "(expected %u, got %u)\n",
			    req->type->out_opcode, out_h.opcode);
		result = -EINVAL;
		goto error;
	}

	result = ub_request_write_out(dev, req,
				      buf + sizeof(out_h),
				      count - sizeof(out_h));
	if (result < 0) {
		ub_dev_warn(dev, "control write: request write out failed\n");
		goto error;
	}

	ub_request_free(req);
	ub_succeed(dev);

	return count;

error:
	ub_put_out(dev, req);

	ub_fail(dev);

	return result;
}

static int ub_control_open(struct inode *inode, struct file *file)
{
	struct ub_device *dev;
	struct ub_request *req;

	dev = ub_create(file);
	if (!dev) {
		pr_warning("ublock: control open: ub_create failed\n");
		return -ENOMEM;
	}

	file->private_data = dev;

	req = ub_request_alloc(&ub_type_init);
	if (!req) {
		ub_dev_warn(dev, "control open: "
			    "couldn't allocate INIT request\n");
		ub_destroy(dev);
		return -ENOMEM;
	}

	ub_enqueue(dev, req, 1);

	return 0;
}

static int ub_control_release(struct inode *inode, struct file *file)
{
	struct ub_device *dev = file->private_data;

	ub_dev_info(dev, "control released; destroying\n");
	ub_destroy_later(dev);

	return 0;
}

static const struct file_operations ub_control_ops = {
	.owner   = THIS_MODULE,
	.llseek  = &ub_control_llseek,
	.read    = &ub_control_read,
	.write   = &ub_control_write,
	.open    = &ub_control_open,
	.release = &ub_control_release,
};

static struct miscdevice ub_control_misc = {
	.minor = 0,
	.name  = "ublockctl",
	.fops  = &ub_control_ops,
};

static int ub_block_init(void)
{
	ub_block_major = register_blkdev(0, "ublock");
	if (ub_block_major < 0) {
		pr_err("ublock: register_blkdev failed\n");
		return -ENOMEM;
	}

	return 0;
}

static void ub_block_exit(void)
{
	struct list_head *pos, *tmp;

	mutex_lock(&ub_devices_lock);
	list_for_each_safe(pos, tmp, &ub_devices) {
		ub_destroy(container_of(pos, struct ub_device, list));
	}
	mutex_unlock(&ub_devices_lock);

	unregister_blkdev(ub_block_major, "ublock");
}

static int ub_control_init(void)
{
	int result;

	result = misc_register(&ub_control_misc);
	if (result < 0) {
		pr_err("ublock: misc_register failed\n");
		return result;
	}

	return 0;
}

static void ub_control_exit(void)
{
	misc_deregister(&ub_control_misc);
}

static int __init ub_init(void)
{
	int result;

	INIT_LIST_HEAD(&ub_devices);
	mutex_init(&ub_devices_lock);

	ub_wq = create_singlethread_workqueue("ublock");
	if (!ub_wq) {
		result = -ENOMEM;
		pr_err("ublock: create_singlethread_workqueue failed\n");
		goto fail1;
	}

	result = ub_block_init();
	if (result < 0)
		goto fail2;

	result = ub_control_init();
	if (result < 0)
		goto fail3;

	pr_info("ublock: Userspace block device driver loaded\n");

	return 0;

fail3:
	ub_block_exit();
fail2:
	destroy_workqueue(ub_wq);
fail1:
	return result;
}

static void __exit ub_exit(void)
{
	ub_control_exit();
	ub_block_exit();
	flush_workqueue(ub_wq);
	destroy_workqueue(ub_wq);
}

module_init(ub_init);
module_exit(ub_exit);
