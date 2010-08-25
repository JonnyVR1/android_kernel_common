/* drivers/misc/apanic.c
 *
 * Copyright (C) 2009 Google, Inc.
 * Author: San Mehat <san@android.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/device.h>
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/wakelock.h>
#include <linux/platform_device.h>
#include <linux/uaccess.h>
#include <linux/notifier.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <linux/preempt.h>

extern void ram_console_enable_console(int);

struct panic_header {
	u32 magic;
#define PANIC_MAGIC 0xdeadf00d

	u32 version;
#define PHDR_VERSION   0x01

	u32 console_offset;
	u32 console_length;

	u32 threads_offset;
	u32 threads_length;
};

struct apanic_data {
	struct panic_header	curr;
	void			*bounce;
	struct proc_dir_entry	*apanic_console;
	struct proc_dir_entry	*apanic_threads;
	unsigned int		xfersize;
	unsigned int		devregistered;
};

static struct apanic_data drv_ctx;
static struct work_struct proc_removal_work;
static DEFINE_MUTEX(drv_mutex);

extern int apanic_dev_read(unsigned int addr, size_t *retlen, void *buf);
extern void apanic_dev_erase(void);
extern int apanic_dev_write(loff_t to, const u_char *buf);

static int apanic_proc_read(char *buffer, char **start, off_t offset,
			       int count, int *peof, void *dat)
{
	struct apanic_data *ctx = &drv_ctx;
	size_t file_length;
	off_t file_offset;
	unsigned int page_no;
	off_t page_offset;
	int rc;
	size_t len;

	if (!ctx->devregistered) {
		*peof = 1;
		return 0;
	}

	if (!count)
		return 0;

	mutex_lock(&drv_mutex);

	switch ((int) dat) {
	case 1:	/* apanic_console */
		file_length = ctx->curr.console_length;
		file_offset = ctx->curr.console_offset;
		break;
	case 2:	/* apanic_threads */
		file_length = ctx->curr.threads_length;
		file_offset = ctx->curr.threads_offset;
		break;
	default:
		pr_err("Bad dat (%d)\n", (int) dat);
		mutex_unlock(&drv_mutex);
		return -EINVAL;
	}

	if ((offset + count) > file_length) {
		mutex_unlock(&drv_mutex);
		return 0;
	}

	if (count > ctx->xfersize)
		count = ctx->xfersize;

	page_no = (file_offset + offset) / ctx->xfersize;
	page_offset = (file_offset + offset) % ctx->xfersize;

	rc = apanic_dev_read(page_no * ctx->xfersize, &len, ctx->bounce);

	if (rc) {
		mutex_unlock(&drv_mutex);
		return -EINVAL;
	}

	if (page_offset)
		count -= page_offset;
	memcpy(buffer, ctx->bounce + page_offset, count);

	*start = count;

	if ((offset + count) == file_length)
		*peof = 1;

	mutex_unlock(&drv_mutex);
	return count;
}


static void apanic_remove_proc_work(struct work_struct *work)
{
	struct apanic_data *ctx = &drv_ctx;

	mutex_lock(&drv_mutex);
	apanic_dev_erase();
	memset(&ctx->curr, 0, sizeof(struct panic_header));
	if (ctx->apanic_console) {
		remove_proc_entry("apanic_console", NULL);
		ctx->apanic_console = NULL;
	}
	if (ctx->apanic_threads) {
		remove_proc_entry("apanic_threads", NULL);
		ctx->apanic_threads = NULL;
	}
	mutex_unlock(&drv_mutex);
}

static int apanic_proc_write(struct file *file, const char __user *buffer,
				unsigned long count, void *data)
{
	if (ctx->devregistered)
		schedule_work(&proc_removal_work);

	return count;
}

int apanic_register_device(int regunreg, unsigned int xfersize)
{
	struct apanic_data *ctx = &drv_ctx;
	struct panic_header *hdr = ctx->bounce;
	int    proc_entry_created = 0;
	int    rc;
	size_t len;

	if (!regunreg) {
		drv_ctx.devregistered = 0;
		return 0;
	}

	if ((drv_ctx.bounce = (void *) __get_free_page(GFP_KERNEL)) == NULL) {
	    printk(KERN_ERR "apanic: Out of memory for bounce buffer\n");
	    return 1;
	}

	drv_ctx.xfersize = xfersize;
	rc = apanic_dev_read(0, &len, drv_ctx.bounce);

	if (rc) {
		printk(KERN_ERR "apanic: Error reading panic header (%d)\n", rc);
		return rc;
	}

	drv_ctx.devregistered = 1;
	hdr = ctx->bounce;

	if (hdr->magic != PANIC_MAGIC) {
		printk(KERN_INFO "apanic: No panic data available\n");
		apanic_dev_erase();
		return 0;
	}

	if (hdr->version != PHDR_VERSION) {
		printk(KERN_INFO "apanic: Version mismatch (%d != %d)\n",
		       hdr->version, PHDR_VERSION);
		apanic_dev_erase();
		return 0;
	}

	memcpy(&ctx->curr, hdr, sizeof(struct panic_header));

	printk(KERN_INFO "apanic: c(%u, %u) t(%u, %u)\n",
	       hdr->console_offset, hdr->console_length,
	       hdr->threads_offset, hdr->threads_length);

	if (hdr->console_length) {
		ctx->apanic_console = create_proc_entry("apanic_console",
						      S_IFREG | S_IRUGO, NULL);
		if (!ctx->apanic_console)
			printk(KERN_ERR "%s: failed creating procfile\n",
			       __func__);
		else {
			ctx->apanic_console->read_proc = apanic_proc_read;
			ctx->apanic_console->write_proc = apanic_proc_write;
			ctx->apanic_console->size = hdr->console_length;
			ctx->apanic_console->data = (void *) 1;
			proc_entry_created = 1;
		}
	}

	if (hdr->threads_length) {
		ctx->apanic_threads = create_proc_entry("apanic_threads",
						       S_IFREG | S_IRUGO, NULL);
		if (!ctx->apanic_threads)
			printk(KERN_ERR "%s: failed creating procfile\n",
			       __func__);
		else {
			ctx->apanic_threads->read_proc = apanic_proc_read;
			ctx->apanic_threads->write_proc = apanic_proc_write;
			ctx->apanic_threads->size = hdr->threads_length;
			ctx->apanic_threads->data = (void *) 2;
			proc_entry_created = 1;
		}
	}

	if (!proc_entry_created)
		apanic_dev_erase();

	return 0;
}

static int in_panic = 0;

extern int log_buf_copy(char *dest, int idx, int len);
extern void log_buf_clear(void);

/*
 * Writes the contents of the console to the specified offset in flash.
 * Returns number of bytes written
 */
static int apanic_write_console(unsigned int off)
{
	struct apanic_data *ctx = &drv_ctx;
	int saved_oip;
	int idx = 0;
	int rc, rc2;
	unsigned int last_chunk = 0;

	while (!last_chunk) {
		saved_oip = oops_in_progress;
		oops_in_progress = 1;
		rc = log_buf_copy(ctx->bounce, idx, ctx->xfersize);
		if (rc < 0)
			break;

		if (rc != ctx->xfersize)
			last_chunk = rc;

		oops_in_progress = saved_oip;
		if (rc <= 0)
			break;
		if (rc != ctx->xfersize)
			memset(ctx->bounce + rc, 0, ctx->xfersize - rc);

		rc2 = apanic_dev_write(off, ctx->bounce);

		if (rc2 <= 0) {
			printk(KERN_EMERG
			       "apanic: Device write failed (%d)\n", rc2);
			return idx;
		}
		if (!last_chunk)
			idx += rc2;
		else
			idx += last_chunk;
		off += rc2;
	}
	return idx;
}

static int apanic(struct notifier_block *this, unsigned long event,
			void *ptr)
{
	struct apanic_data *ctx = &drv_ctx;
	struct panic_header *hdr = (struct panic_header *) ctx->bounce;
	int console_offset = 0;
	int console_len = 0;
	int threads_offset = 0;
	int threads_len = 0;
	int rc;

	if (in_panic)
		return NOTIFY_DONE;
	in_panic = 1;
#ifdef CONFIG_PREEMPT
	/* Ensure that cond_resched() won't try to preempt anybody */
	add_preempt_count(PREEMPT_ACTIVE);
#endif
	touch_softlockup_watchdog();

	if (!ctx->devregistered)
		goto out;

	if (ctx->curr.magic) {
		printk(KERN_EMERG "Crash partition in use!\n");
		goto out;
	}

	console_offset = ctx->xfersize;

	/*
	 * Write out the console
	 */
	console_len = apanic_write_console(console_offset);
	if (console_len < 0) {
		printk(KERN_EMERG "Error writing console to panic log! (%d)\n",
		       console_len);
		console_len = 0;
	}

	/*
	 * Write out all threads
	 */
	threads_offset = ALIGN(console_offset + console_len,
			       ctx->xfersize);
	if (!threads_offset)
		threads_offset = ctx->xfersize;

#ifdef CONFIG_ANDROID_RAM_CONSOLE
	ram_console_enable_console(0);
#endif

	log_buf_clear();
	show_state_filter(0);

	threads_len = apanic_write_console(threads_offset);
	if (threads_len < 0) {
		printk(KERN_EMERG "Error writing threads to panic log! (%d)\n",
		       threads_len);
		threads_len = 0;
	}

	/*
	 * Finally write the panic header
	 */
	memset(ctx->bounce, 0, PAGE_SIZE);
	hdr->magic = PANIC_MAGIC;
	hdr->version = PHDR_VERSION;

	hdr->console_offset = console_offset;
	hdr->console_length = console_len;

	hdr->threads_offset = threads_offset;
	hdr->threads_length = threads_len;

	rc = apanic_dev_write(0, ctx->bounce);

	if (rc <= 0) {
		printk(KERN_EMERG "apanic: Header write failed (%d)\n",
		       rc);
		goto out;
	}

	printk(KERN_EMERG "apanic: Panic dump sucessfully written to flash\n");

 out:
#ifdef CONFIG_PREEMPT
	sub_preempt_count(PREEMPT_ACTIVE);
#endif
	in_panic = 0;
	return NOTIFY_DONE;
}

static struct notifier_block panic_blk = {
	.notifier_call	= apanic,
};

static int panic_dbg_get(void *data, u64 *val)
{
	apanic(NULL, 0, NULL);
	return 0;
}

static int panic_dbg_set(void *data, u64 val)
{
	BUG();
	return -1;
}

DEFINE_SIMPLE_ATTRIBUTE(panic_dbg_fops, panic_dbg_get, panic_dbg_set, "%llu\n");

int __init apanic_init(void)
{
	atomic_notifier_chain_register(&panic_notifier_list, &panic_blk);
	debugfs_create_file("apanic", 0644, NULL, NULL, &panic_dbg_fops);
	INIT_WORK(&proc_removal_work, apanic_remove_proc_work);
	printk(KERN_INFO "Android kernel panic handler initialized\n");
	return 0;
}

module_init(apanic_init);
