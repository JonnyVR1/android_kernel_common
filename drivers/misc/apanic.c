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
#include <linux/apanic.h>

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

#define INFOBUF_SIZE 256

struct apanic_data {
	char			devname[80];
	char			pname[80];
	struct panic_header	curr;
	char			infobuf[INFOBUF_SIZE];
	int			infolen;
	void			*bounce;
	struct proc_dir_entry	*proc_apanic;
	struct proc_dir_entry	*proc_apanic_reset;
	unsigned int		xfersize;
	unsigned int		devregistered;
};

static struct apanic_data drv_ctx;
static struct work_struct proc_removal_work;
static DEFINE_MUTEX(drv_mutex);

/*
 * /proc/apanic reads these keys/values whenever a device is registered:
 *
 * v <apanic header version>
 * s <apanic header size>
 * k {mtd|block}
 * d <devicename>
 * p <partitionname>
 *
 * and these values when a valid apanic dump header has been written
 * to /proc/apanic:
 *
 * c <console offset> <console len>
 * t <threads offset> <threads len>
 */

static void apanic_proc_reset(void)
{
	struct apanic_data *ctx = &drv_ctx;

	ctx->infolen = snprintf(ctx->infobuf, sizeof(ctx->infobuf),
				"v %d\ns %d\nk %s\nd %s\np %s\n",
				PHDR_VERSION, (int) sizeof(struct panic_header),
#if defined(CONFIG_APANIC_MTD)
				"mtd",
#elif defined(CONFIG_APANIC_MMC_SDHCI)
				"block",
#else
#error "apanic_proc_reset doesn't know the apanic device kind"
#endif
				ctx->devname, ctx->pname);
}

static int apanic_proc_read(char *buffer, char **start, off_t offset,
			       int count, int *peof, void *dat)
{
	struct apanic_data *ctx = &drv_ctx;

	if (!ctx->devregistered) {
		*peof = 1;
		return 0;
	}

	if (!count)
		return 0;

	if ((int) offset > ctx->infolen)
		return 0;

	if ((ctx->infolen - (int) offset) < count)
		count = ctx->infolen - (int) offset;

	memcpy(buffer, ctx->infobuf + offset, count);
	*start = count;

	if ((offset + count) >= ctx->infolen)
		*peof = 1;

	return count;
}

static int apanic_proc_write(struct file *file, 
			     const char __user *buffer,
			     unsigned long count, void *data)
{
	struct apanic_data *ctx = &drv_ctx;
	struct panic_header *hdr = ctx->bounce;
	unsigned long len = min(PAGE_SIZE, count);

	if (len < sizeof(struct panic_header))
		return -EINVAL;

	if (copy_from_user(hdr, buffer, len))
                return count;

	if (hdr->magic != PANIC_MAGIC) {
		printk(KERN_INFO "apanic: No panic data available (magic=0x%x)\n",
		       hdr->magic);
		apanic_dev_erase();
		return count;
	}

	if (hdr->version != PHDR_VERSION) {
		printk(KERN_INFO "apanic: Version mismatch (%d != %d)\n",
		       hdr->version, PHDR_VERSION);
		apanic_dev_erase();
		return count;
	}

	memcpy(&ctx->curr, hdr, sizeof(struct panic_header));

	ctx->infolen += snprintf(ctx->infobuf + ctx->infolen,
				 sizeof(ctx->infobuf) - ctx->infolen,
				"c %u %u\nt %u %u\n",
				hdr->console_offset, hdr->console_length,
				hdr->threads_offset, hdr->threads_length);

	printk(KERN_INFO "apanic: c(%u, %u) t(%u, %u)\n",
	       hdr->console_offset, hdr->console_length,
	       hdr->threads_offset, hdr->threads_length);


	return count;
}

static void apanic_remove_proc_work(struct work_struct *work)
{
	struct apanic_data *ctx = &drv_ctx;

	mutex_lock(&drv_mutex);
	apanic_dev_erase();
	memset(&ctx->curr, 0, sizeof(struct panic_header));
	apanic_proc_reset();
	mutex_unlock(&drv_mutex);
}

static int apanic_proc_reset_write(struct file *file, 
				   const char __user *buffer,
				   unsigned long count, void *data)
{
	struct apanic_data *ctx = &drv_ctx;

	if (ctx->devregistered)
		schedule_work(&proc_removal_work);

	return count;
}


int apanic_register_device(char *devname, char *pname, unsigned int xfersize)
{
	struct apanic_data *ctx = &drv_ctx;

	if (!devname) {
		drv_ctx.devregistered = 0;
		return 0;
	}

	if ((drv_ctx.bounce = (void *) __get_free_page(GFP_KERNEL)) == NULL) {
	    printk(KERN_ERR "apanic: Out of memory for bounce buffer\n");
	    return 1;
	}

	strncpy(drv_ctx.devname, devname, sizeof(drv_ctx.devname));
	drv_ctx.devname[sizeof(drv_ctx.devname)-1] = '\0';
	strncpy(drv_ctx.pname, pname, sizeof(drv_ctx.pname));
	drv_ctx.pname[sizeof(drv_ctx.pname)-1] = '\0';
	drv_ctx.xfersize = xfersize;
	drv_ctx.devregistered = 1;

	ctx->proc_apanic = create_proc_entry("apanic",
					     S_IWUSR | S_IRUGO, NULL);
	if (!ctx->proc_apanic)
		printk(KERN_ERR "%s: failed creating apanic proc file\n",
		       __func__);
	else {
		ctx->proc_apanic->read_proc = apanic_proc_read;
		ctx->proc_apanic->write_proc = apanic_proc_write;
		ctx->proc_apanic->size = sizeof(ctx->infobuf);
		ctx->proc_apanic->data = (void *) 1;
	}

	ctx->proc_apanic_reset = create_proc_entry("apanic-reset",
						   S_IWUSR | S_IRUGO, NULL);
	if (!ctx->proc_apanic_reset)
		printk(KERN_ERR "%s: failed creating apanic-reset proc file\n",
		       __func__);
	else {
		ctx->proc_apanic_reset->read_proc = NULL;
		ctx->proc_apanic_reset->write_proc = apanic_proc_reset_write;
	}

	apanic_proc_reset();
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
