/* drivers/misc/apanic_mtd.c
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
#include <linux/mtd/mtd.h>
#include <linux/notifier.h>
#include <linux/mtd/mtd.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <linux/preempt.h>
#include <linux/apanic.h>

static struct apanic_mtd_data {
	struct mtd_info		*mtd;
} mtdctx;

static unsigned int *apanic_bbt;
static unsigned int apanic_erase_blocks;
static unsigned int apanic_good_blocks;

static void set_bb(unsigned int block, unsigned int *bbt)
{
	unsigned int flag = 1;

	BUG_ON(block >= apanic_erase_blocks);

	flag = flag << (block%32);
	apanic_bbt[block/32] |= flag;
	apanic_good_blocks--;
}

static unsigned int get_bb(unsigned int block, unsigned int *bbt)
{
	unsigned int flag;

	BUG_ON(block >= apanic_erase_blocks);

	flag = 1 << (block%32);
	return apanic_bbt[block/32] & flag;
}

static void alloc_bbt(struct mtd_info *mtd, unsigned int *bbt)
{
	int bbt_size;
	apanic_erase_blocks = (mtd->size)>>(mtd->erasesize_shift);
	bbt_size = (apanic_erase_blocks+32)/32;

	apanic_bbt = kmalloc(bbt_size*4, GFP_KERNEL);
	memset(apanic_bbt, 0, bbt_size*4);
	apanic_good_blocks = apanic_erase_blocks;
}
static void scan_bbt(struct mtd_info *mtd, unsigned int *bbt)
{
	int i;

	for (i = 0; i < apanic_erase_blocks; i++) {
		if (mtd->block_isbad(mtd, i*mtd->erasesize))
			set_bb(i, apanic_bbt);
	}
}

#define APANIC_INVALID_OFFSET 0xFFFFFFFF

static unsigned int phy_offset(struct mtd_info *mtd, unsigned int offset)
{
	unsigned int logic_block = offset>>(mtd->erasesize_shift);
	unsigned int phy_block;
	unsigned good_block = 0;

	for (phy_block = 0; phy_block < apanic_erase_blocks; phy_block++) {
		if (!get_bb(phy_block, apanic_bbt))
			good_block++;
		if (good_block == (logic_block + 1))
			break;
	}

	if (good_block != (logic_block + 1))
		return APANIC_INVALID_OFFSET;

	return offset + ((phy_block-logic_block)<<mtd->erasesize_shift);
}

static void apanic_erase_callback(struct erase_info *done)
{
	wait_queue_head_t *wait_q = (wait_queue_head_t *) done->priv;
	wake_up(wait_q);
}

int apanic_dev_read(unsigned int addr, size_t *retlen, void *buf)
{
	unsigned int offset = phy_offset(mtdctx.mtd, addr);
	int rc;

	if (offset == APANIC_INVALID_OFFSET) {
		pr_err("apanic mtd: reading an invalid address\n");
		return -EINVAL;
	}

	rc = mtdctx.mtd->read(mtdctx.mtd, offset, mtdctx.mtd->writesize,
			      retlen, buf);

	if (rc == -EBADMSG && offset == 0) {
		printk(KERN_WARNING
		       "apanic mtd: Bad ECC on block 0 (ignored)\n");
	} else if (rc && rc != -EUCLEAN) {
		printk(KERN_ERR "apanic mtd: Error reading offset %d (%d)\n",
		       offset, rc);
		return -EIO;
	}

	if (*retlen != mtdctx.mtd->writesize) {
		printk(KERN_ERR "apanic mtd: Bad read length at offset %d"
		       " (%d, expected %d)\n",
		       offset, *retlen, mtdctx.mtd->writesize);
		return -EIO;
	}

	return rc;
}

int apanic_dev_write(unsigned int to, const u_char *buf)
{
	struct mtd_info *mtd = mtdctx.mtd;
	int rc;
	size_t wlen;
	int panic = in_interrupt() | in_atomic();

	if (panic && !mtd->panic_write) {
		printk(KERN_EMERG "%s: No panic_write available\n", __func__);
		return 0;
	} else if (!panic && !mtd->write) {
		printk(KERN_EMERG "%s: No write available\n", __func__);
		return 0;
	}

	to = phy_offset(mtd, to);
	if (to == APANIC_INVALID_OFFSET) {
		printk(KERN_EMERG "apanic: write to invalid address\n");
		return 0;
	}

	if (panic)
		rc = mtd->panic_write(mtd, to, mtd->writesize, &wlen, buf);
	else
		rc = mtd->write(mtd, to, mtd->writesize, &wlen, buf);

	if (rc) {
		printk(KERN_EMERG
		       "%s: Error writing data to flash (%d)\n",
		       __func__, rc);
		return rc;
	}

	return wlen;
}

void apanic_dev_erase(void)
{
	struct erase_info erase;
	DECLARE_WAITQUEUE(wait, current);
	wait_queue_head_t wait_q;
	int rc, i;

	init_waitqueue_head(&wait_q);
	erase.mtd = mtdctx.mtd;
	erase.callback = apanic_erase_callback;
	erase.len = mtdctx.mtd->erasesize;
	erase.priv = (u_long)&wait_q;
	for (i = 0; i < mtdctx.mtd->size; i += mtdctx.mtd->erasesize) {
		erase.addr = i;
		set_current_state(TASK_INTERRUPTIBLE);
		add_wait_queue(&wait_q, &wait);

		if (get_bb(erase.addr>>mtdctx.mtd->erasesize_shift, apanic_bbt)) {
			printk(KERN_WARNING
			       "apanic mtd: Skipping erase of bad "
			       "block @%llx\n", erase.addr);
			set_current_state(TASK_RUNNING);
			remove_wait_queue(&wait_q, &wait);
			continue;
		}

		rc = mtdctx.mtd->erase(mtdctx.mtd, &erase);
		if (rc) {
			set_current_state(TASK_RUNNING);
			remove_wait_queue(&wait_q, &wait);
			printk(KERN_ERR
			       "apanic mtd: Erase of 0x%llx, 0x%llx failed\n",
			       (unsigned long long) erase.addr,
			       (unsigned long long) erase.len);
			if (rc == -EIO) {
				if (mtdctx.mtd->block_markbad(mtdctx.mtd,
							    erase.addr)) {
					printk(KERN_ERR
					       "apanic mtd: Err marking blk bad\n");
					goto out;
				}
				printk(KERN_INFO
				       "apanic mtd: Marked a bad block"
				       " @%llx\n", erase.addr);
				set_bb(erase.addr>>mtdctx.mtd->erasesize_shift,
					apanic_bbt);
				continue;
			}
			goto out;
		}
		schedule();
		remove_wait_queue(&wait_q, &wait);
	}
	printk(KERN_DEBUG "apanic mtd: %s partition erased\n",
	       CONFIG_APANIC_PLABEL);
out:
	return;
}

static void mtd_panic_notify_add(struct mtd_info *mtd)
{
	if (strcmp(mtd->name, CONFIG_APANIC_PLABEL))
		return;

	mtdctx.mtd = mtd;
	printk(KERN_INFO "apanic mtd: Bound to partition '%s'\n", mtd->name);

	alloc_bbt(mtd, apanic_bbt);
	scan_bbt(mtd, apanic_bbt);

	if (apanic_good_blocks == 0) {
		printk(KERN_ERR "apanic mtd: no any good blocks?!\n");
		goto out_err;
	}

	if (apanic_register_device(1, mtd->writesize))
		goto out_err;

	return;
out_err:
	mtdctx.mtd = NULL;
}

static void mtd_panic_notify_remove(struct mtd_info *mtd)
{
	if (mtd == mtdctx.mtd) {
		mtdctx.mtd = NULL;
		apanic_register_device(0, mtd->writesize);
		printk(KERN_INFO "apanic mtd: Unbound from %s\n", mtd->name);
	}
}

static struct mtd_notifier mtd_panic_notifier = {
	.add	= mtd_panic_notify_add,
	.remove	= mtd_panic_notify_remove,
};

int __init apanic_mtd_init(void)
{
	memset(&mtdctx, 0, sizeof(mtdctx));
	register_mtd_user(&mtd_panic_notifier);
	return 0;
}

module_init(apanic_mtd_init);
