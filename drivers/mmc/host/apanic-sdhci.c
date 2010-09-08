/* drivers/mmc/host/apanic-sdhci.c
 *
 * Copyright (C) 2010 Google, Inc.
 * Author: Todd Poynor <toddpoynor@google.com>
 *
 * Based on sdhci.c, which is:
 * Copyright (C) 2005-2008 Pierre Ossman, All Rights Reserved.
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
#include <linux/platform_device.h>
#include <linux/mmc/mmc.h>
#include <linux/mmc/host.h>
#include <linux/leds.h>
#include "sdhci.h"
#include <linux/apanic.h>

#define APANIC_MMC_BLOCKSIZE	512

static struct apanic_sdhci_data {
	char			devname[20];
	struct sdhci_host	*host;
	int			startbyte;
	int			sizebytes;
	int			sectoraddrs;
	int			cardinit;
} sdhci_ctx;

static inline void apanic_sdhci_writel(void __iomem *ioaddr, u32 val, int reg)
{
	writel(val, ioaddr + reg);
}

static inline void apanic_sdhci_writew(void __iomem *ioaddr, u16 val, int reg)
{
	writew(val, ioaddr + reg);
}

static inline void apanic_sdhci_writeb(void __iomem *ioaddr, u8 val, int reg)
{
	writeb(val, ioaddr + reg);
}

static inline u32 apanic_sdhci_readl(void __iomem *ioaddr, int reg)
{
	return readl(ioaddr + reg);
}

static inline u16 apanic_sdhci_readw(void __iomem *ioaddr, int reg)
{
	return readw(ioaddr + reg);
}

static inline u8 apanic_sdhci_readb(void __iomem *ioaddr, int reg)
{
	return readb(ioaddr + reg);
}

static void apanic_sdhci_dumpregs(void __iomem *ioaddr)
{
	printk(KERN_DEBUG ": ============== REGISTER DUMP ==============\n");

	printk(KERN_DEBUG  ": Sys addr: 0x%08x | Version:  0x%08x\n",
		apanic_sdhci_readl(ioaddr, SDHCI_DMA_ADDRESS),
		apanic_sdhci_readw(ioaddr, SDHCI_HOST_VERSION));
	printk(KERN_DEBUG  ": Blk size: 0x%08x | Blk cnt:  0x%08x\n",
		apanic_sdhci_readw(ioaddr, SDHCI_BLOCK_SIZE),
		apanic_sdhci_readw(ioaddr, SDHCI_BLOCK_COUNT));
	printk(KERN_DEBUG  ": Argument: 0x%08x | Trn mode: 0x%08x\n",
		apanic_sdhci_readl(ioaddr, SDHCI_ARGUMENT),
		apanic_sdhci_readw(ioaddr, SDHCI_TRANSFER_MODE));
	printk(KERN_DEBUG  ": Present:  0x%08x | Host ctl: 0x%08x\n",
		apanic_sdhci_readl(ioaddr, SDHCI_PRESENT_STATE),
		apanic_sdhci_readb(ioaddr, SDHCI_HOST_CONTROL));
	printk(KERN_DEBUG  ": Power:    0x%08x | Blk gap:  0x%08x\n",
		apanic_sdhci_readb(ioaddr, SDHCI_POWER_CONTROL),
		apanic_sdhci_readb(ioaddr, SDHCI_BLOCK_GAP_CONTROL));
	printk(KERN_DEBUG  ": Wake-up:  0x%08x | Clock:    0x%08x\n",
		apanic_sdhci_readb(ioaddr, SDHCI_WAKE_UP_CONTROL),
		apanic_sdhci_readw(ioaddr, SDHCI_CLOCK_CONTROL));
	printk(KERN_DEBUG  ": Timeout:  0x%08x | Int stat: 0x%08x\n",
		apanic_sdhci_readb(ioaddr, SDHCI_TIMEOUT_CONTROL),
		apanic_sdhci_readl(ioaddr, SDHCI_INT_STATUS));
	printk(KERN_DEBUG  ": Int enab: 0x%08x | Sig enab: 0x%08x\n",
		apanic_sdhci_readl(ioaddr, SDHCI_INT_ENABLE),
		apanic_sdhci_readl(ioaddr, SDHCI_SIGNAL_ENABLE));
	printk(KERN_DEBUG  ": AC12 err: 0x%08x | Slot int: 0x%08x\n",
		apanic_sdhci_readw(ioaddr, SDHCI_ACMD12_ERR),
		apanic_sdhci_readw(ioaddr, SDHCI_SLOT_INT_STATUS));
	printk(KERN_DEBUG  ": Caps:     0x%08x | Max curr: 0x%08x\n",
		apanic_sdhci_readl(ioaddr, SDHCI_CAPABILITIES),
		apanic_sdhci_readl(ioaddr, SDHCI_MAX_CURRENT));
}


static void apanic_sdhci_read_block_pio(u8 *buf)
{
	void __iomem *ioaddr = sdhci_ctx.host->ioaddr;
	unsigned long flags;
	size_t remain, chunk;
	u32 uninitialized_var(scratch);

	chunk = 0;

	local_irq_save(flags);
	remain = APANIC_MMC_BLOCKSIZE;

	while (remain) {
		if (chunk == 0) {
			scratch = apanic_sdhci_readl(ioaddr, SDHCI_BUFFER);
			chunk = 4;
		}

		*buf++ = scratch & 0xFF;
		scratch >>= 8;
		chunk--;
		remain--;
	}

	local_irq_restore(flags);
}

static void apanic_sdhci_write_block_pio(u8 *buf)
{
	void __iomem *ioaddr = sdhci_ctx.host->ioaddr;
	unsigned long flags;
	size_t remain, chunk;
	u32 scratch;

	chunk = 0;
	scratch = 0;

	local_irq_save(flags);
	remain = APANIC_MMC_BLOCKSIZE;

	while (remain) {
		scratch |= (u32)*buf << (chunk * 8);

		buf++;
		chunk++;
		remain--;

		if (chunk == 4) {
			apanic_sdhci_writel(ioaddr, scratch, SDHCI_BUFFER);
			chunk = 0;
			scratch = 0;
		}
	}

	local_irq_restore(flags);
}

static int apanic_sdhci_wait_for_interrupt(u32 *retmask)
{
	void __iomem *ioaddr = sdhci_ctx.host->ioaddr;
	u32 intmask;
	unsigned long timeout;
	int ret = 1;

	/* Wait max 100 ms for interrupt */
	timeout = 100;

	while (1) {
		if ((intmask = apanic_sdhci_readl(ioaddr, SDHCI_INT_STATUS))
		    != 0xffffffff) {
			if (intmask &
			    (SDHCI_INT_DATA_MASK | SDHCI_INT_CMD_MASK))
				break;
		}

		if (timeout == 0) {
			printk(KERN_ERR "apanic sdhci: Host not signalling "
			       "interrupt; status=0x%x\n", intmask);
			apanic_sdhci_dumpregs(ioaddr);
			goto err;
		}
		timeout--;
		mdelay(1);
	}

	apanic_sdhci_writel(ioaddr, intmask, SDHCI_INT_STATUS);

	if (intmask & (SDHCI_INT_TIMEOUT | SDHCI_INT_DATA_TIMEOUT)) {
		printk(KERN_ERR "apanic sdhci: Command or Data timeout; status=0x%x\n",
			intmask);
		apanic_sdhci_dumpregs(ioaddr);
		goto err;
	} else if (intmask & (SDHCI_INT_DATA_CRC | SDHCI_INT_DATA_END_BIT)) {
		printk(KERN_ERR "apanic sdhci: CRC/Data End error; status=0x%x\n",
			intmask);
		apanic_sdhci_dumpregs(ioaddr);
		goto err;
	} else if (intmask & (SDHCI_INT_ERROR)) {
		printk(KERN_ERR "apanic sdhci: Other error, status=0x%x\n",
			intmask);
		apanic_sdhci_dumpregs(ioaddr);
		goto err;
	}

	ret = 0;

err:
	*retmask = intmask;
	return ret;
}

static int apanic_sdhci_xfer(u16 opcode, u8 flags, u32 arg, void *buf,
			    u32 *rsp)
{
	void __iomem *ioaddr = sdhci_ctx.host->ioaddr;
	u32 mask;
	u32 prev_intstaten, prev_intsigen;
	u8 ctrl;
	u16 mode;
	u32 intmask, sumintmask;
	unsigned long timeout;
	unsigned int temp;
	int i;
	int dataxfer = 1;
	int ret = 1;

#define INTENABLEMASK SDHCI_INT_DATA_END_BIT | SDHCI_INT_DATA_CRC | \
		SDHCI_INT_DATA_TIMEOUT | SDHCI_INT_INDEX | SDHCI_INT_END_BIT | \
		SDHCI_INT_CRC | SDHCI_INT_TIMEOUT | SDHCI_INT_DATA_END | \
		SDHCI_INT_DATA_AVAIL | SDHCI_INT_SPACE_AVAIL | \
		SDHCI_INT_RESPONSE | SDHCI_INT_ERROR

	if (opcode == MMC_WRITE_BLOCK)
		mode = 0;
	else if (opcode == MMC_READ_SINGLE_BLOCK)
		mode = SDHCI_TRNS_READ;
	else
		dataxfer = 0;

	sumintmask = 0;

	/* Wait max 10 ms for command and data inhibit cleared */
	timeout = 10;
	mask = SDHCI_CMD_INHIBIT;

	if (dataxfer)
		mask |= SDHCI_DATA_INHIBIT;

	while ((temp = apanic_sdhci_readl(ioaddr, SDHCI_PRESENT_STATE)) & mask) {
		if (timeout == 0) {
			printk(KERN_ERR "apanic sdhci: Host never released "
			       "inhibit bit(s); present state=0x%x\n", temp);
			goto err;
		}
		timeout--;
		mdelay(1);
	}

	/* Enable interrupt status in regs, but disable IRQ generation */

	prev_intstaten = apanic_sdhci_readl(ioaddr, SDHCI_INT_ENABLE);
	apanic_sdhci_writel(ioaddr, INTENABLEMASK, SDHCI_INT_ENABLE);
	prev_intsigen = apanic_sdhci_readl(ioaddr, SDHCI_SIGNAL_ENABLE);
	apanic_sdhci_writel(ioaddr, 0, SDHCI_SIGNAL_ENABLE);

	if (dataxfer) {
		/* Ensure DMA off for PIO */
		ctrl = apanic_sdhci_readb(ioaddr, SDHCI_HOST_CONTROL);
		ctrl &= ~SDHCI_CTRL_DMA_MASK;
		apanic_sdhci_writeb(ioaddr, ctrl, SDHCI_HOST_CONTROL);

		apanic_sdhci_writew(ioaddr, APANIC_MMC_BLOCKSIZE, SDHCI_BLOCK_SIZE);
		apanic_sdhci_writew(ioaddr, 1, SDHCI_BLOCK_COUNT);
		apanic_sdhci_writew(ioaddr, mode, SDHCI_TRANSFER_MODE);
	}

	apanic_sdhci_writel(ioaddr, arg, SDHCI_ARGUMENT);
	apanic_sdhci_writew(ioaddr, SDHCI_MAKE_CMD(opcode, flags), SDHCI_COMMAND);

	while (1) {
		if (apanic_sdhci_wait_for_interrupt(&intmask))
			goto err_restore;

		sumintmask |= intmask;

		if (intmask & SDHCI_INT_RESPONSE) {
			if (flags & SDHCI_CMD_RESP_SHORT)
				*rsp = apanic_sdhci_readl(ioaddr, SDHCI_RESPONSE);
			else if (flags & SDHCI_CMD_RESP_LONG) {
				for (i = 0;i < 4;i++) {
					rsp[i] =
					   apanic_sdhci_readl(ioaddr,
						SDHCI_RESPONSE + (3-i)*4) << 8;
					if (i != 3)
						rsp[i] |=
						    apanic_sdhci_readb(ioaddr,
						       SDHCI_RESPONSE +
						       (3-i)*4-1);
				}
			}

			if (!dataxfer)
				break;
		}

		if (intmask & SDHCI_INT_DATA_AVAIL &&
		    opcode == MMC_READ_SINGLE_BLOCK) {
			apanic_sdhci_read_block_pio(buf);
		} else if (intmask & SDHCI_INT_SPACE_AVAIL &&
			   opcode == MMC_WRITE_BLOCK) {
			apanic_sdhci_write_block_pio(buf);
		}

		if (dataxfer && intmask & SDHCI_INT_DATA_END)
			break;
	}

	ret = 0;

err_restore:
	apanic_sdhci_writel(ioaddr, prev_intstaten, SDHCI_INT_ENABLE);
	apanic_sdhci_writel(ioaddr, prev_intsigen, SDHCI_SIGNAL_ENABLE);

err:
	if (ret) {
		if (sumintmask & SDHCI_INT_RESPONSE &&
		    flags & SDHCI_CMD_RESP_SHORT)
			printk("apanic sdhci: card response=0x%x\n", *rsp);

		apanic_sdhci_dumpregs(ioaddr);
	}

	return ret;
}

static void apanic_sdhci_set_clock(unsigned int clock)
{
	void __iomem *ioaddr = sdhci_ctx.host->ioaddr;
	struct sdhci_host *host = sdhci_ctx.host;
	int div;
	u16 clk;
	unsigned long timeout;

	if (host->ops->set_clock) {
		host->ops->set_clock(host, clock);
		if (host->quirks & SDHCI_QUIRK_NONSTANDARD_CLOCK)
			return;
	}

	apanic_sdhci_writew(ioaddr, 0, SDHCI_CLOCK_CONTROL);

	if (clock == 0)
		goto out;

	for (div = 1;div < 256;div *= 2) {
		if ((host->max_clk / div) <= clock)
			break;
	}

	div >>= 1;

	clk = div << SDHCI_DIVIDER_SHIFT;
	clk |= SDHCI_CLOCK_INT_EN;
	apanic_sdhci_writew(ioaddr, clk, SDHCI_CLOCK_CONTROL);

	/* Wait max 20 ms */
	timeout = 20;
	while (!((clk = apanic_sdhci_readw(ioaddr, SDHCI_CLOCK_CONTROL))
		& SDHCI_CLOCK_INT_STABLE)) {
		if (timeout == 0) {
			printk(KERN_ERR "apanic sdhci: Internal clock never "
				"stabilised.\n");
			apanic_sdhci_dumpregs(ioaddr);
			return;
		}
		timeout--;
		mdelay(1);
	}

	clk |= SDHCI_CLOCK_CARD_EN;
	apanic_sdhci_writew(ioaddr, clk, SDHCI_CLOCK_CONTROL);

out:

	host->clock = clock;
}

static void apanic_sdhci_set_power(unsigned short power)
{
	u8 pwr;

	if (power == (unsigned short)-1)
		pwr = 0;
	else {
		switch (1 << power) {
		case MMC_VDD_165_195:
			pwr = SDHCI_POWER_180;
			break;
		case MMC_VDD_29_30:
		case MMC_VDD_30_31:
			pwr = SDHCI_POWER_300;
			break;
		case MMC_VDD_32_33:
		case MMC_VDD_33_34:
			pwr = SDHCI_POWER_330;
			break;
		default:
			BUG();
		}
	}

	sdhci_ctx.host->pwr = pwr;

	if (pwr == 0) {
		apanic_sdhci_writeb(sdhci_ctx.host->ioaddr, 0,
				    SDHCI_POWER_CONTROL);
		return;
	}

	pwr |= SDHCI_POWER_ON;
	apanic_sdhci_writeb(sdhci_ctx.host->ioaddr, pwr, SDHCI_POWER_CONTROL);
}


static int apanic_sdhci_check_init_card(void)
{
	void __iomem *ioaddr = sdhci_ctx.host->ioaddr;
	struct sdhci_host *host = sdhci_ctx.host;
	unsigned int caps, ocr_avail, min_clk, vdd, rsp;
	u32 ocr;
	u32 cid[4];
	int timeout;

	if (sdhci_ctx.cardinit)
		return 0;

	caps = apanic_sdhci_readl(ioaddr, SDHCI_CAPABILITIES);
	ocr_avail = 0;

	if (caps & SDHCI_CAN_VDD_330)
		ocr_avail |= MMC_VDD_32_33|MMC_VDD_33_34;
	if (caps & SDHCI_CAN_VDD_300)
		ocr_avail |= MMC_VDD_29_30|MMC_VDD_30_31;
	if (caps & SDHCI_CAN_VDD_180)
		ocr_avail |= MMC_VDD_165_195;

	if (ocr_avail == 0) {
		printk(KERN_ERR "apanic sdhci: Hardware doesn't report any "
			"supported voltages.\n");
		return -1;
	}

	/* Put card back to idle state so can read OCR. */
	if (apanic_sdhci_xfer(MMC_GO_IDLE_STATE, SDHCI_CMD_RESP_NONE, 0, NULL,
			      NULL)) {
		printk("apanic sdhci: Go idle failed\n");
		return -1;
	}

	mdelay(2);

	/* Set SDCLK to minimum (divider 256), must be less than 400KHz. */
	min_clk = host->max_clk / 256;
	apanic_sdhci_set_clock(min_clk);

	/* Send available power modes and High Capacity support.  Read OCR
	   and wait for card ready. */
	timeout = 100; /* wait 100ms */

	while (1) {
		if (apanic_sdhci_xfer(MMC_SEND_OP_COND, SDHCI_CMD_RESP_SHORT,
				      ocr_avail | (1 << 30) , NULL, &ocr)) {
			printk("apanic sdhci: Send OCR failed\n");
			return -1;
		}

		if (ocr & MMC_CARD_BUSY)
			break;

		if (--timeout == 0) {
			printk("apanic sdhci: Timeout on MMC card ready; ocr=0x%x\n",
			       ocr);
			return -1;
		}
	}

	/* Set lowest compatible power mode between card and host. */
	ocr_avail &= ocr;
	vdd = ffs(ocr_avail);

	if (vdd) {
		vdd -= 1;
		apanic_sdhci_set_power((u8) vdd);
	} else
		printk(KERN_ERR "apanic sdhci: host doesn't support card's voltages\n");

	/* Read Card ID.  We don't care, but the card does. */
	if (apanic_sdhci_xfer(MMC_ALL_SEND_CID, SDHCI_CMD_RESP_LONG, 0,
			      NULL, cid))
		return -1;

	/* Set relative card address (always 1), exit card ID mode to
	   standby */
	if (apanic_sdhci_xfer(MMC_SET_RELATIVE_ADDR, SDHCI_CMD_RESP_SHORT,
			      1 << 16, NULL, &rsp))
		return -1;

	/* Select card, toggle from standby to transfer state */
	if (apanic_sdhci_xfer(MMC_SELECT_CARD, SDHCI_CMD_RESP_SHORT,
			      1 << 16, NULL, &rsp))
		return -1;

	/* Set clock to <= 20MHz, max for eMMC non-hispeed mode */
	apanic_sdhci_set_clock(20000000);

	/* Set max timeout */
	apanic_sdhci_writeb(ioaddr, 0xE, SDHCI_TIMEOUT_CONTROL);

	/* Is device sector addressed or byte addressed? */
	if (((ocr >> 29) & 0x3) == 0x2)
		sdhci_ctx.sectoraddrs = 1;

	/* Clear 4- and 8-bit width and hispeed */
	apanic_sdhci_writeb(ioaddr, 0, SDHCI_HOST_CONTROL);
	sdhci_ctx.cardinit = 1;
	return 0;
}

int apanic_dev_read(unsigned int offset, size_t *len, void *buf)
{
	u8 flags = SDHCI_CMD_RESP_SHORT | SDHCI_CMD_CRC |
		SDHCI_CMD_INDEX | SDHCI_CMD_DATA;
	u32 rsp;

	if (apanic_sdhci_check_init_card())
		return -1;

	offset += sdhci_ctx.startbyte;

	if (sdhci_ctx.sectoraddrs)
		offset /= APANIC_MMC_BLOCKSIZE;

	if (apanic_sdhci_xfer(MMC_READ_SINGLE_BLOCK, flags, offset, buf, &rsp))
		return -1;

	*len = APANIC_MMC_BLOCKSIZE;
	return 0;
}

int apanic_dev_write(unsigned int offset, const u_char *buf)
{
	u8 flags = SDHCI_CMD_RESP_SHORT | SDHCI_CMD_CRC |
		SDHCI_CMD_INDEX | SDHCI_CMD_DATA;
	u32 rsp;

	if (offset >= sdhci_ctx.sizebytes) {
		printk(KERN_ERR "apanic sdhci: out of space in partition\n");
		return -1;
	}

	if (apanic_sdhci_check_init_card())
			return -1;

	/* Divide byte address by 512B block size, assumes High Capacity
	   card.  Can read card's OCR (MMC_SEND_OP_COND response) bit 30
	   to find out whether or not HC. */

	if (apanic_sdhci_xfer(MMC_WRITE_BLOCK, flags,
			      (sdhci_ctx.startbyte + offset)
			      / APANIC_MMC_BLOCKSIZE, (void *) buf, &rsp))
		return -1;

	return APANIC_MMC_BLOCKSIZE;
}

void apanic_dev_erase(void)
{
	/* Not implemented for apanic SDHCI, not safe. */
}

void apanic_sdhci_register_device(char *devname, void *host)
{

	strncpy(sdhci_ctx.devname, devname, sizeof(sdhci_ctx.devname));
	sdhci_ctx.devname[sizeof(sdhci_ctx.devname)-1] = '\0';
	sdhci_ctx.host = (struct sdhci_host *) host;
	return;
}

void apanic_sdhci_check_partition(char *pname, unsigned long startbyte,
				  unsigned long sizebytes,
				  struct device *blkdev)
{
	struct kobject *kobj = &blkdev->kobj;

	if (strcmp(pname, CONFIG_APANIC_PLABEL) != 0)
		return;

	/* verify the block device kobj is a child of our registered
	   SDHCI controller */

	while (kobj) {
		if (strcmp(kobject_name(kobj), sdhci_ctx.devname) == 0)
			break;

		kobj = kobj->parent;
	}

	if (!kobj) {
		printk("\napanic sdhci: blkdev %s not a child of %s, skipping\n",
		       kobject_name(&blkdev->kobj), sdhci_ctx.devname);
		return;
	}

	sdhci_ctx.startbyte = startbyte;
	sdhci_ctx.sizebytes = sizebytes;

	if (sdhci_ctx.host != NULL) {
		printk("\napanic sdhci: Registering device %s partition %s\n",
		       sdhci_ctx.devname, pname);
		apanic_register_device(1, APANIC_MMC_BLOCKSIZE);
	}
}
