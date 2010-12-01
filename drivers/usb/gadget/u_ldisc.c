/*
 * ACM Line Discipline
 *
 * Copyright (C) 2010 Google, Inc.
 * Author: Benoit Goby <benoit@android.com>
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

/* #define VERBOSE_DEBUG */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/device.h>
#include <linux/delay.h>
#include <linux/tty.h>
#include <linux/tty_flip.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include "u_ldisc.h"


#define READ_POOL_SIZE 8

#define NUM_DISCS 5
static struct gldisc disc_list[NUM_DISCS];
static DEFINE_MUTEX(disc_list_lock);

static void gld_free_req(struct usb_ep *ep, struct usb_request *req);


#ifdef VERBOSE_DEBUG
#define pr_vdebug(fmt, arg...) \
	pr_debug(fmt, ##arg)
#else
#define pr_vdebug(fmt, arg...) \
	({ if (0) pr_debug(fmt, ##arg); })
#endif


static void gld_read_complete(struct usb_ep *ep, struct usb_request *req)
{
	struct gldisc *gld = ep->driver_data;
	unsigned long flags;
	int count;
	int status;

	pr_vdebug("%s\n", __func__);

	switch (req->status) {
	case 0:
		/* normal completion */
		break;
	case -ESHUTDOWN:
		pr_vdebug("%s: shutdown\n", __func__);
		return;
	default:
		pr_warn("%s: unexpected status %d\n", __func__, req->status);
		return;
	}

	spin_lock_irqsave(&gld->lock, flags);
	if (req->actual && gld->tty) {
		count = gld->tty->driver->ops->write(gld->tty,
					req->buf, req->actual);
		if (count != req->actual)
			pr_err("%s: dropped %d bytes\n", __func__,
						req->actual - count);
	}
	spin_unlock_irqrestore(&gld->lock, flags);

	status = usb_ep_queue(ep, req, GFP_ATOMIC);
	if (status)
		pr_debug("%s: ep queue err %d\n", __func__, status);
}

static void gld_write_complete(struct usb_ep *ep, struct usb_request *req)
{
	pr_vdebug("%s\n", __func__);

	switch (req->status) {
	case 0:
		/* normal completion */
		break;
	case -ESHUTDOWN:
		pr_vdebug("%s: shutdown\n", __func__);
		break;
	default:
		pr_warn("%s: unexpected status %d\n", __func__, req->status);
		break;
	}

	gld_free_req(ep, req);
}

struct usb_request *gld_alloc_req(struct usb_ep *ep, unsigned len, gfp_t flags)
{
	struct usb_request *req;

	req = usb_ep_alloc_request(ep, flags);
	if (!req)
		return req;

	req->length = len;
	req->buf = kmalloc(len, flags);
	if (!req->buf) {
		usb_ep_free_request(ep, req);
		return NULL;
	}

	return req;
}

static int gld_alloc_requests(struct usb_ep *ep, struct list_head *head,
		void (*fn)(struct usb_ep *, struct usb_request *))
{
	struct usb_request *req;
	int i;

	pr_vdebug("%s\n", __func__);

	for (i = 0; i < READ_POOL_SIZE; i++) {
		req = gld_alloc_req(ep, ep->maxpacket, GFP_ATOMIC);
		if (!req)
			return list_empty(head) ? -ENOMEM : 0;
		req->complete = fn;
		list_add_tail(&req->list, head);
	}
	return 0;
}

static void gld_free_req(struct usb_ep *ep, struct usb_request *req)
{
	kfree(req->buf);
	usb_ep_free_request(ep, req);
}

static void gld_free_requests(struct usb_ep *ep, struct list_head *head)
{
	struct usb_request *req;

	pr_vdebug("%s\n", __func__);

	while (!list_empty(head)) {
		req = list_first_entry(head, struct usb_request, list);
		list_del(&req->list);
		gld_free_req(ep, req);
	}
}

/* called with gld->lock locked */
static int gld_start_rx(struct gldisc *gld)
{
	struct list_head *pool = &gld->read_pool;
	struct usb_ep *out = gld->out;
	struct usb_request *req;
	int status;
	int started = 0;

	pr_vdebug("%s\n", __func__);

	while (!list_empty(pool)) {
		req = list_first_entry(pool, struct usb_request, list);
		list_del(&req->list);
		req->length = out->maxpacket;

		spin_unlock(&gld->lock);
		status = usb_ep_queue(out, req, GFP_ATOMIC);
		spin_lock(&gld->lock);

		if (status) {
			pr_debug("%s: queue err %d\n", __func__, status);
			list_add(&req->list, pool);
			break;
		}
		started++;

		/* abort immediately after disconnect */
		if (!gld->connected)
			break;
	}
	return started;
}

/* called with gld->lock locked */
static int gld_start_io(struct gldisc *gld)
{
	struct list_head *head = &gld->read_pool;
	struct usb_ep *ep = gld->out;
	int status;
	int started;

	pr_vdebug("%s\n", __func__);

	status = gld_alloc_requests(ep, head, gld_read_complete);
	if (status)
		return status;

	started = gld_start_rx(gld);
	if (!started) {
		gld_free_requests(ep, head);
		status = -EIO;
	}

	return status;
}

struct gldisc *gldisc_get(int port_num)
{
	pr_vdebug("%s\n", __func__);
	if (port_num < 0 || port_num >= NUM_DISCS)
		return NULL;
	return &disc_list[port_num];
}

void gldisc_cleanup(void)
{
	pr_vdebug("%s\n", __func__);
}

/* notify ldisc that USB link is active */
int gldisc_connect(struct gldisc *gld)
{
	unsigned long flags;
	int status;

	pr_vdebug("%s\n", __func__);

	status = usb_ep_enable(gld->in, gld->in_desc);
	if (status < 0) {
		pr_err("%s: cannot enable in ep", __func__);
		return status;
	}
	gld->in->driver_data = gld;

	status = usb_ep_enable(gld->out, gld->out_desc);
	if (status < 0) {
		pr_err("%s: cannot enable out ep", __func__);
		usb_ep_disable(gld->in);
		gld->in->driver_data = NULL;
		return status;
	}
	gld->out->driver_data = gld;

	spin_lock_irqsave(&gld->lock, flags);
	gld->connected = true;
	if (gld->opened) {
		pr_debug("%s: start io\n", __func__);
		gld_start_io(gld);
		if (gld->connect)
			gld->connect(gld);
	} else {
		if (gld->disconnect)
			gld->disconnect(gld);
	}
	spin_unlock_irqrestore(&gld->lock, flags);

	return status;
}

/* notify ldisc that USB link is inactive */
void gldisc_disconnect(struct gldisc *gld)
{
	unsigned long flags;

	pr_vdebug("%s\n", __func__);

	gld->connected = false;

	usb_ep_disable(gld->out);
	gld->out->driver_data = NULL;

	usb_ep_disable(gld->in);
	gld->in->driver_data = NULL;

	spin_lock_irqsave(&gld->lock, flags);
	gld_free_requests(gld->out, &gld->read_pool);
	spin_unlock_irqrestore(&gld->lock, flags);
}


/*
 *	Line Discipline
 */

static int g_ldisc_open(struct tty_struct *tty)
{
	struct gldisc *gld = NULL;
	int i;

	pr_vdebug("%s\n", __func__);

	mutex_lock(&disc_list_lock);
	for (i = 0; i < NUM_DISCS; ++i) {
		if (disc_list[i].opened)
			continue;
		gld = &disc_list[i];
		gld->opened = true;
		break;
	}
	mutex_unlock(&disc_list_lock);

	if (!gld)
		return -ENXIO;

	spin_lock_irq(&gld->lock);

	gld->tty = tty;
	tty->disc_data = gld;

	/* if connected, start the I/O stream */
	if (gld->connected) {
		gld_start_io(gld);
		if (gld->connect)
			gld->connect(gld);
	}

	spin_unlock_irq(&gld->lock);

	return 0;
}

static void g_ldisc_close(struct tty_struct *tty)
{
	struct gldisc *gld = tty->disc_data;

	pr_vdebug("%s\n", __func__);

	spin_lock_irq(&gld->lock);

	if (gld->connected && gld->disconnect)
		gld->disconnect(gld);

	tty->disc_data = NULL;
	gld->tty = NULL;
	gld->opened = false;

	spin_unlock_irq(&gld->lock);
}

static int g_ldisc_hangup(struct tty_struct *tty)
{
	pr_vdebug("%s\n", __func__);
	return 0;
}

static ssize_t g_ldisc_read(struct tty_struct *tty, struct file *file,
				unsigned char __user *buf, size_t count)
{
	return -EAGAIN;
}

static ssize_t g_ldisc_write(struct tty_struct *tty, struct file *file,
				const unsigned char *buf, size_t count)
{
	return -EAGAIN;
}

static int g_ldisc_ioctl(struct tty_struct *tty, struct file *file,
				unsigned int cmd, unsigned long arg)
{
	return 0;
}

static unsigned int g_ldisc_poll(struct tty_struct *tty, struct file *file,
							poll_table *wait)
{
	return 0;
}


static void g_ldisc_receive(struct tty_struct *tty, const unsigned char *data,
						char *cflags, int count)
{
	struct gldisc *gld = tty->disc_data;
	struct usb_ep *in = gld->in;
	int status = 0;
	int len;
	int maxpacket = in->maxpacket;
	struct usb_request *req;

	pr_vdebug("%s: receiving %d bytes\n", __func__, count);

	if (!gld->connected)
		return;

	while (count > 0) {
		len = min(count, maxpacket);

		req = gld_alloc_req(in, len, GFP_KERNEL);
		if (!req) {
			pr_err("%s: cannot allocate request", __func__);
			break;
		}

		memcpy(req->buf, data, len);
		req->zero = 0;
		req->complete = gld_write_complete;

		status = usb_ep_queue(in, req, GFP_KERNEL);
		if (status) {
			pr_debug("%s: ep queue %s err %d\n",
				__func__, in->name, status);
			gld_free_req(in, req);
			break;
		}

		data += len;
		count -= len;
	}
}

static void g_ldisc_wakeup(struct tty_struct *tty)
{
	pr_vdebug("%s\n", __func__);
}

static struct tty_ldisc_ops g_ldisc = {
	.owner  = THIS_MODULE,
	.magic	= TTY_LDISC_MAGIC,
	.name	= "n_acm",
	.open	= g_ldisc_open,
	.close	= g_ldisc_close,
	.hangup	= g_ldisc_hangup,
	.read	= g_ldisc_read,
	.write	= g_ldisc_write,
	.ioctl	= g_ldisc_ioctl,
	.poll	= g_ldisc_poll,
	.receive_buf = g_ldisc_receive,
	.write_wakeup = g_ldisc_wakeup,
};

int gldisc_register(void)
{
	int i;

	pr_vdebug("%s\n", __func__);

	for (i = 0; i < NUM_DISCS; ++i) {
		INIT_LIST_HEAD(&disc_list[i].read_pool);
		spin_lock_init(&disc_list[i].lock);
	}

	if (tty_register_ldisc(N_USBACM, &g_ldisc) < 0) {
		pr_err("%s: unable to register line discipline\n", __func__);
		return -EINVAL;
	}

	return 0;
}
