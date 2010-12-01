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
#ifndef __U_LDISC_H
#define __U_LDISC_H

#include <linux/usb/composite.h>
#include <linux/usb/cdc.h>

struct gldisc {
	struct tty_struct		*tty;

	struct usb_ep			*in;
	struct usb_ep			*out;
	struct usb_endpoint_descriptor	*in_desc;
	struct usb_endpoint_descriptor	*out_desc;

	spinlock_t			lock;
	struct list_head		read_pool;

	void				*f_data;
	bool				opened;		/* tty side */
	bool				connected;	/* usb side */

	/* notification callbacks */
	void (*connect)(struct gldisc *p);
	void (*disconnect)(struct gldisc *p);
};

/* register the line discipline */
int gldisc_register(void);
void gldisc_cleanup(void);

struct gldisc *gldisc_get(int port_num);

/* connect/disconnect is handled by individual functions */
int gldisc_connect(struct gldisc *gld);
void gldisc_disconnect(struct gldisc *gld);

/* functions are bound to configurations by a config or gadget driver */
int gldisc_bind_config(struct usb_configuration *c, u8 port_num);

#endif /* __U_LDISC_H */
