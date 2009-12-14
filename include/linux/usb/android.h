/*
 * Platform data for Android USB
 *
 * Copyright (C) 2008 Google, Inc.
 * Author: Mike Lockwood <lockwood@android.com>
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
#ifndef	__LINUX_USB_ANDROID_H
#define	__LINUX_USB_ANDROID_H

#include <linux/usb/composite.h>

struct android_usb_product {
	/* Default product ID. */
	__u16 product_id;

	/* List of function names associated with this product.
	 * This is used to compute the USB product ID dynamically
	 * based on which functions are enabled.
	 */
	int num_functions;
	char **functions;
};

typedef int (usb_function_adder)(struct usb_composite_dev *cdev,
		struct usb_configuration *c);

struct android_usb_platform_data {
	/* USB device descriptor fields */
	__u16 vendor_id;

	/* Default product ID. */
	__u16 product_id;

	__u16 version;

	char *product_name;
	char *manufacturer_name;
	char *serial_number;

	/* List of function add callbacks for all 
	 * supported USB functions
	 */
	int num_functions;
	usb_function_adder **function_adders;

	/* List of available USB products.
	 * This is used to compute the USB product ID dynamically
	 * based on which functions are enabled.
	 * if num_products is zero or no match can be found,
	 * we use the default product ID
	 */
	int num_products;
	struct android_usb_product *products;
};

/* Platform data for "usb_mass_storage" driver. */
struct usb_mass_storage_platform_data {
	/* Contains values for the SC_INQUIRY SCSI command. */
	char *vendor;
	char *product;
	int release;

	/* number of LUNS */
	int nluns;
};

extern void android_usb_set_connected(int on);

extern void android_enable_function(struct usb_function *f, int enable);

/* Function adder callbacks */
extern int acm_function_add(struct usb_composite_dev *cdev,
	struct usb_configuration *c);
extern int adb_function_add(struct usb_composite_dev *cdev,
	struct usb_configuration *c);
extern int mass_storage_function_add(struct usb_composite_dev *cdev,
	struct usb_configuration *c);


#endif	/* __LINUX_USB_ANDROID_H */
