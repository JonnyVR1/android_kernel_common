/*
 * otg-wakelock.c
 *
 * Copyright (C) 2011 Google, Inc.
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

#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/notifier.h>
#include <linux/wakelock.h>
#include <linux/spinlock.h>
#include <linux/usb/otg.h>

static struct otg_transceiver *otgwl_xceiv;
static struct notifier_block otgwl_nb;

/*
 * otgwl_spinlock is held while the VBUS lock is grabbed or dropped and the locked
 * field is updated to match, and also holds off OTG notifiers while the initial
 * OTG state is determined at boot time.
 */

static DEFINE_SPINLOCK(otgwl_spinlock);

/*
 * Only one lock, but since these 3 fields are associated with each other...
 */

struct otgwl_lock {
	char name[40];
	struct wake_lock wakelock;
	bool locked;
};

/*
 * VBUS present lock.
 */

static struct otgwl_lock vbus_lock;

static void otgwl_grab(struct otgwl_lock *lock)
{
	if (!lock->locked) {
		wake_lock(&lock->wakelock);
		lock->locked = true;
	}
}

static void otgwl_drop(struct otgwl_lock *lock)
{
	if (lock->locked) {
		wake_unlock(&lock->wakelock);
		lock->locked = false;
	}
}

static int otgwl_otg_notifications(struct notifier_block *nb,
				   unsigned long event, void *unused)
{
	unsigned long irqflags;

	spin_lock_irqsave(&otgwl_spinlock, irqflags);

	switch (event) {
	case USB_EVENT_VBUS:
	case USB_EVENT_ENUMERATED:
		otgwl_grab(&vbus_lock);
		break;

	case USB_EVENT_NONE:
	case USB_EVENT_ID:
	case USB_EVENT_CHARGER:
		otgwl_drop(&vbus_lock);
		break;

	default:
		break;
	}

	spin_unlock_irqrestore(&otgwl_spinlock, irqflags);
	return NOTIFY_OK;
}

static int __init otg_wakelock_init(void)
{
	unsigned long irqflags;

	otgwl_xceiv = otg_get_transceiver();

	if (!otgwl_xceiv) {
		pr_err("%s: No OTG transceiver found\n", __func__);
		return -ENODEV;
	}

	snprintf(vbus_lock.name, sizeof(vbus_lock.name), "vbus-%s",
		 dev_name(otgwl_xceiv->dev));
	wake_lock_init(&vbus_lock.wakelock, WAKE_LOCK_SUSPEND, vbus_lock.name);

	otgwl_nb.notifier_call = otgwl_otg_notifications;

	spin_lock_irqsave(&otgwl_spinlock, irqflags);

	if (otg_register_notifier(otgwl_xceiv, &otgwl_nb))
		pr_err("%s: otg_register_notifier on transceiver %s failed\n", __func__,
		       dev_name(otgwl_xceiv->dev));

	if ((otgwl_xceiv->last_event == USB_EVENT_VBUS) ||
	    (otgwl_xceiv->last_event == USB_EVENT_ENUMERATED))
		otgwl_grab(&vbus_lock);
	else
		otgwl_drop(&vbus_lock);

	spin_unlock_irqrestore(&otgwl_spinlock, irqflags);
	return 0;
}

late_initcall(otg_wakelock_init);
