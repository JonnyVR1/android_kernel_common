/* drivers/misc/iface_stat.c
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

#include <linux/err.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/rtnetlink.h>
#include <linux/iface_stat.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>

#include <net/protocol.h>

static LIST_HEAD(iface_list);
static DEFINE_SPINLOCK(iface_list_lock);
static struct proc_dir_entry *iface_stat_procdir;

struct uid_stat {
	struct list_head u_link;
	uid_t uid;
	unsigned long tx_bytes_tcp;
	unsigned long rx_bytes_tcp;
	unsigned long tx_bytes_udp;
	unsigned long rx_bytes_udp;
	unsigned long tx_packets_tcp;
	unsigned long rx_packets_tcp;
	unsigned long tx_packets_udp;
	unsigned long rx_packets_udp;
};

struct iface_stat {
	struct list_head if_link;
	char *iface_name;
	unsigned long tx_bytes;
	unsigned long rx_bytes;
	unsigned long tx_packets;
	unsigned long rx_packets;
	bool active;
	struct proc_dir_entry *proc_ptr;
	struct list_head uid_list;
	spinlock_t uid_list_lock;
};

enum tx_rx {
	TX,
	RX
};

enum tcp_udp {
	TCP,
	UDP
};

/*
 * The work queue structure for if_uid_stat creation task, from workqueue.h
 */
struct create_stat_work_struct {
	struct work_struct create_work_struct;
	struct iface_stat *iface_entry;
	uid_t uid;
	enum tx_rx direction;
	enum tcp_udp transport;
	int bytes;
};

static int read_proc_entry(char *page, char **start, off_t off,
		int count, int *eof, void *data)
{
	int len;
	unsigned long value;
	char *p = page;
	unsigned long *iface_entry = (unsigned long *) data;
	if (!data)
		return 0;

	value = (unsigned long) (*iface_entry);
	p += sprintf(p, "%lu\n", value);
	len = (p - page) - off;
	*eof = (len <= count) ? 1 : 0;
	*start = page + off;
	return len;
}

static int read_proc_bool_entry(char *page, char **start, off_t off,
		int count, int *eof, void *data)
{
	int len;
	bool value;
	char *p = page;
	unsigned long *iface_entry = (unsigned long *) data;
	if (!data)
		return 0;

	value = (bool) (*iface_entry);
	p += sprintf(p, "%u\n", value ? 1 : 0);
	len = (p - page) - off;
	*eof = (len <= count) ? 1 : 0;
	*start = page + off;
	return len;
}

/* Find the entry for tracking the specified interface. */
static struct iface_stat *get_iface_stat(const char *ifname)
{
	unsigned long flags;
	struct iface_stat *iface_entry;
	if (!ifname)
		return NULL;

	spin_lock_irqsave(&iface_list_lock, flags);
	list_for_each_entry(iface_entry, &iface_list, if_link) {
		if (!strcmp(iface_entry->iface_name, ifname)) {
			spin_unlock_irqrestore(&iface_list_lock, flags);
			return iface_entry;
		}
	}
	spin_unlock_irqrestore(&iface_list_lock, flags);
	return NULL;
}

/*
 * Create a new entry for tracking the specified interface.
 * Do nothing if the entry already exists.
 * Called when an interface is configured with a valid IP address.
 */
void create_iface_stat(const struct in_device *in_dev)
{
	unsigned long flags;
	struct iface_stat *new_iface;
	struct proc_dir_entry *proc_entry;
	const struct net_device *dev;
	const char *ifname;
	struct iface_stat *entry;
	__be32 ipaddr = 0;
	struct in_ifaddr *ifa = NULL;

	ASSERT_RTNL(); /* No need for separate locking */

	dev = in_dev->dev;
	if (!dev) {
		pr_err("iface_stat: This should never happen.\n");
		return;
	}

	ifname = dev->name;
	for (ifa = in_dev->ifa_list; ifa; ifa = ifa->ifa_next)
		if (!strcmp(dev->name, ifa->ifa_label))
			break;

	if (ifa)
		ipaddr = ifa->ifa_local;
	else {
		pr_err("iface_stat: Interface not found.\n");
		return;
	}

	entry = get_iface_stat(dev->name);
	if (entry != NULL) {
		pr_debug("iface_stat: Already monitoring device %s\n", ifname);
		if (ipv4_is_loopback(ipaddr)) {
			entry->active = false;
			pr_debug("iface_stat: Disabling monitor for "
					"loopback device %s\n", ifname);
		} else {
			entry->active = true;
			pr_debug("iface_stat: Re-enabling monitor for "
					"device %s with ip %pI4\n",
					ifname, &ipaddr);
		}
		return;
	} else if (ipv4_is_loopback(ipaddr)) {
		pr_debug("iface_stat: Ignoring monitor for "
				"loopback device %s with ip %pI4\n",
				ifname, &ipaddr);
		return;
	}

	/* Create a new entry for tracking the specified interface. */
	new_iface = kmalloc(sizeof(struct iface_stat), GFP_KERNEL);
	if (new_iface == NULL)
		return;

	new_iface->iface_name = kmalloc((strlen(ifname)+1)*sizeof(char),
						GFP_KERNEL);
	if (new_iface->iface_name == NULL) {
		kfree(new_iface);
		return;
	}

	strcpy(new_iface->iface_name, ifname);
	/* Counters start at 0, so we can track 4GB of network traffic. */
	new_iface->tx_bytes = 0;
	new_iface->rx_bytes = 0;
	new_iface->rx_packets = 0;
	new_iface->tx_packets = 0;
	new_iface->active = true;

	/*
	 * We don't need uid_list_lock here as the new iface is not yet added
	 * to the iface_list and hence unavailable for any update operations.
	 */
	INIT_LIST_HEAD(&new_iface->uid_list);

	/* Append the newly created iface stat struct to the list. */
	spin_lock_irqsave(&iface_list_lock, flags);
	list_add_tail(&new_iface->if_link, &iface_list);
	spin_unlock_irqrestore(&iface_list_lock, flags);

	proc_entry = proc_mkdir(ifname, iface_stat_procdir);
	new_iface->proc_ptr = proc_entry;

	/* Keep reference to iface_stat so we know where to read stats from. */
	create_proc_read_entry("tx_bytes", S_IRUGO, proc_entry,
			read_proc_entry, &new_iface->tx_bytes);

	create_proc_read_entry("rx_bytes", S_IRUGO, proc_entry,
			read_proc_entry, &new_iface->rx_bytes);

	create_proc_read_entry("tx_packets", S_IRUGO, proc_entry,
			read_proc_entry, &new_iface->tx_packets);

	create_proc_read_entry("rx_packets", S_IRUGO, proc_entry,
			read_proc_entry, &new_iface->rx_packets);

	create_proc_read_entry("active", S_IRUGO, proc_entry,
			read_proc_bool_entry, &new_iface->active);

	pr_debug("iface_stat: Now monitoring device %s with ip %pI4\n",
			ifname, &ipaddr);
}

/*
 * Update stats for the specified interface. Do nothing if the entry
 * does not exist (when a device was never configured with an IP address).
 * Called when an device is being unregistered.
 */
void iface_stat_update(struct net_device *dev)
{
	const struct net_device_stats *stats = dev_get_stats(dev);
	struct iface_stat *entry;

	ASSERT_RTNL();

	entry = get_iface_stat(dev->name);
	if (entry == NULL) {
		pr_debug("iface_stat: dev %s monitor not found\n", dev->name);
		return;
	}

	if (entry->active) { /* FIXME: Support for more than 4GB */
		entry->tx_bytes += stats->tx_bytes;
		entry->tx_packets += stats->tx_packets;
		entry->rx_bytes += stats->rx_bytes;
		entry->rx_packets += stats->rx_packets;
		entry->active = false;
		pr_debug("iface_stat: Updating stats for "
			       "dev %s which went down\n", dev->name);
	} else
		pr_debug("iface_stat: Did not update stats for "
				"dev %s which went down\n", dev->name);
}

static void uid_stat_update(struct uid_stat *uid_entry, enum tx_rx direction,
				enum tcp_udp transport, int bytes)
{
	switch (transport) {
	case TCP:
		switch (direction) {
		case TX:
			uid_entry->tx_bytes_tcp += bytes;
			uid_entry->tx_packets_tcp += 1;
			break;
		case RX:
		default:
			uid_entry->rx_bytes_tcp += bytes;
			uid_entry->rx_packets_tcp += 1;
			break;
		}
		break;
	case UDP:
	default:
		switch (direction) {
		case TX:
			uid_entry->tx_bytes_udp += bytes;
			uid_entry->tx_packets_udp += 1;
			break;
		case RX:
		default:
			uid_entry->rx_bytes_udp += bytes;
			uid_entry->rx_packets_udp += 1;
			break;
		}
	}
}

/* Create a new entry for tracking the specified uid within the interface */
static void create_if_uid_stat(struct iface_stat *iface_entry, uid_t uid,
				enum tx_rx direction, enum tcp_udp transport,
				int bytes)
{
	struct proc_dir_entry *proc_entry;
	struct uid_stat *uid_entry;
	struct uid_stat *new_uid = NULL;
	char uid_s[32];
	unsigned long flags;

	spin_lock_irqsave(&iface_entry->uid_list_lock, flags);
	list_for_each_entry(uid_entry, &(iface_entry->uid_list), u_link) {
		if (uid_entry->uid == uid) { /* Uid for this device exists */
			uid_stat_update(uid_entry, direction, transport, bytes);
			spin_unlock_irqrestore(&iface_entry->uid_list_lock,
						flags);
			return;
		}
	}
	spin_unlock_irqrestore(&iface_entry->uid_list_lock, flags);

	/*
	 * Create a new stat entry for tracking this uid under this device.
	 * KMalloc might sleep, so check again later if entry exists.
	 */
	new_uid = kmalloc(sizeof(struct uid_stat), GFP_KERNEL);
	if (new_uid == NULL) {
		pr_err("iface_stat: KMalloc error");
		return;
	}

	new_uid->uid = uid;
	/*
	 * We can track 4GB of network traffic.
	 */
	new_uid->tx_bytes_tcp = 0;
	new_uid->rx_bytes_tcp = 0;
	new_uid->tx_packets_tcp = 0;
	new_uid->rx_packets_tcp = 0;
	new_uid->tx_bytes_udp = 0;
	new_uid->rx_bytes_udp = 0;
	new_uid->tx_packets_udp = 0;
	new_uid->rx_packets_udp = 0;

	uid_stat_update(new_uid, direction, transport, bytes);

	spin_lock_irqsave(&iface_entry->uid_list_lock, flags);
	/*
	 * Check again if the uid_entry has been created while we were
	 * allocating memory. This race condition is possible when a new uid
	 * tx/rx multiple packets before the first workqueue was able to
	 * create the uid_entry, in which case multiple workqueues might
	 * be trying to create the same uid_entry.
	 */
	list_for_each_entry(uid_entry, &(iface_entry->uid_list), u_link) {
		if (uid_entry->uid == uid) { /* Found uid for this device */
			uid_stat_update(uid_entry, direction, transport, bytes);
			spin_unlock_irqrestore(&iface_entry->uid_list_lock,
						flags);
			kfree(new_uid);
			return;
		}
	}
	/* Append the newly created uid stat struct to the list. */
	list_add_tail(&new_uid->u_link, &(iface_entry->uid_list));
	spin_unlock_irqrestore(&iface_entry->uid_list_lock, flags);

	sprintf(uid_s, "%d", uid);
	proc_entry = proc_mkdir(uid_s, iface_entry->proc_ptr);

	/* Keep reference to uid_stat so we know where to read stats from. */
	create_proc_read_entry("tx_bytes_tcp", S_IRUGO, proc_entry,
			read_proc_entry, &new_uid->tx_bytes_tcp);

	create_proc_read_entry("rx_bytes_tcp", S_IRUGO, proc_entry,
			read_proc_entry, &new_uid->rx_bytes_tcp);

	create_proc_read_entry("tx_packets_tcp", S_IRUGO, proc_entry,
			read_proc_entry, &new_uid->tx_packets_tcp);

	create_proc_read_entry("rx_packets_tcp", S_IRUGO, proc_entry,
			read_proc_entry, &new_uid->rx_packets_tcp);

	create_proc_read_entry("tx_bytes_udp", S_IRUGO, proc_entry,
			read_proc_entry, &new_uid->tx_bytes_udp);

	create_proc_read_entry("rx_bytes_udp", S_IRUGO, proc_entry,
			read_proc_entry, &new_uid->rx_bytes_udp);

	create_proc_read_entry("tx_packets_udp", S_IRUGO, proc_entry,
			read_proc_entry, &new_uid->tx_packets_udp);

	create_proc_read_entry("rx_packets_udp", S_IRUGO, proc_entry,
			read_proc_entry, &new_uid->rx_packets_udp);

	pr_debug("iface_stat: Adding new uid entry for %d under device %s\n",
			uid, iface_entry->iface_name);
}

/*
 * iface_worker_func() is run in process context.
 */
static void iface_worker_func(struct work_struct *work)
{
	struct create_stat_work_struct *create_work
		= container_of(work, struct create_stat_work_struct,
				create_work_struct);

	create_if_uid_stat(create_work->iface_entry, create_work->uid,
				create_work->direction, create_work->transport,
				create_work->bytes);
	kfree(work);
}

static int if_uid_stat_update(const char *ifname, uid_t uid, int bytes,
		enum tx_rx direction, enum tcp_udp transport)
{
	struct uid_stat *uid_entry;
	struct iface_stat *iface_entry;
	struct create_stat_work_struct *create_work;
	unsigned long flags;
	bool iface_entry_exists = false;
	bool uid_entry_exists = false;

	/* Find the entry for tracking the specified uid within the interface */
	if (ifname == NULL) {
		pr_err("iface_stat: Supplied with a NULL device name\n");
		return -1;
	}

	/* Iterate over interfaces */
	spin_lock_irqsave(&iface_list_lock, flags);
	list_for_each_entry(iface_entry, &iface_list, if_link) {
		if (!strcmp(ifname, iface_entry->iface_name)) {
			iface_entry_exists = true;
			break;
		}
	}
	spin_unlock_irqrestore(&iface_list_lock, flags);

	if (!iface_entry_exists) {
		pr_err("iface_stat: Update request for invalid interface\n");
		return -1;
	}

	/* Make sure (sanity check) that interface is active */
	if (iface_entry->active == false) {
		pr_err("iface_stat: Error in logic. "
			"Update request for inactive interface.\n");
		return -1;
	}

	/* Loop over uid list under this interface */
	spin_lock_irqsave(&iface_entry->uid_list_lock, flags);
	list_for_each_entry(uid_entry, &(iface_entry->uid_list), u_link) {
		if (uid_entry->uid == uid) {
			uid_entry_exists = true;
			break;
		}
	}
	spin_unlock_irqrestore(&iface_entry->uid_list_lock, flags);

	if (!uid_entry_exists) {
		/*
		 * Create a new stat entry in a workqueue outside the critical
		 * path of a network packet.
		 */
		create_work = kmalloc(sizeof(struct create_stat_work_struct),
					GFP_ATOMIC);
		if (create_work == NULL) {
			pr_err("iface_stat: Error allocating memory in "
				"kmalloc(GFP_ATOMIC)\n");
			return -1;
		}

		INIT_WORK(&create_work->create_work_struct, iface_worker_func);
		create_work->iface_entry = iface_entry;
		create_work->uid = uid;
		create_work->direction = direction;
		create_work->transport = transport;
		create_work->bytes = bytes;
		schedule_work(&create_work->create_work_struct);
		return -1;
	}

	spin_lock_irqsave(&iface_entry->uid_list_lock, flags);
	uid_stat_update(uid_entry, direction, transport, bytes);
	spin_unlock_irqrestore(&iface_entry->uid_list_lock, flags);

	return 0;
}

void if_uid_stat_update_tx(const char *devname, uid_t uid, int bytes, int prot)
{
	switch (prot & (MAX_INET_PROTOS - 1)) {
	case IPPROTO_TCP:
		if (0 != if_uid_stat_update(devname, uid, bytes, TX, TCP))
			pr_debug("iface_stat: "
					"Error updating tx_tcp stats for "
					"uid=%d.\n", uid);
		break;
	case IPPROTO_UDP:
	default:  /* All non TCP traffic gets counted under UDP stats */
		if (0 != if_uid_stat_update(devname, uid, bytes, TX, UDP))
			pr_debug("iface_stat: "
					"Error updating tx non_tcp stats for "
					"uid=%d.\n", uid);
		break;
	}

}

void if_uid_stat_update_rx(const char *devname, uid_t uid, int bytes, int prot)
{
	switch (prot & (MAX_INET_PROTOS - 1)) {
	case IPPROTO_TCP:
		if (0 != if_uid_stat_update(devname, uid, bytes, RX, TCP))
			pr_debug("iface_stat: "
					"Error updating rx_tcp stats for "
					"uid=%d.\n", uid);
		break;
	case IPPROTO_UDP:
	default:  /* All non TCP traffic gets counted under UDP stats */
		if (0 != if_uid_stat_update(devname, uid, bytes, RX, UDP))
			pr_debug("iface_stat: "
					"Error updating rx non_tcp stats for "
					"uid=%d.\n", uid);
		break;
	}
}

static int __init iface_stat_init(void)
{
	iface_stat_procdir = proc_mkdir("iface_stat", NULL);
	if (!iface_stat_procdir) {
		pr_err("iface_stat: failed to create proc entry\n");
		return -1;
	}

	return 0;
}

device_initcall(iface_stat_init);
