/* drivers/misc/uid_stat.c
 *
 * Copyright (C) 2008 - 2009 Google, Inc.
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

#include <asm/atomic.h>

#include <linux/err.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/stat.h>
#include <linux/uid_stat.h>
#include <net/activity_stats.h>

static DEFINE_SPINLOCK(uid_lock);
static LIST_HEAD(uid_list);
static struct proc_dir_entry *parent;

struct uid_stat {
	struct list_head link;
	uid_t uid;
	atomic_t tcp_rcv;
	atomic_t tcp_snd;
	atomic_t tcp_rcv_pkt;
	atomic_t tcp_snd_pkt;
	atomic_t udp_rcv;
	atomic_t udp_snd;
	atomic_t udp_rcv_pkt;
	atomic_t udp_snd_pkt;
};

enum stat_name {
	TCP_RCV,
	TCP_SND,
	TCP_RCV_PKT,
	TCP_SND_PKT,
	UDP_RCV,
	UDP_SND,
	UDP_RCV_PKT,
	UDP_SND_PKT,
};

static int read_proc_entry(enum stat_name which,
				char *page, char **start, off_t off,
				int count, int *eof, void *data)
{
	int len;
	unsigned int value;
	char *p = page;
	struct uid_stat *uid_entry = (struct uid_stat *) data;
		if (!data)
		return 0;

	switch (which) {
	case TCP_RCV:
		value = (unsigned int) (atomic_read(&uid_entry->tcp_rcv) + INT_MIN);
		break;
	case TCP_SND:
		value = (unsigned int) (atomic_read(&uid_entry->tcp_snd) + INT_MIN);
		break;
	case TCP_RCV_PKT:
		value = (unsigned int) (atomic_read(&uid_entry->tcp_rcv_pkt) + INT_MIN);
		break;
	case TCP_SND_PKT:
		value = (unsigned int) (atomic_read(&uid_entry->tcp_snd_pkt) + INT_MIN);
		break;
	case UDP_RCV:
		value = (unsigned int) (atomic_read(&uid_entry->udp_rcv) + INT_MIN);
		break;
	case UDP_SND:
		value = (unsigned int) (atomic_read(&uid_entry->udp_snd) + INT_MIN);
		break;
	case UDP_RCV_PKT:
		value = (unsigned int) (atomic_read(&uid_entry->udp_rcv_pkt) + INT_MIN);
		break;
	case UDP_SND_PKT:
		value = (unsigned int) (atomic_read(&uid_entry->udp_snd_pkt) + INT_MIN);
		break;
	default:
		value = 0;
		break;
	}

	p += sprintf(p, "%u\n", value);
	len = (p - page) - off;
	*eof = (len <= count) ? 1 : 0;
	*start = page + off;
	return len;
}

static int tcp_snd_read_proc(char *page, char **start, off_t off,
				int count, int *eof, void *data)
{
	return read_proc_entry(TCP_SND, page, start, off, count, eof, data);
}


static int tcp_snd_pkt_read_proc(char *page, char **start, off_t off,
				int count, int *eof, void *data)
{
	return read_proc_entry(TCP_SND_PKT, page, start, off, count, eof, data);
}

static int tcp_rcv_read_proc(char *page, char **start, off_t off,
				int count, int *eof, void *data)
{
	return read_proc_entry(TCP_RCV, page, start, off, count, eof, data);
}

static int tcp_rcv_pkt_read_proc(char *page, char **start, off_t off,
				int count, int *eof, void *data)
{
	return read_proc_entry(TCP_RCV_PKT, page, start, off, count, eof, data);
}

static int udp_snd_read_proc(char *page, char **start, off_t off,
				int count, int *eof, void *data)
{
	return read_proc_entry(UDP_SND, page, start, off, count, eof, data);
}

static int udp_snd_pkt_read_proc(char *page, char **start, off_t off,
				int count, int *eof, void *data)
{
	return read_proc_entry(UDP_SND_PKT, page, start, off, count, eof, data);
}

static int udp_rcv_read_proc(char *page, char **start, off_t off,
				int count, int *eof, void *data)
{
	return read_proc_entry(UDP_RCV, page, start, off, count, eof, data);
}

static int udp_rcv_pkt_read_proc(char *page, char **start, off_t off,
				int count, int *eof, void *data)
{
	return read_proc_entry(UDP_RCV_PKT, page, start, off, count, eof, data);
}

/* Find or create a new entry for tracking the specified uid. */
static struct uid_stat *get_uid_stat(uid_t uid) {
	unsigned long flags;
	struct uid_stat *uid_entry;
	struct uid_stat *new_uid;
	struct proc_dir_entry *proc_entry;
	char uid_s[32];

	spin_lock_irqsave(&uid_lock, flags);
	list_for_each_entry(uid_entry, &uid_list, link) {
		if (uid_entry->uid == uid) {
			spin_unlock_irqrestore(&uid_lock, flags);
			return uid_entry;
		}
	}
	spin_unlock_irqrestore(&uid_lock, flags);

	/* Create a new entry for tracking the specified uid. */
	if ((new_uid = kmalloc(sizeof(struct uid_stat), GFP_KERNEL)) == NULL)
		return NULL;

	new_uid->uid = uid;
	/* Counters start at INT_MIN, so we can track 4GB of network traffic. */
	atomic_set(&new_uid->tcp_rcv, INT_MIN);
	atomic_set(&new_uid->tcp_snd, INT_MIN);
	atomic_set(&new_uid->tcp_snd_pkt, INT_MIN);
	atomic_set(&new_uid->tcp_rcv_pkt, INT_MIN);
	atomic_set(&new_uid->udp_rcv, INT_MIN);
	atomic_set(&new_uid->udp_snd, INT_MIN);
	atomic_set(&new_uid->udp_snd_pkt, INT_MIN);
	atomic_set(&new_uid->udp_rcv_pkt, INT_MIN);

	/* Append the newly created uid stat struct to the list. */
	spin_lock_irqsave(&uid_lock, flags);
	list_add_tail(&new_uid->link, &uid_list);
	spin_unlock_irqrestore(&uid_lock, flags);

	sprintf(uid_s, "%d", uid);
	proc_entry = proc_mkdir(uid_s, parent);

	/* Keep reference to uid_stat so we know what uid to read stats from. */
	create_proc_read_entry("tcp_snd", S_IRUGO, proc_entry, tcp_snd_read_proc,
		(void *) new_uid);

	create_proc_read_entry("tcp_rcv", S_IRUGO, proc_entry, tcp_rcv_read_proc,
		(void *) new_uid);

	create_proc_read_entry("tcp_snd_pkt", S_IRUGO, proc_entry, tcp_snd_pkt_read_proc,
		(void *) new_uid);

	create_proc_read_entry("tcp_rcv_pkt", S_IRUGO, proc_entry, tcp_rcv_pkt_read_proc,
		(void *) new_uid);

	create_proc_read_entry("udp_snd", S_IRUGO, proc_entry, udp_snd_read_proc,
		(void *) new_uid);

	create_proc_read_entry("udp_rcv", S_IRUGO, proc_entry, udp_rcv_read_proc,
		(void *) new_uid);

	create_proc_read_entry("udp_snd_pkt", S_IRUGO, proc_entry, udp_snd_pkt_read_proc,
		(void *) new_uid);

	create_proc_read_entry("udp_rcv_pkt", S_IRUGO, proc_entry, udp_rcv_pkt_read_proc,
		(void *) new_uid);

	return new_uid;
}

int uid_stat_tcp_snd(uid_t uid, int size) {
	struct uid_stat *entry;
	activity_stats_update();
	if ((entry = get_uid_stat(uid)) == NULL) {
			return -1;
	}
	atomic_add(size, &entry->tcp_snd);
        atomic_inc(&entry->tcp_snd_pkt);
	return 0;
}

int uid_stat_tcp_rcv(uid_t uid, int size) {
	struct uid_stat *entry;
	activity_stats_update();
	if ((entry = get_uid_stat(uid)) == NULL) {
			return -1;
	}
	atomic_add(size, &entry->tcp_rcv);
        atomic_inc(&entry->tcp_rcv_pkt);
	return 0;
}

int uid_stat_udp_snd(uid_t uid, int size) {
	struct uid_stat *entry;
	activity_stats_update();
	if ((entry = get_uid_stat(uid)) == NULL) {
			return -1;
	}
	atomic_add(size, &entry->udp_snd);
        atomic_inc(&entry->udp_snd_pkt);
	return 0;
}

int uid_stat_udp_rcv(uid_t uid, int size) {
	struct uid_stat *entry;
	activity_stats_update();
	if ((entry = get_uid_stat(uid)) == NULL) {
			return -1;
	}
	atomic_add(size, &entry->udp_rcv);
        atomic_inc(&entry->udp_rcv_pkt);
	return 0;
}

static int __init uid_stat_init(void)
{
	parent = proc_mkdir("uid_stat", NULL);
	if (!parent) {
		pr_err("uid_stat: failed to create proc entry\n");
		return -1;
	}
	return 0;
}

__initcall(uid_stat_init);
