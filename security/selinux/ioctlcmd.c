/*
 * Ioctl command table
 *
 * SELinux must keep a mapping of ioctl commands to labels/SIDs.  This
 * mapping is maintained as part of the normal policy but a fast cache is
 * needed to reduce the lookup overhead.
 *
 * Author: Jeff Vander Stoep <jeffv@google.com>
 *
 * This code is heavily based on the "netport" implementation by
 * Paul Moore <paul@paul-moore.com> which in turn is based
 * on the "netif" concept originally developed by
 * James Morris <jmorris@redhat.com>
 *   (see security/selinux/netif.c for more information)
 *
 */
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include "ioctlcmd.h"
#include "objsec.h"

#define SEL_IOCTLCMD_HASH_SIZE       256
#define SEL_IOCTLCMD_HASH_BKT_LIMIT   16

struct sel_ioctlcmd_bkt {
	int size;
	struct list_head list;
};

struct sel_ioctlcmd {
	struct ioctlcmd_security_struct psec;
	struct list_head list;
	struct rcu_head rcu;
};

static LIST_HEAD(sel_ioctlcmd_list);
static DEFINE_SPINLOCK(sel_ioctlcmd_lock);
static struct sel_ioctlcmd_bkt sel_ioctlcmd_hash[SEL_IOCTLCMD_HASH_SIZE];

/**
 * sel_ioctlcmd_hashfn - Hashing function for the ioctl command table
 * @cmd: command number
 *
 * Description:
 * This is the hashing function for the ioctl command table, it returns
 * the bucket number for the given command.
 *
 */
static unsigned int sel_ioctlcmd_hashfn(u32 cmd)
{
	return ((cmd >> 24) ^ (cmd >> 4) ^ cmd) &
			(SEL_IOCTLCMD_HASH_SIZE - 1);
}

/**
 * sel_ioctlcmd_find - Search for a ioctl command record
 * @cmd: ioctl command
 *
 * Description:
 * Search the ioctl command table and return the matching record.
 * If an entry can not be found in the table return NULL.
 *
 */
static struct sel_ioctlcmd *sel_ioctlcmd_find(unsigned int cmd)
{
	unsigned int idx;
	struct sel_ioctlcmd *ioccmd;
	idx = sel_ioctlcmd_hashfn(cmd);
	list_for_each_entry_rcu(ioccmd, &sel_ioctlcmd_hash[idx].list, list)
		if (ioccmd->psec.cmd == cmd)
			return ioccmd;

	return NULL;
}

/**
 * sel_ioctlcmd_insert - Insert a new ioctl command into the table
 * @cmd: the new ioctl command number
 *
 * Description:
 * Add a new ioctl command record to the ioctl command hash table.
 *
 */
static void sel_ioctlcmd_insert(struct sel_ioctlcmd *ioccmd)
{
	unsigned int idx;
	/* we need to impose a limit on the growth of the hash table so check
	 * this bucket to make sure it is within the specified bounds */
	idx = sel_ioctlcmd_hashfn(ioccmd->psec.cmd);
	list_add_rcu(&ioccmd->list, &sel_ioctlcmd_hash[idx].list);
	if (sel_ioctlcmd_hash[idx].size == SEL_IOCTLCMD_HASH_BKT_LIMIT) {
		struct sel_ioctlcmd *tail;
		tail = list_entry(
			rcu_dereference_protected(
				sel_ioctlcmd_hash[idx].list.prev,
				lockdep_is_held(&sel_ioctlcmd_lock)),
			struct sel_ioctlcmd, list);
		list_del_rcu(&tail->list);
		kfree_rcu(tail, rcu);
	} else
		sel_ioctlcmd_hash[idx].size++;
}

/**
 * sel_ioctlcmd_sid_slow - Lookup the SID of a ioctl command using the policy
 * @cmd: ioctl command
 * @sid: ioctl command SID
 *
 * Description:
 * This function determines the SID of a ioctl command by quering the security
 * policy.  The result is added to the ioctl command table to speedup future
 * queries.  Returns zero on success, negative values on failure.
 *
 */
static int sel_ioctlcmd_sid_slow(unsigned int cmd, u32 *sid)
{
	int ret = -ENOMEM;
	struct sel_ioctlcmd *ioccmd;
	struct sel_ioctlcmd *new = NULL;

	spin_lock_bh(&sel_ioctlcmd_lock);
	ioccmd = sel_ioctlcmd_find(cmd);
	if (ioccmd != NULL) {
		*sid = ioccmd->psec.sid;
		spin_unlock_bh(&sel_ioctlcmd_lock);
		return 0;
	}
	new = kzalloc(sizeof(*new), GFP_ATOMIC);
	if (new == NULL)
		goto out;
	ret = security_ioctlcmd_sid(cmd, sid);
	if (ret != 0)
		goto out;

	new->psec.cmd = cmd;
	new->psec.sid = *sid;
	sel_ioctlcmd_insert(new);
out:
	spin_unlock_bh(&sel_ioctlcmd_lock);
	if (unlikely(ret)) {
		printk(KERN_WARNING
		       "SELinux: failure in sel_ioctlcmd_sid_slow(),"
		       " unable to determine ioctl command label\n");
		kfree(new);
	}
	return ret;
}

/**
 * sel_ioctlcmd_sid - Lookup the SID of an ioctl command
 * @file: ioctl file
 * @cmd: command
 *
 * Description:
 * This function determines the SID of an ioctl command using the fastest method
 * possible.  First the ioctl table is queried, but if an entry can't be found
 * then the policy is queried and the result is added to the table to speedup
 * future queries.  Returns zero on success, negative values on failure.
 *
 */
int sel_ioctlcmd_sid(unsigned int cmd, u32 *sid)
{
	struct sel_ioctlcmd *ioccmd;
	rcu_read_lock();
	ioccmd = sel_ioctlcmd_find(cmd);
	if (ioccmd != NULL) {
		*sid = ioccmd->psec.sid;
		rcu_read_unlock();
		return 0;
	}
	rcu_read_unlock();

	return sel_ioctlcmd_sid_slow(cmd, sid);
}

/**
 * sel_ioctlcmd_flush - Flush the entire ioctl command table
 *
 * Description:
 * Remove all entries from the ioctl command table.
 *
 */
static void sel_ioctlcmd_flush(void)
{
	unsigned int idx;
	struct sel_ioctlcmd *ioccmd, *ioccmd_tmp;

	spin_lock_bh(&sel_ioctlcmd_lock);
	for (idx = 0; idx < SEL_IOCTLCMD_HASH_SIZE; idx++) {
		list_for_each_entry_safe(ioccmd, ioccmd_tmp,
					 &sel_ioctlcmd_hash[idx].list, list) {
			list_del_rcu(&ioccmd->list);
			kfree_rcu(ioccmd, rcu);
		}
		sel_ioctlcmd_hash[idx].size = 0;
	}
	spin_unlock_bh(&sel_ioctlcmd_lock);
}

static int sel_ioctlcmd_avc_callback(u32 event)
{
	if (event == AVC_CALLBACK_RESET)
		sel_ioctlcmd_flush();
	return 0;
}

static __init int sel_ioctlcmd_init(void)
{
	int iter;
	int ret;

	if (!selinux_enabled)
		return 0;

	for (iter = 0; iter < SEL_IOCTLCMD_HASH_SIZE; iter++) {
		INIT_LIST_HEAD(&sel_ioctlcmd_hash[iter].list);
		sel_ioctlcmd_hash[iter].size = 0;
	}

	ret = avc_add_callback(sel_ioctlcmd_avc_callback, AVC_CALLBACK_RESET);
	if (ret != 0)
		panic("avc_add_callback() failed, error %d\n", ret);

	return ret;
}

__initcall(sel_ioctlcmd_init);
