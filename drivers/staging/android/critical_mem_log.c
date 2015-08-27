/**
 * The critical memory logging utiltiy lets user dumps memory statistics just
 * before lowmemorykiller is triggered,so using this utility user can know
 * system memory snapshot just before lmk is triggered. User can dump memory stats
 * using proc command cat /proc/critical_memlogs.
 * This utility shows memory information of all processes and kernel memory
 * usage and lost ram  if any.

 * Copyright (C) 2015 Spreadtrum India.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <linux/uaccess.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/poll.h>
#include <linux/wait.h>
#include<linux/sched.h>
#include <linux/slab.h>
#include<linux/percpu-defs.h>
#include <linux/moduleparam.h>
#include <asm/current.h>
#include <linux/pid.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/vmstat.h>
#include <linux/blkdev.h>
#include "critical_mem_log.h"


#define pr_format(fmt) "critical_mem_log: " fmt
#define pr_error(fmt, ...) printk(KERN_ERR pr_format(fmt), ##__VA_ARGS__)


static void add_timestamp(void);
static DEFINE_SPINLOCK(critical_memlog_lock);
DECLARE_WAIT_QUEUE_HEAD(critical_memlog_wait);


 /*read and write buffer pointers */
struct mem_log_t *s_mem_log = NULL;

/*two buffers for storing and reading stats in ping pong manner */
struct mem_buffer_t *s_mem_buff1 = NULL;
struct mem_buffer_t *s_mem_buff2 = NULL;

enum status{
	SUCCESS,
	FAILURE
};
/*for storing time stamp when lowmemorykiller is triggerd */
static void  add_timestamp()
{
	struct timeval t;
	struct tm tm_v;
	do_gettimeofday(&t);
	time_to_tm(t.tv_sec, 0, &tm_v);
	critical_mem_log("%02d-%02d  %02d:%02d:%02d:%03d\n\n",tm_v.tm_mon + 1, tm_v.tm_mday,tm_v.tm_hour, tm_v.tm_min, tm_v.tm_sec, t.tv_usec);
}

void calculate_critical_memory_stats(struct critical_memory_stat *mem_stats)
{

	/*calulate memory stats */
	mem_stats->total_memory = (totalram_pages * PAGE_SIZE);
	mem_stats->free_memory 	= (global_page_state(NR_FREE_PAGES) * PAGE_SIZE);
	mem_stats->shmem_usage 	= (global_page_state(NR_SHMEM) * PAGE_SIZE);
	mem_stats->slab_usage 	= ((global_page_state(NR_SLAB_RECLAIMABLE) + global_page_state(NR_SLAB_UNRECLAIMABLE)) * PAGE_SIZE);
	mem_stats->buffer_usage	= (nr_blockdev_pages() * PAGE_SIZE);

	mem_stats->page_tables_usage 	=  	(global_page_state(NR_PAGETABLE) * PAGE_SIZE);
	mem_stats->kernel_stack_usage	=	(global_page_state(NR_KERNEL_STACK) * PAGE_SIZE);
	mem_stats->cached_memory	=       (global_page_state(NR_FILE_PAGES) * PAGE_SIZE) - (total_swapcache_pages() * PAGE_SIZE)
											- mem_stats->buffer_usage;

	/*calcuate totoal memory usage */
	mem_stats->total_usage = 	(mem_stats->shmem_usage + mem_stats->slab_usage+  mem_stats->buffer_usage + mem_stats->cached_memory
					      +	mem_stats->total_pss + mem_stats->page_tables_usage +  mem_stats->kernel_stack_usage);

	/*calculate lost ram if any */
	if(( mem_stats->total_memory > (mem_stats->total_usage + mem_stats->free_memory)))
		mem_stats->lost_ram =  mem_stats->total_memory -(mem_stats->total_usage + mem_stats->free_memory);

}
/* calculates and stores memory stats in write buffer to be read by  /proc/critical_memlogs */
int record_critical_memstats()
{
	struct task_struct *p = NULL;
	struct user_process_mem_info upmeminfo;
	struct critical_memory_stat mem_stats = {};

	if(s_mem_log->write_buf->data_size != 0)
			return FAILURE;

	critical_mem_log("\nLow memory killer starts killing processes at: ");
	add_timestamp();
	critical_mem_log(" \n %5s %11s %9s %11s %9s %9s %s\n",
			"pid", "vss", "rss", "rss_mapped", "pss", "uss", "name");

	critical_mem_log("-----------------------------------------------------------------\n");
	for_each_process(p) {
		memset(&upmeminfo, 0, sizeof(upmeminfo));
		if (get_userprocess_meminfo(p, &upmeminfo))
			continue;
		mem_stats.total_pss += upmeminfo.pss;

		critical_mem_log("%5d %10luK %8luK %10luK %8luK %8luK %s\n",
				upmeminfo.task_pid,
				upmeminfo.vss >> 10,
				upmeminfo.rss >> 10,
				upmeminfo.rss_mapped >> 10,
				upmeminfo.pss >> 10,
				upmeminfo.uss >> 10,
				p->comm);
	}

	/*calculate memory status */

	calculate_critical_memory_stats(&mem_stats);

	critical_mem_log("-----------------------------------------------------------------\n\n");
	critical_mem_log(" Total pss:           %20luK \n",mem_stats.total_pss >>10);
	critical_mem_log(" Slab usage:          %20luK \n",mem_stats.slab_usage >>10);
	critical_mem_log(" Shmem usage:         %20luK \n",mem_stats.shmem_usage >>10);
	critical_mem_log(" Buffer usage:        %20luK \n",mem_stats.buffer_usage >>10);
	critical_mem_log(" Cached memory:       %20luK \n",mem_stats.cached_memory >>10);
	critical_mem_log(" Page tables usage:   %20luK \n",mem_stats.page_tables_usage >>10);
	critical_mem_log(" Kernel statck usage: %20luK \n",mem_stats.kernel_stack_usage >>10);
	critical_mem_log("-----------------------------------------------------------------\n");
	critical_mem_log("Total memory usage (total pss + shmem + slab + buffer\n"
			"	+ cached +page tables + kernel statck): %luK \n\n",mem_stats.total_usage >>10);

	critical_mem_log("Total Memory 		%luK\n",mem_stats.total_memory >> 10);
	critical_mem_log("Free memory 		%luK\n\n",mem_stats.free_memory >> 10);
	critical_mem_log("Lost ram (total memory - (total usage + free_memory)): %luK\n",mem_stats.lost_ram >> 10);


	spin_lock_irq(&critical_memlog_lock);

	if(s_mem_log->read_buf->data_size == 0){

		if(s_mem_log->write_buf == s_mem_buff1)
		{
			s_mem_log->read_buf = s_mem_buff1;
			s_mem_buff1->status = READ_BUFFER;
			s_mem_log->write_buf = s_mem_buff2;
			s_mem_buff2->status = WRITE_BUFFER;
			s_mem_buff2->data_size = 0;
		}else{
			s_mem_log->read_buf = s_mem_buff2;
			s_mem_buff2->status = READ_BUFFER;
			s_mem_log->write_buf = s_mem_buff1;
			s_mem_buff1->status = WRITE_BUFFER;
			s_mem_buff1->data_size = 0;
		}
	}
	spin_unlock_irq(&critical_memlog_lock);
	wake_up_interruptible(&critical_memlog_wait);
	return SUCCESS;
}

static int critical_mem_log_init(void)
{
	/*allocate memory for structurs used in critical mempry logging */
	s_mem_log = (struct mem_log_t *)kzalloc(sizeof(struct mem_log_t),GFP_KERNEL );
	if(s_mem_log == NULL) {
		pr_error("kzalloc failed for s_mem_log !!!\n");
		return -ENOMEM;
	}

	s_mem_buff1 = (struct mem_buffer_t *)kzalloc(sizeof(struct mem_buffer_t),GFP_KERNEL );
	if(s_mem_buff1 == NULL) {
		pr_error("kzalloc failed for s_mem_log_info !!!\n");
		return -ENOMEM;
	}


	s_mem_buff2 = (struct mem_buffer_t *)kzalloc(sizeof(struct mem_buffer_t),GFP_KERNEL );
	if(s_mem_buff2 == NULL) {
		pr_error("kzalloc failed for s_mem_buff2 !!!\n");
		return -ENOMEM;
	}

	/*allocate memory to buffers those stores critial memory logs */
	s_mem_buff1->buffer = (char *)vzalloc(LOG_BUF_SIZE);
	if(s_mem_buff1->buffer == NULL){
		pr_error("vzalloc failed for s_mem_buff1->buffer !!!\n");
		kfree(s_mem_buff1);
		s_mem_buff1 = NULL;
		return -ENOMEM;
	}

	s_mem_buff2->buffer = (char *)vzalloc(LOG_BUF_SIZE);
	if(s_mem_buff2->buffer == NULL){
		pr_error("vzalloc failed for s_mem_buff2->buffer !!!\n");
		kfree(s_mem_buff2);
		s_mem_buff2 = NULL;
		return -ENOMEM;
	}


	/* Initialize read and write pointer for reading and writing logs in ping pong manner */
	s_mem_buff1->data_size = 0;
	s_mem_buff1->status = WRITE_BUFFER;

	s_mem_buff2->data_size = 0;
	s_mem_buff2->status = READ_BUFFER;

	/* Initially read and write pointers points to buffer1 and bufer2 respectively*/
	s_mem_log->write_buf = s_mem_buff1;
	s_mem_log->read_buf = s_mem_buff2;

	return SUCCESS;
}

static void critical_memlog_free(void )
{
	if(s_mem_log != NULL)
		kfree(s_mem_log);

	if(s_mem_buff1 != NULL){
		vfree(s_mem_buff1->buffer);
		kfree(s_mem_buff1);
	}

	if(s_mem_buff2 != NULL){
		vfree(s_mem_buff2->buffer);
		kfree(s_mem_buff2);
	}
	return;
}


static int critical_memlog_write(char * buff, int size)
{
	struct mem_buffer_t *writebuf = s_mem_log->write_buf;

	if((writebuf->status != WRITE_BUFFER))
		return FAILURE;

	if(writebuf->data_size + size <= LOG_BUF_SIZE)	{
		memcpy(writebuf->buffer + writebuf->data_size,buff ,size);
		writebuf->data_size += size;
	}else{
		pr_error("critical memory logs overflow !!! \n");
		return FAILURE;
	}
	return SUCCESS;
}

int critical_mem_log_f(const char *format, ...)
{
	va_list arg;
	int log_len = 0;

	char * temp_buff = (char *)kzalloc(MAX_LOG_LEN,GFP_KERNEL);
	if (temp_buff == NULL)	{
		pr_error("Memory allocation failed for temp_buff in mem_log!!! \n");
		return 	FAILURE;
	}

	va_start (arg, format);
	log_len = vsnprintf(temp_buff, MAX_LOG_LEN , format, arg);
	if(log_len >= MAX_LOG_LEN)
		log_len = MAX_LOG_LEN;
	critical_memlog_write(temp_buff,log_len);
	va_end (arg);
	kfree(temp_buff);
	return SUCCESS;
}

static ssize_t read_critical_mem_log(struct file *file,char __user *buf, size_t size, loff_t *offset)
{
	int rcnt = 0;
	int ret = 0;
	int cpy_cnt = 0;
	static int offset_idx = 0;
	struct mem_buffer_t *readbuf = NULL;

	/*verify user buffer */
	if (!access_ok(VERIFY_WRITE, buf, size)) {
			ret = -EFAULT;
			return ret;
		}

	ret = wait_event_interruptible(critical_memlog_wait,
					(s_mem_log->read_buf->data_size > 0));
	if (ret)
		return ret;

	readbuf = s_mem_log->read_buf;
	rcnt = readbuf->data_size;

	if(rcnt < size){
		cpy_cnt = copy_to_user(buf,readbuf->buffer+offset_idx,rcnt);
		readbuf->data_size -= rcnt;
		offset_idx += rcnt;
                ret += rcnt;
	}else{
		cpy_cnt = copy_to_user(buf,readbuf->buffer+offset_idx,size);
                readbuf->data_size -= size ;
		offset_idx += size;
                ret += size;
		}

	if(readbuf->data_size == 0){
		offset_idx = 0;
		memset(readbuf->buffer,0,LOG_BUF_SIZE);
	}

	return ret;
}

static int open_critical_mem_log(struct inode *inode, struct file *file)
{
	if((s_mem_buff1->status == READ_BUFFER) || (s_mem_buff2->status == READ_BUFFER))
		return SUCCESS;
	else
		return -EACCES;
}

static unsigned int critical_mem_poll(struct file *filp, poll_table *wait)
{
	poll_wait(filp, &critical_memlog_wait,  wait);
	if (s_mem_log->read_buf->data_size > 0 ){
		return POLLIN | POLLRDNORM;
	}
	return SUCCESS;
}
static int critical_mem_log_release(struct inode * inode, struct file * file)
{
	if(s_mem_buff1 == NULL || s_mem_buff2 == NULL)
		return single_release(inode,file);
	else
		return SUCCESS;
}

static const struct file_operations proc_file_fops = {
	.read  	= read_critical_mem_log,
	.open  	= open_critical_mem_log,
	.poll  	= critical_mem_poll,
	.llseek	= generic_file_llseek,
	.release = critical_mem_log_release,
};
static int create_proc_entry(void)
{
	struct proc_dir_entry *proc_file_entry;
	proc_file_entry = proc_create(PROC_ENTRY_NAME,S_IRUSR, NULL, &proc_file_fops);
	if(proc_file_entry == NULL)
	{
		pr_error("create_proc_entry failed!!!\n");
		return -ENOMEM;
	}
	return SUCCESS ;
}
static int  __init critical_mem_log_module_init(void)
{
	if(critical_mem_log_init() || create_proc_entry())
	{
		pr_error("critical_mem_log_init failed!!!\n");
		return -FAILURE ;
	}

	return SUCCESS;
}
static void __exit critical_mem_log_module_exit(void)
{
	critical_memlog_free();
	remove_proc_entry(PROC_ENTRY_NAME, NULL);
	return ;
}

module_init(critical_mem_log_module_init);
module_exit(critical_mem_log_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("SPRD IND KERNEL MEM");
MODULE_DESCRIPTION("Stores critical memory statistics");
