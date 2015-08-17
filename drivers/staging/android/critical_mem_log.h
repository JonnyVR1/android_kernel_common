
/*
 *
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
 *
 */

#ifndef __CRITICAL_MEM_LOG_H__
#define __CRITICAL_MEM_LOG_H__


#define LOG_BUF_SIZE 16 * 1024 	/*maximum size of critical memory log buffer */
#define MAX_LOG_LEN 150		/*maximum length of a log that can be store at once */
#define PROC_ENTRY_NAME "critical_memlogs"


#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__
#define critical_mem_log(a, args...) critical_mem_log_f(a,##args)


/*this enum is for checking status of ping poing buffers */
enum buffer_staus {
	READ_BUFFER,
	WRITE_BUFFER
};

/* structure for storing and tracing critical memory logs  */
struct mem_buffer_t {
	char *buffer;
	int status;
	int data_size;
};

/* keeps track of read and write pointer for critical memory logs */
struct mem_log_t {
	struct	mem_buffer_t  *read_buf;
	struct 	mem_buffer_t  *write_buf;
};

/* stucrue for calculating memory related stats */
struct critical_memory_stat{
	unsigned long 	cached_memory;
	unsigned long 	free_memory;
	unsigned long 	shmem_usage;
	unsigned long	buffer_usage;
	unsigned long	slab_usage;
	unsigned long 	page_tables_usage;
	unsigned long	kernel_stack_usage;
	unsigned long 	total_pss;
	unsigned long  	total_usage;
	unsigned long	lost_ram;
	unsigned long 	total_memory;
};

/* structure for processes memory stats */
struct user_process_mem_info {
        unsigned long vss;
        unsigned long rss;
        unsigned long rss_mapped;
        unsigned long pss;
        unsigned long uss;
        int task_pid;
};

extern int  record_critical_memstats(void);
extern int critical_mem_log_f(const char *format, ...);
extern int   get_userprocess_meminfo(struct task_struct *p, struct user_process_mem_info *upmeminfo);
#endif

