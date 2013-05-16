/*
 * Copyright (C) 2013 Google, Inc.
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

#undef TRACE_SYSTEM
#define TRACE_SYSTEM mmc

#if !defined(_TRACE_MMC_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_MMC_H

#include <linux/tracepoint.h>

/* Logging start of mmc block operation including cmd, address, size */
TRACE_EVENT(mmc_blk_op_start,
	TP_PROTO(int cmd, int addr, int size),
	TP_ARGS(cmd, addr, size),
	TP_STRUCT__entry(
		__field(int, cmd)
		__field(int, addr)
		__field(int, size)
	),
	TP_fast_assign(
		__entry->cmd = cmd;
		__entry->addr = addr;
		__entry->size = size;
	),
	TP_printk("%d,0x%x,0x%x", __entry->cmd, __entry->addr, __entry->size)
);

/* Logging end of mmc block operation including cmd, address, size */
TRACE_EVENT(mmc_blk_op_end,
	TP_PROTO(int cmd, int addr, int size),
	TP_ARGS(cmd, addr, size),
	TP_STRUCT__entry(
		__field(int, cmd)
		__field(int, addr)
		__field(int, size)
	),
	TP_fast_assign(
		__entry->cmd = cmd;
		__entry->addr = addr;
		__entry->size = size;
	),
	TP_printk("  %d,0x%x,0x%x", __entry->cmd, __entry->addr, __entry->size)
);

#endif /* _TRACE_MMC_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
