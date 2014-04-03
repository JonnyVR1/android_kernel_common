/*
 * Copyright (C) 2014 Google, Inc.
 * Author: Colin Cross <ccross@android.com>
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

#include "fiq_debugger_priv.h"

void dump_pc(struct fiq_debugger_state *state, unsigned *regs)
{
}

void dump_regs(struct fiq_debugger_state *state, unsigned *regs)
{
}


void dump_allregs(struct fiq_debugger_state *state, unsigned *regs)
{
}

void dump_stacktrace(struct fiq_debugger_state *state,
		struct pt_regs * const regs, unsigned int depth, void *ssp)
{
}
