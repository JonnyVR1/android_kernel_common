/*
 *  linux/lib/memcpy_chk.c
 *
 * Copyright (C) 2016 Google Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#undef _FORTIFY_SOURCE

#include <linux/types.h>
#include <linux/string.h>
#include <linux/kernel.h>

void* __memcpy_chk (void * __dest, const void * __src, __kernel_size_t __len, size_t chk)
{
    if (__len > chk) {
        panic("Out of bounds memcpy - panic");
    }

    return memcpy(__dest, __src, __len);
}
