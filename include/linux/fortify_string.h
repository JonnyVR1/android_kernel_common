/*
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

#ifndef __FORTIFY_STRING_H
#define __FORTIFY_STRING_H

#if defined _FORTIFY_SOURCE && _FORTIFY_SOURCE > 0

#define __HAVE_ARCH_MEMCPY
static __inline __attribute__ ((__always_inline__)) __attribute__ ((__gnu_inline__)) __attribute__ ((__artificial__))
void* memcpy (void *__restrict __dest, const void *__restrict __src, size_t __len)

{
  return __builtin___memcpy_chk(__dest, __src, __len, __builtin_object_size (__dest, 0));
}
#endif

#endif
