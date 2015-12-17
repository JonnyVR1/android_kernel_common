/*
 *  linux/lib/memcpy_chk.c
 *
 *  Copyright (C) ??????
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
