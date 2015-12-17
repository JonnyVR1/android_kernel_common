/*
 *  linux/lib/memcpy_chk.c
 *
 *  Copyright (C) ??????
 */

#include <linux/types.h>

extern void *memcpy(void *, const void *, __kernel_size_t);
extern void panic(const char *fmt, ...);

void* __memcpy_chk (void * __dest, const void * __src, size_t __len, size_t chk)
{
    if (__len > chk) {
        panic("Out of bounds memcpy - panic");
    }

    return memcpy(__dest, __src, __len);
}
