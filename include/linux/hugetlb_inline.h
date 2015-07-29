#ifndef _LINUX_HUGETLB_INLINE_H
#define _LINUX_HUGETLB_INLINE_H

#ifdef CONFIG_HUGETLB_PAGE

#include <linux/mm.h>

static inline int is_vm_hugetlb_page(struct vm_area_struct *vma)
{
	return !!((vma->vm_flags & (VM_HUGETLB | VM_MERGEABLE)) == VM_HUGETLB);
}

static inline int TestVmHugetlb(unsigned long vm_flags)
{
	return (vm_flags & (VM_HUGETLB | VM_MERGEABLE)) == VM_HUGETLB;
}

#else

static inline int is_vm_hugetlb_page(struct vm_area_struct *vma)
{
	return 0;
}

static inline int TestVmHugetlb(unsigned long vm_flags)
{
	return 0;
}
#endif

#endif
