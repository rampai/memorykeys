/*
 * PowerPC Memory Protection Keys management
 * Copyright (c) 2017, IBM Corporation.
 * Author: Ram Pai <linuxram@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _ASM_POWERPC_KEYS_H
#define _ASM_POWERPC_KEYS_H

#include <linux/jump_label.h>

DECLARE_STATIC_KEY_TRUE(pkey_disabled);
extern int pkeys_total; /* total pkeys as per device tree */
extern u32 initial_allocation_mask; /* bits set for reserved keys */

/*
 * powerpc needs VM_PKEY_BIT* bit to enable pkey system.
 * Without them, at least compilation needs to succeed.
 */
#ifndef VM_PKEY_BIT0
#define VM_PKEY_SHIFT 0
#define VM_PKEY_BIT0 0
#define VM_PKEY_BIT1 0
#define VM_PKEY_BIT2 0
#define VM_PKEY_BIT3 0
#endif

/*
 * powerpc needs an additional vma bit to support 32 keys. Till the additional
 * vma bit lands in include/linux/mm.h we can only support 16 keys.
 */
#ifndef VM_PKEY_BIT4
#define VM_PKEY_BIT4 0
#endif

#define ARCH_VM_PKEY_FLAGS (VM_PKEY_BIT0 | VM_PKEY_BIT1 | VM_PKEY_BIT2 | \
			    VM_PKEY_BIT3 | VM_PKEY_BIT4)

#define arch_max_pkey() pkeys_total

#define pkey_alloc_mask(pkey) (0x1 << pkey)

#define mm_pkey_allocation_map(mm) (mm->context.pkey_allocation_map)

#define __mm_pkey_allocated(mm, pkey) {	\
	mm_pkey_allocation_map(mm) |= pkey_alloc_mask(pkey); \
}

#define __mm_pkey_free(mm, pkey) {	\
	mm_pkey_allocation_map(mm) &= ~pkey_alloc_mask(pkey);	\
}

#define __mm_pkey_is_allocated(mm, pkey)	\
	(mm_pkey_allocation_map(mm) & pkey_alloc_mask(pkey))

#define __mm_pkey_is_reserved(pkey) (initial_allocation_mask & \
				       pkey_alloc_mask(pkey))

static inline bool mm_pkey_is_allocated(struct mm_struct *mm, int pkey)
{
	/* A reserved key is never considered as 'explicitly allocated' */
	return ((pkey < arch_max_pkey()) &&
		!__mm_pkey_is_reserved(pkey) &&
		__mm_pkey_is_allocated(mm, pkey));
}

extern void __arch_activate_pkey(int pkey);
extern void __arch_deactivate_pkey(int pkey);
/*
 * Returns a positive, 5-bit key on success, or -1 on failure.
 * Relies on the mmap_sem to protect against concurrency in mm_pkey_alloc() and
 * mm_pkey_free().
 */
static inline int mm_pkey_alloc(struct mm_struct *mm)
{
	/*
	 * Note: this is the one and only place we make sure that the pkey is
	 * valid as far as the hardware is concerned. The rest of the kernel
	 * trusts that only good, valid pkeys come out of here.
	 */
	u32 all_pkeys_mask = (u32)(~(0x0));
	int ret;

	if (static_branch_likely(&pkey_disabled))
		return -1;

	/*
	 * Are we out of pkeys? We must handle this specially because ffz()
	 * behavior is undefined if there are no zeros.
	 */
	if (mm_pkey_allocation_map(mm) == all_pkeys_mask)
		return -1;

	ret = ffz((u32)mm_pkey_allocation_map(mm));
	__mm_pkey_allocated(mm, ret);

	/*
	 * Enable the key in the hardware
	 */
	if (ret > 0)
		__arch_activate_pkey(ret);
	return ret;
}

static inline int mm_pkey_free(struct mm_struct *mm, int pkey)
{
	if (static_branch_likely(&pkey_disabled))
		return -1;

	if (!mm_pkey_is_allocated(mm, pkey))
		return -EINVAL;

	/*
	 * Disable the key in the hardware
	 */
	__arch_deactivate_pkey(pkey);
	__mm_pkey_free(mm, pkey);

	return 0;
}

/*
 * Try to dedicate one of the protection keys to be used as an
 * execute-only protection key.
 */
static inline int execute_only_pkey(struct mm_struct *mm)
{
	return 0;
}

static inline int arch_override_mprotect_pkey(struct vm_area_struct *vma,
					      int prot, int pkey)
{
	return 0;
}

extern int __arch_set_user_pkey_access(struct task_struct *tsk, int pkey,
				       unsigned long init_val);
static inline int arch_set_user_pkey_access(struct task_struct *tsk, int pkey,
					    unsigned long init_val)
{
	if (static_branch_likely(&pkey_disabled))
		return -EINVAL;
	return __arch_set_user_pkey_access(tsk, pkey, init_val);
}

static inline void pkey_mm_init(struct mm_struct *mm)
{
	if (static_branch_likely(&pkey_disabled))
		return;
	mm_pkey_allocation_map(mm) = initial_allocation_mask;
}

extern void pkey_initialize(void);
#endif /*_ASM_POWERPC_KEYS_H */
