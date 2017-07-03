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

#include <asm/mman.h>
#include <linux/pkeys.h>

bool pkey_inited;
bool pkey_execute_disable_support;
int  pkeys_total;		/* Total pkeys as per device tree */
u32  initial_allocation_mask;	/* Bits set for reserved keys */
u64  pkey_register_mask;	/* Bits in AMR/IAMR/UMOR not to be touched */

#define PKEY_REG_BITS (sizeof(u64)*8)
#define pkeyshift(pkey) (PKEY_REG_BITS - ((pkey+1) * AMR_BITS_PER_PKEY))

void __init pkey_initialize(void)
{
	int os_reserved, i;

	/*
	 * We define PKEY_DISABLE_EXECUTE in addition to the arch-neutral
	 * generic defines for PKEY_DISABLE_ACCESS and PKEY_DISABLE_WRITE.
	 * Ensure that the bits a distinct.
	 */
	BUILD_BUG_ON(PKEY_DISABLE_EXECUTE &
		     (PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE));

	/*
	 * Disable the pkey system till everything is in place. A subsequent
	 * patch will enable it.
	 */
	pkey_inited = false;

	/*
	 * Disable execute_disable support for now. A subsequent patch will
	 * it.
	 */
	pkey_execute_disable_support = false;

	/* Lets assume 32 keys */
	pkeys_total = 32;

	/* 
	 * Adjust the upper limit, based on the number of bits supported by
	 * arch-neutral code.
	 */
	pkeys_total = min_t(int, pkeys_total,
			(ARCH_VM_PKEY_FLAGS >> VM_PKEY_SHIFT));

#ifdef CONFIG_PPC_4K_PAGES
	/*
	 * The OS can manage only 8 pkeys due to its inability to represent them
	 * in the Linux 4K PTE.
	 */
	os_reserved = pkeys_total - 8;
#else
	os_reserved = 0;
#endif
	/*
	 * Bits are in LE format. NOTE: 1, 0 are reserved.
	 * key 0 is the default key, which allows read/write/execute.
	 * key 1 is recommended not to be used. PowerISA(3.0) page 1015,
	 * 	programming note.
	 */
	initial_allocation_mask = ~0x0;

	/* register mask is in BE format */
	pkey_register_mask = ~0x0ul;

	for (i = 2; i < (pkeys_total - os_reserved); i++) {
		initial_allocation_mask &= ~(0x1 << i);
		pkey_register_mask &= ~(0x3ul << pkeyshift(i));
	}
}

static bool is_pkey_enabled(int pkey)
{
	u64 uamor = read_uamor();
	u64 pkey_bits = 0x3ul << pkeyshift(pkey);
	u64 uamor_pkey_bits = (uamor & pkey_bits);

	/* 
	 * both the bits in UMOR corresponding to the key should be set or
	 * reset.
	 */
	BUG_ON(uamor_pkey_bits && (uamor_pkey_bits != pkey_bits));
	return !!(uamor_pkey_bits);
}

static inline void init_amr(int pkey, u8 init_bits)
{
	u64 new_amr_bits = (((u64)init_bits & 0x3UL) << pkeyshift(pkey));
	u64 old_amr = read_amr() & ~((u64)(0x3ul) << pkeyshift(pkey));

	write_amr(old_amr | new_amr_bits);
}

static inline void init_iamr(int pkey, u8 init_bits)
{
	u64 new_iamr_bits = (((u64)init_bits & 0x3UL) << pkeyshift(pkey));
	u64 old_iamr = read_iamr() & ~((u64)(0x3ul) << pkeyshift(pkey));

	write_iamr(old_iamr | new_iamr_bits);
}

static void pkey_status_change(int pkey, bool enable)
{
	u64 old_uamor;

	/* Reset the AMR and IAMR bits for this key */
	init_amr(pkey, 0x0);
	init_iamr(pkey, 0x0);

	/* Enable/disable key */
	old_uamor = read_uamor();
	if (enable)
		old_uamor |= (0x3ul << pkeyshift(pkey));
	else
		old_uamor &= ~(0x3ul << pkeyshift(pkey));
	write_uamor(old_uamor);
}

void __arch_activate_pkey(int pkey)
{
	pkey_status_change(pkey, true);
}

void __arch_deactivate_pkey(int pkey)
{
	pkey_status_change(pkey, false);
}

/*
 * Set the access rights in AMR IAMR and UAMOR registers for @pkey to that
 * specified in @init_val.
 */
int __arch_set_user_pkey_access(struct task_struct *tsk, int pkey,
				unsigned long init_val)
{
	u64 new_amr_bits = 0x0ul;
	u64 new_iamr_bits = 0x0ul;

	if (!is_pkey_enabled(pkey))
		return -EINVAL;

	if (init_val & PKEY_DISABLE_EXECUTE) {
		if (!pkey_execute_disable_support)
			return -EINVAL;
		new_iamr_bits |= IAMR_EX_BIT;
	}
	init_iamr(pkey, new_iamr_bits);

	/* Set the bits we need in AMR: */
	if (init_val & PKEY_DISABLE_ACCESS)
		new_amr_bits |= AMR_RD_BIT | AMR_WR_BIT;
	else if (init_val & PKEY_DISABLE_WRITE)
		new_amr_bits |= AMR_WR_BIT;

	init_amr(pkey, new_amr_bits);
	return 0;
}

void thread_pkey_regs_save(struct thread_struct *thread)
{
	if (!pkey_inited)
		return;

	/*
	 * TODO: Skip saving registers if @thread hasn't used any keys yet.
	 */

	thread->amr = read_amr();
	thread->iamr = read_iamr();
	thread->uamor = read_uamor();
}

void thread_pkey_regs_restore(struct thread_struct *new_thread,
			      struct thread_struct *old_thread)
{
	if (!pkey_inited)
		return;

	/*
	 * TODO: Just set UAMOR to zero if @new_thread hasn't used any keys yet.
	 */

	if (old_thread->amr != new_thread->amr)
		write_amr(new_thread->amr);
	if (old_thread->iamr != new_thread->iamr)
		write_iamr(new_thread->iamr);
	if (old_thread->uamor != new_thread->uamor)
		write_uamor(new_thread->uamor);
}

void thread_pkey_regs_init(struct thread_struct *thread)
{
	write_amr(read_amr() & pkey_register_mask);
	write_iamr(read_iamr() & pkey_register_mask);
	write_uamor(read_uamor() & pkey_register_mask);
}

static inline bool pkey_allows_readwrite(int pkey)
{
	int pkey_shift = pkeyshift(pkey);

	if (!is_pkey_enabled(pkey))
		return true;

	return !(read_amr() & ((AMR_RD_BIT|AMR_WR_BIT) << pkey_shift));
}

int __execute_only_pkey(struct mm_struct *mm)
{
	bool need_to_set_mm_pkey = false;
	int execute_only_pkey = mm->context.execute_only_pkey;
	int ret;

	/* Do we need to assign a pkey for mm's execute-only maps? */
	if (execute_only_pkey == -1) {
		/* Go allocate one to use, which might fail */
		execute_only_pkey = mm_pkey_alloc(mm);
		if (execute_only_pkey < 0)
			return -1;
		need_to_set_mm_pkey = true;
	}

	/*
	 * We do not want to go through the relatively costly dance to set AMR
	 * if we do not need to. Check it first and assume that if the
	 * execute-only pkey is readwrite-disabled than we do not have to set it
	 * ourselves.
	 */
	if (!need_to_set_mm_pkey && !pkey_allows_readwrite(execute_only_pkey))
		return execute_only_pkey;

	/*
	 * Set up AMR so that it denies access for everything other than
	 * execution.
	 */
	ret = __arch_set_user_pkey_access(current, execute_only_pkey,
					  PKEY_DISABLE_ACCESS |
					  PKEY_DISABLE_WRITE);
	/*
	 * If the AMR-set operation failed somehow, just return 0 and
	 * effectively disable execute-only support.
	 */
	if (ret) {
		mm_set_pkey_free(mm, execute_only_pkey);
		return -1;
	}

	/* We got one, store it and use it from here on out */
	if (need_to_set_mm_pkey)
		mm->context.execute_only_pkey = execute_only_pkey;
	return execute_only_pkey;
}

static inline bool vma_is_pkey_exec_only(struct vm_area_struct *vma)
{
	/* Do this check first since the vm_flags should be hot */
	if ((vma->vm_flags & (VM_READ | VM_WRITE | VM_EXEC)) != VM_EXEC)
		return false;

	return (vma_pkey(vma) == vma->vm_mm->context.execute_only_pkey);
}

/*
 * This should only be called for *plain* mprotect calls.
 */
int __arch_override_mprotect_pkey(struct vm_area_struct *vma, int prot,
				  int pkey)
{
	/*
	 * If the currently associated pkey is execute-only, but the requested
	 * protection requires read or write, move it back to the default pkey.
	 */
	if (vma_is_pkey_exec_only(vma) && (prot & (PROT_READ | PROT_WRITE)))
		return 0;

	/*
	 * The requested protection is execute-only. Hence let's use an
	 * execute-only pkey.
	 */
	if (prot == PROT_EXEC) {
		pkey = execute_only_pkey(vma->vm_mm);
		if (pkey > 0)
			return pkey;
	}

	/* Nothing to override. */
	return vma_pkey(vma);
}

static bool pkey_access_permitted(int pkey, bool write, bool execute)
{
	int pkey_shift;
	u64 amr;

	if (!pkey)
		return true;

	if (!is_pkey_enabled(pkey))
		return true;

	pkey_shift = pkeyshift(pkey);
	if (execute && !(read_iamr() & (IAMR_EX_BIT << pkey_shift)))
		return true;

	amr = read_amr(); /* Delay reading amr until absolutely needed */
	return ((!write && !(amr & (AMR_RD_BIT << pkey_shift))) ||
		(write &&  !(amr & (AMR_WR_BIT << pkey_shift))));
}

bool arch_pte_access_permitted(u64 pte, bool write, bool execute)
{
	if (!pkey_inited)
		return true;

	return pkey_access_permitted(pte_to_pkey_bits(pte), write, execute);
}

/*
 * We only want to enforce protection keys on the current process because we
 * effectively have no access to AMR/IAMR for other processes or any way to tell
 * *which * AMR/IAMR in a threaded process we could use.
 *
 * So do not enforce things if the VMA is not from the current mm, or if we are
 * in a kernel thread.
 */
static inline bool vma_is_foreign(struct vm_area_struct *vma)
{
	if (!current->mm)
		return true;
	/*
	 * If the VMA is from another process, then AMR/IAMR has no relevance
	 * and should not be enforced.
	 */
	if (current->mm != vma->vm_mm)
		return true;

	return false;
}

bool arch_vma_access_permitted(struct vm_area_struct *vma, bool write,
			       bool execute, bool foreign)
{
	int pkey;

	if (!pkey_inited)
		return true;

	/* Allow access if the VMA is not one from this process */
	if (foreign || vma_is_foreign(vma))
		return true;

	pkey = vma_pkey(vma);

	if (!pkey)
		return true;

	return pkey_access_permitted(pkey, write, execute);
}
