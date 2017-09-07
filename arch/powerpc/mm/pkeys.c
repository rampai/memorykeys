/*
 * PowerPC Memory Protection Keys management
 * Copyright (c) 2017, IBM Corporation.
 * Author: Ram Pai <linuxram@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */
#include <asm/mman.h>
#include <linux/pkeys.h>                /* PKEY_*                       */

bool pkey_inited;
bool pkey_execute_disable_support;
int  pkeys_total;		/* total pkeys as per device tree */
u32  initial_allocation_mask;	/* bits set for reserved keys */

void __init pkey_initialize(void)
{
	int os_reserved, i;

	/*
	 * we define PKEY_DISABLE_EXECUTE in addition to the arch-neutral
	 * generic defines for PKEY_DISABLE_ACCESS and PKEY_DISABLE_WRITE.
	 * Ensure that the bits a distinct.
	 */
	BUILD_BUG_ON(PKEY_DISABLE_EXECUTE &
		     (PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE));

	/*
	 * disable the pkey system till everything
	 * is in place. A patch further down the
	 * line will enable it.
	 */
	pkey_inited = false;
	if (pkey_mmu_enabled())
		pkey_inited = !radix_enabled();
	if (!pkey_inited)
		return;

	/*
	 * the device tree cannot be relied on for 
	 * execute_disable support. Hence we depend
	 * on CPU FTR.
	 */
	pkey_execute_disable_support = cpu_has_feature(CPU_FTR_PKEY_EXECUTE);

	/*
	 * Lets assume 32 keys if we are not told
	 * the number of pkeys.
	 */
	if (!pkeys_total)
		pkeys_total = 32;

#ifdef CONFIG_PPC_4K_PAGES
	/*
	 * the OS can manage only 8 pkeys
	 * due to its inability to represent
	 * them in the linux 4K-PTE.
	 */
	os_reserved = pkeys_total-8;
#else
	os_reserved = 0;
#endif
	/*
	 * Bits are in LE format.
	 * NOTE: 1, 0 are reserved.
	 * key 0 is the default key, which allows read/write/execute.
	 * key 1 is recommended not to be used.
	 * PowerISA(3.0) page 1015, programming note.
	 */
	initial_allocation_mask = ~0x0;
	for (i = 2; i < (pkeys_total - os_reserved); i++)
		initial_allocation_mask &= ~(0x1<<i);
}

#define PKEY_REG_BITS (sizeof(u64)*8)
#define pkeyshift(pkey) (PKEY_REG_BITS - ((pkey+1) * AMR_BITS_PER_PKEY))

static bool is_pkey_enabled(int pkey)
{
	return !!(read_uamor() & (0x3ul << pkeyshift(pkey)));
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

	/* reset the AMR and IAMR bits for this key */
	init_amr(pkey, 0x0);
	init_iamr(pkey, 0x0);

	/* enable/disable key */
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
 * set the access right in AMR IAMR and UAMOR register
 * for @pkey to that specified in @init_val.
 */
int __arch_set_user_pkey_access(struct task_struct *tsk, int pkey,
		unsigned long init_val)
{
	u64 new_amr_bits = 0x0ul;
	u64 new_iamr_bits = 0x0ul;

	if (!is_pkey_enabled(pkey))
		return -EINVAL;

	if ((init_val & PKEY_DISABLE_EXECUTE)) {
		if (!pkey_execute_disable_support)
			return -EINVAL;
		new_iamr_bits |= IAMR_EX_BIT;
	}
	init_iamr(pkey, new_iamr_bits);

	/* Set the bits we need in AMR:  */
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

	/* @TODO skip saving any registers if the thread
	 * has not used any keys yet.
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

	/* @TODO just reset uamor to zero if the new_thread
	 * has not used any keys yet.
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
	write_amr(0x0ul);
	write_iamr(0x0ul);
	write_uamor(0x0ul);
}

static inline bool pkey_allows_readwrite(int pkey)
{
	int pkey_shift = pkeyshift(pkey);

	if (!(read_uamor() & (0x3UL << pkey_shift)))
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
	 * We do not want to go through the relatively costly
	 * dance to set AMR if we do not need to.  Check it
	 * first and assume that if the execute-only pkey is
	 * readwrite-disabled than we do not have to set it
	 * ourselves.
	 */
	if (!need_to_set_mm_pkey &&
	    !pkey_allows_readwrite(execute_only_pkey))
		return execute_only_pkey;

	/*
	 * Set up AMR so that it denies access for everything
	 * other than execution.
	 */
	ret = __arch_set_user_pkey_access(current, execute_only_pkey,
			(PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE));
	/*
	 * If the AMR-set operation failed somehow, just return
	 * 0 and effectively disable execute-only support.
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
	 * Is this an mprotect_pkey() call?  If so, never
	 * override the value that came from the user.
	 */
	if (pkey != -1)
		return pkey;

	/*
	 * If the currently associated pkey is execute-only,
	 * but the requested protection requires read or write,
	 * move it back to the default pkey.
	 */
	if (vma_is_pkey_exec_only(vma) &&
	    (prot & (PROT_READ|PROT_WRITE)))
		return 0;

	/*
	 * the requested protection is execute-only. Hence
	 * lets use a execute-only pkey.
	 */
	if (prot == PROT_EXEC) {
		pkey = execute_only_pkey(vma->vm_mm);
		if (pkey > 0)
			return pkey;
	}

	/*
	 * nothing to override.
	 */
	return vma_pkey(vma);
}

static bool pkey_access_permitted(int pkey, bool write, bool execute)
{
	int pkey_shift;
	u64 amr;

	if (!pkey)
		return true;

	pkey_shift = pkeyshift(pkey);
	if (!(read_uamor() & (0x3UL << pkey_shift)))
		return true;

	if (execute && !(read_iamr() & (IAMR_EX_BIT << pkey_shift)))
		return true;

	amr = read_amr(); /* delay reading amr uptil absolutely needed*/
	return ((!write && !(amr & (AMR_RD_BIT << pkey_shift))) ||
		(write &&  !(amr & (AMR_WR_BIT << pkey_shift))));
}

bool arch_pte_access_permitted(u64 pte, bool write, bool execute)
{
	if (!pkey_inited)
		return true;
	return pkey_access_permitted(pte_to_pkey_bits(pte),
			write, execute);
}

/*
 * We only want to enforce protection keys on the current process
 * because we effectively have no access to AMR/IAMR for other
 * processes or any way to tell *which * AMR/IAMR in a threaded
 * process we could use.
 *
 * So do not enforce things if the VMA is not from the current
 * mm, or if we are in a kernel thread.
 */
static inline bool vma_is_foreign(struct vm_area_struct *vma)
{
	if (!current->mm)
		return true;
	/*
	 * if the VMA is from another process, then AMR/IAMR has no
	 * relevance and should not be enforced.
	 */
	if (current->mm != vma->vm_mm)
		return true;

	return false;
}

bool arch_vma_access_permitted(struct vm_area_struct *vma,
		bool write, bool execute, bool foreign)
{
	int pkey;

	if (!pkey_inited)
		return true;

	/* allow access if the VMA is not one from this process */
	if (foreign || vma_is_foreign(vma))
		return true;

	pkey = vma_pkey(vma);

	if (!pkey)
		return true;

	return pkey_access_permitted(pkey, write, execute);
}

unsigned int arch_usable_pkeys(void)
{
	unsigned int reserved;

	if (!pkey_inited)
		return 0;

	/* Reserve one more to account for the execute-only pkey. */
	reserved = hweight32(initial_allocation_mask) + 1;

	return pkeys_total > reserved ? pkeys_total - reserved : 0;
}

bool arch_supports_pkeys(int cap)
{
	if (cap & PKEY_DISABLE_EXECUTE)
		return pkey_execute_disable_support;
	return (cap & (PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE));
}

long sys_pkey_modify(int pkey, unsigned long new_val)
{
	/* check for unsupported init values */
	if (new_val & ~PKEY_ACCESS_MASK)
		return -EINVAL;

	return __arch_set_user_pkey_access(current, pkey, new_val);
}
