#ifndef _ASM_PPC64_PKEYS_H
#define _ASM_PPC64_PKEYS_H

extern bool pkey_inited;
extern int pkeys_total; /* total pkeys as per device tree */
extern u32 initial_allocation_mask;/* bits set for reserved keys */

#define arch_max_pkey()  pkeys_total
#define AMR_RD_BIT 0x1UL
#define AMR_WR_BIT 0x2UL
#define IAMR_EX_BIT 0x1UL
#define ARCH_VM_PKEY_FLAGS (VM_PKEY_BIT0 | VM_PKEY_BIT1 | VM_PKEY_BIT2 | \
				VM_PKEY_BIT3 | VM_PKEY_BIT4)
#define AMR_BITS_PER_PKEY 2

#define pkey_alloc_mask(pkey) (0x1 << pkey)

#define mm_pkey_allocation_map(mm)	(mm->context.pkey_allocation_map)

#define mm_set_pkey_allocated(mm, pkey) {	\
	mm_pkey_allocation_map(mm) |= pkey_alloc_mask(pkey); \
}

#define mm_set_pkey_free(mm, pkey) {	\
	mm_pkey_allocation_map(mm) &= ~pkey_alloc_mask(pkey);	\
}

#define mm_set_pkey_is_allocated(mm, pkey)	\
	(mm_pkey_allocation_map(mm) & pkey_alloc_mask(pkey))

#define mm_set_pkey_is_reserved(mm, pkey) (initial_allocation_mask & \
					pkey_alloc_mask(pkey))

static inline bool mm_pkey_is_allocated(struct mm_struct *mm, int pkey)
{
	/* a reserved key is never considered as 'explicitly allocated' */
	return ((pkey < arch_max_pkey()) &&
		!mm_set_pkey_is_reserved(mm, pkey) &&
		mm_set_pkey_is_allocated(mm, pkey));
}

extern void __arch_activate_pkey(int pkey);
extern void __arch_deactivate_pkey(int pkey);
/*
 * Returns a positive, 5-bit key on success, or -1 on failure.
 */
static inline int mm_pkey_alloc(struct mm_struct *mm)
{
	/*
	 * Note: this is the one and only place we make sure
	 * that the pkey is valid as far as the hardware is
	 * concerned.  The rest of the kernel trusts that
	 * only good, valid pkeys come out of here.
	 */
	u32 all_pkeys_mask = (u32)(~(0x0));
	int ret;

	if (!pkey_inited)
		return -1;
	/*
	 * Are we out of pkeys?  We must handle this specially
	 * because ffz() behavior is undefined if there are no
	 * zeros.
	 */
	if (mm_pkey_allocation_map(mm) == all_pkeys_mask)
		return -1;

	ret = ffz((u32)mm_pkey_allocation_map(mm));
	mm_set_pkey_allocated(mm, ret);

	/*
	 * enable the key in the hardware
	 */
	if (ret > 0)
		__arch_activate_pkey(ret);
	return ret;
}

static inline int mm_pkey_free(struct mm_struct *mm, int pkey)
{
	if (!pkey_inited)
		return -1;

	if (!mm_pkey_is_allocated(mm, pkey))
		return -EINVAL;

	/*
	 * Disable the key in the hardware
	 */
	__arch_deactivate_pkey(pkey);
	mm_set_pkey_free(mm, pkey);

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
	if (!pkey_inited)
		return -EINVAL;
	return __arch_set_user_pkey_access(tsk, pkey, init_val);
}

static inline void pkey_mm_init(struct mm_struct *mm)
{
	if (!pkey_inited)
		return;
	mm_pkey_allocation_map(mm) = initial_allocation_mask;
}

static inline void pkey_initialize(void)
{
	int os_reserved, i;

	/* disable the pkey system till everything
	 * is in place. A patch further down the
	 * line will enable it.
	 */
	pkey_inited = false;

	/* Lets assume 32 keys */
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
#endif /*_ASM_PPC64_PKEYS_H */
