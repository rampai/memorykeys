#ifndef _ASM_PPC64_PKEYS_H
#define _ASM_PPC64_PKEYS_H

extern bool pkey_inited;
extern int pkeys_total; /* total pkeys as per device tree */
extern u32 initial_allocation_mask;/* bits set for reserved keys */

/*
 * powerpc needs an additional vma bit to support 32 keys.
 * Till the additional vma bit lands in include/linux/mm.h
 * we have to carry the hunk below. This is  needed to get
 * pkeys working on power. -- Ram
 */
#ifndef VM_HIGH_ARCH_BIT_4
#define VM_HIGH_ARCH_BIT_4	36
#define VM_HIGH_ARCH_4	BIT(VM_HIGH_ARCH_BIT_4)
#define VM_PKEY_SHIFT VM_HIGH_ARCH_BIT_0
#define VM_PKEY_BIT0	VM_HIGH_ARCH_0
#define VM_PKEY_BIT1	VM_HIGH_ARCH_1
#define VM_PKEY_BIT2	VM_HIGH_ARCH_2
#define VM_PKEY_BIT3	VM_HIGH_ARCH_3
#define VM_PKEY_BIT4	VM_HIGH_ARCH_4
#endif

/* override any generic PKEY Permission defines */
#undef  PKEY_DISABLE_ACCESS
#define PKEY_DISABLE_ACCESS    0x1
#undef  PKEY_DISABLE_WRITE
#define PKEY_DISABLE_WRITE     0x2
#undef  PKEY_DISABLE_EXECUTE
#define PKEY_DISABLE_EXECUTE   0x4
#undef  PKEY_ACCESS_MASK
#define PKEY_ACCESS_MASK       (PKEY_DISABLE_ACCESS |\
				PKEY_DISABLE_WRITE  |\
				PKEY_DISABLE_EXECUTE)

static inline u64 pkey_to_vmflag_bits(u16 pkey)
{
	if (!pkey_inited)
		return 0x0UL;

	return (((pkey & 0x1UL) ? VM_PKEY_BIT0 : 0x0UL) |
		((pkey & 0x2UL) ? VM_PKEY_BIT1 : 0x0UL) |
		((pkey & 0x4UL) ? VM_PKEY_BIT2 : 0x0UL) |
		((pkey & 0x8UL) ? VM_PKEY_BIT3 : 0x0UL) |
		((pkey & 0x10UL) ? VM_PKEY_BIT4 : 0x0UL));
}

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
extern int __execute_only_pkey(struct mm_struct *mm);
static inline int execute_only_pkey(struct mm_struct *mm)
{
	if (!pkey_inited)
		return -1;
	return __execute_only_pkey(mm);
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
	/* -1 means unallocated or invalid */
	mm->context.execute_only_pkey = -1;
}

extern void thread_pkey_regs_save(struct thread_struct *thread);
extern void thread_pkey_regs_restore(struct thread_struct *new_thread, 
			struct thread_struct *old_thread);
extern void thread_pkey_regs_init(struct thread_struct *thread);
extern void pkey_initialize(void);
#endif /*_ASM_PPC64_PKEYS_H */
