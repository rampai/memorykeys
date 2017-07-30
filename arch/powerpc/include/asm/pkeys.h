#ifndef _ASM_PPC64_PKEYS_H
#define _ASM_PPC64_PKEYS_H

extern bool pkey_inited;
extern bool pkey_execute_disable_support;

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

#define ARCH_VM_PKEY_FLAGS 0

static inline bool mm_pkey_is_allocated(struct mm_struct *mm, int pkey)
{
	return (pkey == 0);
}

static inline int mm_pkey_alloc(struct mm_struct *mm)
{
	return -1;
}

static inline int mm_pkey_free(struct mm_struct *mm, int pkey)
{
	return -EINVAL;
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

static inline int arch_set_user_pkey_access(struct task_struct *tsk, int pkey,
		unsigned long init_val)
{
	return 0;
}

extern void pkey_initialize(void);
#endif /*_ASM_PPC64_PKEYS_H */
