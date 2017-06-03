/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */
#ifndef _ASM_POWERPC_MMAN_H
#define _ASM_POWERPC_MMAN_H

#include <uapi/asm/mman.h>

#ifdef CONFIG_PPC64

#include <asm/cputable.h>
#include <linux/mm.h>
#include <linux/pkeys.h>
#include <asm/cpu_has_feature.h>

#ifdef CONFIG_PPC64_MEMORY_PROTECTION_KEYS

/*
 * This file is included by linux/mman.h, so we can't use cacl_vm_prot_bits()
 * here.  How important is the optimization?
 */
#define arch_calc_vm_prot_bits(prot, key) (             \
		((prot) & PROT_SAO ? VM_SAO : 0) |	\
			pkey_to_vmflag_bits(key))
#define arch_vm_get_page_prot(vm_flags) __pgprot(       \
		((vm_flags) & VM_SAO ? _PAGE_SAO : 0) |	\
		vmflag_to_page_pkey_bits(vm_flags))

#else /* CONFIG_PPC64_MEMORY_PROTECTION_KEYS */

#define arch_calc_vm_prot_bits(prot, key) (	\
		((prot) & PROT_SAO ? VM_SAO : 0))
#define arch_vm_get_page_prot(vm_flags) __pgprot(	\
		((vm_flags) & VM_SAO ? _PAGE_SAO : 0))

#endif /* CONFIG_PPC64_MEMORY_PROTECTION_KEYS */


static inline bool arch_validate_prot(unsigned long prot)
{
	if (prot & ~(PROT_READ | PROT_WRITE | PROT_EXEC | PROT_SEM | PROT_SAO))
		return false;
	if ((prot & PROT_SAO) && !cpu_has_feature(CPU_FTR_SAO))
		return false;
	return true;
}
#define arch_validate_prot(prot) arch_validate_prot(prot)

#endif /* CONFIG_PPC64 */
#endif	/* _ASM_POWERPC_MMAN_H */
