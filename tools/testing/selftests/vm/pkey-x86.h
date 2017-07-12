/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _PKEYS_X86_H
#define _PKEYS_X86_H

#ifdef __i386__

#ifndef SYS_mprotect_key
# define SYS_mprotect_key 380
#endif
#ifndef SYS_pkey_alloc
# define SYS_pkey_alloc	  381
# define SYS_pkey_free	  382
#endif
#define REG_IP_IDX REG_EIP
#define si_pkey_offset 0x14

#else

#ifndef SYS_mprotect_key
# define SYS_mprotect_key 329
#endif
#ifndef SYS_pkey_alloc
# define SYS_pkey_alloc	  330
# define SYS_pkey_free	  331
#endif
#define REG_IP_IDX REG_RIP
#define si_pkey_offset 0x20

#endif

#define PKEY_DISABLE_ACCESS	0x1
#define PKEY_DISABLE_WRITE	0x2
#define HPAGE_SIZE		(1UL<<21)
#define pkey_reg_t u32
#define PKEY_REG_FMT "%016x"

static inline void __page_o_noops(void)
{
	/* 8-bytes of instruction * 512 bytes = 1 page */
	asm(".rept 512 ; nopl 0x7eeeeeee(%eax) ; .endr");
}

#endif /* _PKEYS_X86_H */
