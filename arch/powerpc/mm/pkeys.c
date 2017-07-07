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
#include <linux/pkeys.h>                /* PKEY_*                       */

bool pkey_inited;
bool pkey_execute_disable_support;
int  pkeys_total;		/* total pkeys as per device tree */
u32  initial_allocation_mask;	/* bits set for reserved keys */

void __init pkey_initialize(void)
{
	int os_reserved, i;

	/*
	 * disable the pkey system till everything
	 * is in place. A patch further down the
	 * line will enable it.
	 */
	pkey_inited = false;

	/*
	 * disable execute_disable support for now.
	 * A patch further down will enable it.
	 */
	pkey_execute_disable_support = false;

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

#define PKEY_REG_BITS (sizeof(u64)*8)
#define pkeyshift(pkey) (PKEY_REG_BITS - ((pkey+1) * AMR_BITS_PER_PKEY))

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
