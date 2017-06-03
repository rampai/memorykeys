/*
 * PowerPC Memory Protection Keys management
 * Copyright (c) 2015, Intel Corporation.
 * Copyright (c) 2017, IBM Corporation.
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
#include <uapi/asm-generic/mman-common.h>
#include <linux/pkeys.h>                /* PKEY_*                       */

bool pkey_inited;
int  pkeys_total;		/* total pkeys as per device tree */
u32  initial_allocation_mask;	/* bits set for reserved keys */

void pkey_initialize(void)
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
