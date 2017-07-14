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

#include <linux/pkeys.h>

DEFINE_STATIC_KEY_TRUE(pkey_disabled);
bool pkey_execute_disable_supported;

void __init pkey_initialize(void)
{
	/*
	 * Disable the pkey system till everything is in place. A subsequent
	 * patch will enable it.
	 */
	static_branch_enable(&pkey_disabled);

	/*
	 * Disable execute_disable support for now. A subsequent patch will
	 * enable it.
	 */
	pkey_execute_disable_supported = false;
}
