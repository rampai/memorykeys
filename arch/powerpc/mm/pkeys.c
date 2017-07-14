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

void __init pkey_initialize(void)
{
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
}
