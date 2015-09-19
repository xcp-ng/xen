/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * purgatory:  stack
 *
 * Copyright (C) 2014 Red Hat Inc.
 * Copyright (C) 2024  Cloud Software Group Inc.
 *
 *	This code has been adapted from kexec-tools and Linux.
 */

#include "config.h"

	/* A stack for the loaded kernel.
	 * Separate and in the data section so it can be prepopulated.
	 */
	.data

BALIGN(4096)
GLOBAL(stack)
	.skip 4096
GLOBAL_END(stack)
