// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Setup code for LAN966X
 *
 * Copyright (C) 2021 Microchip Technology, Inc. and its subsidiaries
 *
 */

#include <linux/of.h>
#include <linux/of_platform.h>

#include <asm/mach/arch.h>
#include <asm/system_misc.h>

#include "generic.h"

static const char *const lan966x_dt_board_compat[] __initconst = {
	"microchip,lan966x",
	NULL
};

DT_MACHINE_START(lan966x_dt, "Microchip LAN966X")
	/* Maintainer: Microchip */
	.dt_compat	= lan966x_dt_board_compat,
MACHINE_END
