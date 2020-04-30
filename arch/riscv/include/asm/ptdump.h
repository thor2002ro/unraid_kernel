/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2019 SiFive
 */

#ifndef _ASM_RISCV_PTDUMP_H
#define _ASM_RISCV_PTDUMP_H

void ptdump_check_wx(void);

#ifdef CONFIG_DEBUG_WX
#define debug_checkwx() ptdump_check_wx()
#else
#define debug_checkwx() do { } while (0)
#endif

#endif /* _ASM_RISCV_PTDUMP_H */
