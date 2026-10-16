/*
 * QEMU disassembler -- RISC-V specific header (xjitdomain).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DISAS_RISCV_XJITDOMAIN_H
#define DISAS_RISCV_XJITDOMAIN_H

#include "disas/riscv.h"

extern const rv_opcode_data xjitdomain_opcode_data[];

void decode_xjitdomain(rv_decode*, rv_isa);

#endif /* DISAS_RISCV_XJITDOMAIN_H */
