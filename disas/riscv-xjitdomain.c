/*
 * QEMU RISC-V Disassembler for xjitdomain.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "disas/riscv.h"
#include "disas/riscv-xjitdomain.h"

typedef enum {
    /* 0 is reserved for rv_op_illegal. */
    xjitdomain_op_dlb = 1,
    xjitdomain_op_dlh = 2,
    xjitdomain_op_dlw = 3,
    xjitdomain_op_dld = 4,
    xjitdomain_op_dlbu = 5,
    xjitdomain_op_dlhu = 6,
    xjitdomain_op_dlwu = 7,
    xjitdomain_op_dsb = 8,
    xjitdomain_op_dsh = 9,
    xjitdomain_op_dsw = 10,
    xjitdomain_op_dsd = 11,
    xjitdomain_op_domcall = 12,
    xjitdomain_op_domret = 13,
    xjitdomain_op_domlpad = 14,
} rv_xjitdomain_op;

const rv_opcode_data xjitdomain_opcode_data[] = {
    { "jd.illegal", rv_codec_illegal, rv_fmt_none, NULL, 0, 0, 0 },
    { "dlb", rv_codec_i, rv_fmt_rd_offset_rs1, NULL, 0, 0, 0 },
    { "dlh", rv_codec_i, rv_fmt_rd_offset_rs1, NULL, 0, 0, 0 },
    { "dlw", rv_codec_i, rv_fmt_rd_offset_rs1, NULL, 0, 0, 0 },
    { "dld", rv_codec_i, rv_fmt_rd_offset_rs1, NULL, 0, 0, 0 },
    { "dlbu", rv_codec_i, rv_fmt_rd_offset_rs1, NULL, 0, 0, 0 },
    { "dlhu", rv_codec_i, rv_fmt_rd_offset_rs1, NULL, 0, 0, 0 },
    { "dlwu", rv_codec_i, rv_fmt_rd_offset_rs1, NULL, 0, 0, 0 },
    { "dsb", rv_codec_s, rv_fmt_rs2_offset_rs1, NULL, 0, 0, 0 },
    { "dsh", rv_codec_s, rv_fmt_rs2_offset_rs1, NULL, 0, 0, 0 },
    { "dsw", rv_codec_s, rv_fmt_rs2_offset_rs1, NULL, 0, 0, 0 },
    { "dsd", rv_codec_s, rv_fmt_rs2_offset_rs1, NULL, 0, 0, 0 },
    { "domcall", rv_codec_dom, rv_fmt_rd_rs1_immh_imml, NULL, 0, 0, 0 },
    { "domret", rv_codec_none, rv_fmt_none, NULL, 0, 0, 0 },
    { "domlpad", rv_codec_dom, rv_fmt_imm_imm1, NULL, 0, 0, 0 },
};

void decode_xjitdomain(rv_decode *dec, rv_isa isa)
{
    rv_inst inst = dec->inst;
    rv_opcode op = rv_op_illegal;

    switch (((inst >> 0) & 0b11)) {
    case 3:
        switch (((inst >> 2) & 0b11111)) {
        case 2:
            /* custom-0: typed loads */
            switch (((inst >> 12) & 0b111)) {
            case 0: op = xjitdomain_op_dlb; break;
            case 1: op = xjitdomain_op_dlh; break;
            case 2: op = xjitdomain_op_dlw; break;
            case 3: op = xjitdomain_op_dld; break;
            case 4: op = xjitdomain_op_dlbu; break;
            case 5: op = xjitdomain_op_dlhu; break;
            case 6: op = xjitdomain_op_dlwu; break;
            }
            break;
        case 10:
            /* custom-1: typed stores */
            switch (((inst >> 12) & 0b111)) {
            case 0: op = xjitdomain_op_dsb; break;
            case 1: op = xjitdomain_op_dsh; break;
            case 2: op = xjitdomain_op_dsw; break;
            case 3: op = xjitdomain_op_dsd; break;
            }
            break;
        case 22:
            /* custom-2: domain transitions */
            switch (((inst >> 12) & 0b111)) {
            case 0:
                op = xjitdomain_op_domcall;
                break;
            case 1:
                /* imm, rs1 and rd are zero */
                if ((inst & 0xffff8f80) == 0) {
                    op = xjitdomain_op_domret;
                }
                break;
            case 2:
                /* rs1 and rd are zero */
                if ((inst & 0x000f8f80) == 0) {
                    op = xjitdomain_op_domlpad;
                }
                break;
            }
            break;
        }
        break;
    }

    dec->op = op;
}
