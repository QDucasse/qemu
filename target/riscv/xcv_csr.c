/*
 * CORE-V hidden-time CSRs (xcvhtime).
 *
 * Software-visible model of the CVA6 hidden-time extension: guest time and
 * cycle stop while the hart runs with V=0, if htimectl.HHAE=1.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "cpu.h"

/*
 * The generic CSR check derives the access rules from the H-level address:
 * VS/VU raise a virtual-instruction fault, U an illegal instruction.
 */
static RISCVException xcvhtime(CPURISCVState *env, int csrno)
{
    if (riscv_cpu_cfg(env)->ext_xcvhtime) {
        return RISCV_EXCP_NONE;
    }

    return RISCV_EXCP_ILLEGAL_INST;
}

static uint64_t *xcv_csr_ptr(CPURISCVState *env, int csrno)
{
    switch (csrno) {
    case CSR_XCV_HTIMECTL:
        return &env->htimectl;
    case CSR_XCV_HEXIT_TIME:
        return &env->hexit_time;
    case CSR_XCV_HHIDDEN_TIME:
        return &env->hhidden_time;
    case CSR_XCV_HVTIMECMP:
        return &env->hvtimecmp;
    case CSR_XCV_HEXIT_CYCLE:
        return &env->hexit_cycle;
    case CSR_XCV_HHIDDEN_CYCLE:
        return &env->hhidden_cycle;
    default:
        g_assert_not_reached();
    }
}

static RISCVException read_xcv(CPURISCVState *env, int csrno,
                               target_ulong *val)
{
    *val = *xcv_csr_ptr(env, csrno);
    return RISCV_EXCP_NONE;
}

static RISCVException write_xcv(CPURISCVState *env, int csrno,
                                target_ulong val, uintptr_t ra)
{
    if (csrno == CSR_XCV_HTIMECTL) {
        val &= XCV_HTIMECTL_HHAE;
    }
    *xcv_csr_ptr(env, csrno) = val;

    return RISCV_EXCP_NONE;
}

#define XCV_CSR(no, name) \
    { .csrno = no, .csr_ops = { name, xcvhtime, read_xcv, write_xcv } }

const RISCVCSR xcv_csr_list[] = {
    XCV_CSR(CSR_XCV_HTIMECTL, "htimectl"),
    XCV_CSR(CSR_XCV_HEXIT_TIME, "hexit_time"),
    XCV_CSR(CSR_XCV_HHIDDEN_TIME, "hhidden_time"),
    XCV_CSR(CSR_XCV_HVTIMECMP, "hvtimecmp"),
    XCV_CSR(CSR_XCV_HEXIT_CYCLE, "hexit_cycle"),
    XCV_CSR(CSR_XCV_HHIDDEN_CYCLE, "hhidden_cycle"),
    { }
};
