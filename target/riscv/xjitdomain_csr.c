/*
 * JITDomain CSRs (xjitdomain).
 *
 * Domain state of the JITDomain compartments: rights matrix, typed-access
 * targets, domcall gates, Domain Return Stack pointer and PMP keys.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/cputlb.h"

/*
 * The generic CSR check derives the access rules from the address: dcause
 * and curdom are read-only, curdom is the only one readable from U mode.
 */
static RISCVException xjitdomain(CPURISCVState *env, int csrno)
{
    if (riscv_cpu_cfg(env)->ext_xjitdomain) {
        return RISCV_EXCP_NONE;
    }

    return RISCV_EXCP_ILLEGAL_INST;
}

/* mndstatus, the RNMI copy of the trap fields, exists only with Smrnmi */
static RISCVException xjitdomain_smrnmi(CPURISCVState *env, int csrno)
{
    if (riscv_cpu_cfg(env)->ext_xjitdomain && riscv_cpu_cfg(env)->ext_smrnmi) {
        return RISCV_EXCP_NONE;
    }

    return RISCV_EXCP_ILLEGAL_INST;
}

/* As for pmpcfg, a dmpcfg CSR exists only if its first PMP entry does */
static RISCVException xjitdomain_dmpcfg(CPURISCVState *env, int csrno)
{
    unsigned first = (csrno - CSR_DMPCFG0) * 16;

    if (riscv_cpu_cfg(env)->ext_xjitdomain &&
        first < riscv_cpu_cfg(env)->pmp_regions) {
        return RISCV_EXCP_NONE;
    }

    return RISCV_EXCP_ILLEGAL_INST;
}

static uint64_t xjitdomain_dtarget_identity(void)
{
    uint64_t val = 0;

    for (uint64_t d = 0; d < JITDOMAIN_NDOMS; d++) {
        val |= d << (3 * d);
    }
    return val;
}

/* DOM0, nothing pending, identity dtarget, dmpcfg unlocked */
void xjitdomain_reset(CPURISCVState *env)
{
    env->curdom = 0;
    env->dpend = 0;
    env->dstatus = 0;
    env->mdstatus = 0;
    env->mndstatus = 0;
    memset(env->drights, 0, sizeof(env->drights));
    env->dtarget = xjitdomain_dtarget_identity();
    env->dgate = 0;
    env->dsp = 0;
    env->dspbase = 0;
    env->dcause = 0;
    memset(env->dmpcfg, 0, sizeof(env->dmpcfg));
}

/*
 * A trap saves {curdom, dpend} in xPD/xPPEND and enters DOM0; xret restores
 * them and clears xPPEND, so that a second xret cannot restore a stale entry.
 * dstatus, mdstatus and mndstatus share bit positions.
 */
void xjitdomain_save_on_trap(CPURISCVState *env, uint64_t *xdstatus)
{
    if (!riscv_cpu_cfg(env)->ext_xjitdomain) {
        return;
    }
    *xdstatus = set_field(*xdstatus, DSTATUS_SPD, env->curdom);
    *xdstatus = set_field(*xdstatus, DSTATUS_SPPEND, env->dpend);
    xjitdomain_set_dom(env, 0, 0);
}

void xjitdomain_restore_on_xret(CPURISCVState *env, uint64_t *xdstatus)
{
    if (!riscv_cpu_cfg(env)->ext_xjitdomain) {
        return;
    }
    xjitdomain_set_dom(env, get_field(*xdstatus, DSTATUS_SPD),
                       get_field(*xdstatus, DSTATUS_SPPEND));
    *xdstatus = set_field(*xdstatus, DSTATUS_SPPEND, 0);
}

/* Instructions are fetched with the rights of the pending domain, if any */
static uint64_t xjitdomain_fetch_dom(uint64_t curdom, uint64_t dpend)
{
    return (dpend & DPEND_VALID) ? get_field(dpend, DPEND_DOM) : curdom;
}

/*
 * The TLB holds entries narrowed to the rights of curdom (R, W) and of the
 * fetch domain (X), so it is flushed when either changes
 */
void xjitdomain_set_dom(CPURISCVState *env, uint64_t curdom, uint64_t dpend)
{
    if ((env->dstatus & DSTATUS_EN) &&
        (curdom != env->curdom ||
         xjitdomain_fetch_dom(curdom, dpend) !=
         xjitdomain_fetch_dom(env->curdom, env->dpend))) {
        tlb_flush(env_cpu(env));
    }
    env->curdom = curdom;
    env->dpend = dpend;
}

static uint64_t *xjitdomain_csr_ptr(CPURISCVState *env, int csrno)
{
    switch (csrno) {
    case CSR_DSTATUS:
        return &env->dstatus;
    case CSR_DRIGHTS0:
    case CSR_DRIGHTS1:
    case CSR_DRIGHTS2:
        return &env->drights[csrno - CSR_DRIGHTS0];
    case CSR_DTARGET:
        return &env->dtarget;
    case CSR_DGATE:
        return &env->dgate;
    case CSR_DSP:
        return &env->dsp;
    case CSR_DSPBASE:
        return &env->dspbase;
    case CSR_DCAUSE:
        return &env->dcause;
    case CSR_MDSTATUS:
        return &env->mdstatus;
    case CSR_MNDSTATUS:
        return &env->mndstatus;
    default:
        g_assert_not_reached();
    }
}

static RISCVException read_xjitdomain(CPURISCVState *env, int csrno,
                                      target_ulong *val)
{
    *val = *xjitdomain_csr_ptr(env, csrno);
    return RISCV_EXCP_NONE;
}

static RISCVException write_xjitdomain(CPURISCVState *env, int csrno,
                                       target_ulong val, uintptr_t ra)
{
    switch (csrno) {
    case CSR_DSTATUS:
        val &= DSTATUS_EN | DSTATUS_SPD | DSTATUS_SPPEND | DSTATUS_DRSKEY |
               DSTATUS_SCHK;
        break;
    case CSR_MDSTATUS:
        val &= MDSTATUS_MPD | MDSTATUS_MPPEND;
        break;
    case CSR_MNDSTATUS:
        val &= MNDSTATUS_MNPD | MNDSTATUS_MNPPEND;
        break;
    case CSR_DTARGET:
        val &= MAKE_64BIT_MASK(0, 3 * JITDOMAIN_NDOMS);
        break;
    }
    *xjitdomain_csr_ptr(env, csrno) = val;

    /* dstatus and drights feed the access check */
    if (csrno == CSR_DSTATUS ||
        (csrno >= CSR_DRIGHTS0 && csrno <= CSR_DRIGHTS2)) {
        tlb_flush(env_cpu(env));
    }
    return RISCV_EXCP_NONE;
}

static RISCVException read_curdom(CPURISCVState *env, int csrno,
                                  target_ulong *val)
{
    *val = (env->dpend << ctz32(CURDOM_PEND)) | env->curdom;
    return RISCV_EXCP_NONE;
}

/*
 * udsp: the U-mode alias of dsp. Only DOM0 may access it, with EN = 1, and a
 * write may only move dsp up, to at most dspbase. A debugger access is a
 * plain access to dsp. The access checks are in the predicate, so that reads
 * get them too.
 */
static RISCVException xjitdomain_udsp(CPURISCVState *env, int csrno)
{
    if (!riscv_cpu_cfg(env)->ext_xjitdomain) {
        return RISCV_EXCP_ILLEGAL_INST;
    }
    if (env->debugger) {
        return RISCV_EXCP_NONE;
    }
    if (!(env->dstatus & DSTATUS_EN)) {
        return RISCV_EXCP_ILLEGAL_INST;
    }
    if (env->curdom != 0) {
        env->dcause = DCAUSE_DSP;
        return RISCV_EXCP_DOMAIN_CFI_FAULT;
    }
    return RISCV_EXCP_NONE;
}

static RISCVException read_udsp(CPURISCVState *env, int csrno,
                                target_ulong *val)
{
    *val = env->dsp;
    return RISCV_EXCP_NONE;
}

/*
 * val is the value the instruction writes, csrrs/csrrc already merged with
 * the old dsp. The fault leaves dsp unchanged, and rd too, since the helper
 * raises it before writing rd.
 */
static RISCVException write_udsp(CPURISCVState *env, int csrno,
                                 target_ulong val, uintptr_t ra)
{
    if (!env->debugger && (val < env->dsp || val > env->dspbase)) {
        env->dcause = DCAUSE_DSPRANGE;
        return RISCV_EXCP_DOMAIN_CFI_FAULT;
    }
    env->dsp = val;
    return RISCV_EXCP_NONE;
}

/* dmpcfg0/1: a {L, k} nibble per PMP entry, 16 entries per CSR */
static RISCVException read_dmpcfg(CPURISCVState *env, int csrno,
                                  target_ulong *val)
{
    unsigned first = (csrno - CSR_DMPCFG0) * 16;
    unsigned n = MIN(16, riscv_cpu_cfg(env)->pmp_regions - first);

    *val = 0;
    for (unsigned i = 0; i < n; i++) {
        *val |= (target_ulong)env->dmpcfg[first + i] << (4 * i);
    }
    return RISCV_EXCP_NONE;
}

static RISCVException write_dmpcfg(CPURISCVState *env, int csrno,
                                   target_ulong val, uintptr_t ra)
{
    unsigned first = (csrno - CSR_DMPCFG0) * 16;
    unsigned n = MIN(16, riscv_cpu_cfg(env)->pmp_regions - first);

    for (unsigned i = 0; i < n; i++) {
        if (!(env->dmpcfg[first + i] & DMPCFG_L)) {
            env->dmpcfg[first + i] = (val >> (4 * i)) & (DMPCFG_L | DMPCFG_K);
        }
    }
    tlb_flush(env_cpu(env));
    return RISCV_EXCP_NONE;
}

#define XJITDOMAIN_CSR(no, name) \
    { .csrno = no, .csr_ops = { name, xjitdomain, read_xjitdomain, \
                                write_xjitdomain } }

const RISCVCSR xjitdomain_csr_list[] = {
    XJITDOMAIN_CSR(CSR_DSTATUS, "dstatus"),
    XJITDOMAIN_CSR(CSR_DRIGHTS0, "drights0"),
    XJITDOMAIN_CSR(CSR_DRIGHTS1, "drights1"),
    XJITDOMAIN_CSR(CSR_DRIGHTS2, "drights2"),
    XJITDOMAIN_CSR(CSR_DTARGET, "dtarget"),
    XJITDOMAIN_CSR(CSR_DGATE, "dgate"),
    XJITDOMAIN_CSR(CSR_DSP, "dsp"),
    XJITDOMAIN_CSR(CSR_DSPBASE, "dspbase"),
    XJITDOMAIN_CSR(CSR_DCAUSE, "dcause"),
    XJITDOMAIN_CSR(CSR_MDSTATUS, "mdstatus"),
    { .csrno = CSR_MNDSTATUS,
      .csr_ops = { "mndstatus", xjitdomain_smrnmi, read_xjitdomain,
                   write_xjitdomain } },
    { .csrno = CSR_CURDOM,
      .csr_ops = { "curdom", xjitdomain, read_curdom } },
    { .csrno = CSR_UDSP,
      .csr_ops = { "udsp", xjitdomain_udsp, read_udsp, write_udsp } },
    { .csrno = CSR_DMPCFG0,
      .csr_ops = { "dmpcfg0", xjitdomain_dmpcfg, read_dmpcfg, write_dmpcfg } },
    { .csrno = CSR_DMPCFG1,
      .csr_ops = { "dmpcfg1", xjitdomain_dmpcfg, read_dmpcfg, write_dmpcfg } },
    { }
};
