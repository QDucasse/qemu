/*
 * JITDomain (xjitdomain) user ABI for linux-user: the PR_RISCV_JITDOMAIN
 * prctl.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef RISCV_JITDOMAIN_H
#define RISCV_JITDOMAIN_H

#define PR_RISCV_JITDOMAIN              0x4A444F4D  /* "JDOM" */
#define PR_JITDOMAIN_ENABLE             1
#define PR_JITDOMAIN_SET_MATRICES       2
#define PR_JITDOMAIN_GET_MATRICES       3
#define PR_JITDOMAIN_DRS_ALLOC          4

abi_long do_prctl_riscv_jitdomain(CPUArchState *env, abi_ulong op,
                                  abi_ulong arg3, abi_ulong arg4,
                                  abi_ulong arg5);
/* Load the process's EN and matrices into env if they changed */
void jitdomain_sync(CPUArchState *env);

#endif /* RISCV_JITDOMAIN_H */
