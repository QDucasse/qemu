/*
 * JITDomain (xjitdomain) user ABI for linux-user.
 *
 * EN and the matrices belong to the process. Each
 * thread runs with a copy of the matrices in its env, refreshed from the
 * process copy when it returns to the guest after a change, as a kernel
 * would load them on its next return to U mode.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/atomic.h"
#include "qemu/rcu.h"
#include "qemu/thread.h"
#include "qemu.h"
#include "user-internals.h"
#include "jitdomain.h"

/* Key of the DRS pages */
#define JITDOMAIN_DRSKEY        7

typedef struct JitDomainMatrices {
    uint64_t drights[3];
    uint64_t dtarget;
    uint64_t dgate;
} JitDomainMatrices;

static QemuMutex jitdomain_lock;
static bool jitdomain_enabled;
static JitDomainMatrices jitdomain_matrices;
/* Bumped on every change of the process state, read without the lock */
static uint64_t jitdomain_gen;
/* The generation this thread's env holds */
static __thread uint64_t jitdomain_seen_gen;

static void __attribute__((constructor)) jitdomain_init(void)
{
    qemu_mutex_init(&jitdomain_lock);
}

/* drights entry {X, W, R} of domain d on key k */
static unsigned jitdomain_rights(const JitDomainMatrices *m, unsigned d,
                                 unsigned k)
{
    unsigned rights = 0;

    for (unsigned b = 0; b < 3; b++) {
        unsigned bit = 3 * (JITDOMAIN_NDOMS * d + k) + b;
        rights |= ((m->drights[bit / 64] >> (bit % 64)) & 1) << b;
    }
    return rights;
}

void jitdomain_sync(CPUArchState *env)
{
    if (likely(qatomic_read(&jitdomain_gen) == jitdomain_seen_gen)) {
        return;
    }
    qemu_mutex_lock(&jitdomain_lock);
    if (jitdomain_enabled) {
        env->dstatus |= DSTATUS_EN;
        env->dstatus = set_field(env->dstatus, DSTATUS_DRSKEY,
                                 JITDOMAIN_DRSKEY);
        memcpy(env->drights, jitdomain_matrices.drights,
               sizeof(env->drights));
        env->dtarget = jitdomain_matrices.dtarget;
        env->dgate = jitdomain_matrices.dgate;
    }
    jitdomain_seen_gen = jitdomain_gen;
    qemu_mutex_unlock(&jitdomain_lock);
}

/*
 * After a change of the process state: the caller takes it at once, the
 * other threads at their next return to the guest, which cpu_exit() brings
 * forward.
 */
static void jitdomain_publish(CPUArchState *env)
{
    CPUState *self = env_cpu(env), *cpu;

    jitdomain_sync(env);
    WITH_RCU_READ_LOCK_GUARD() {
        CPU_FOREACH(cpu) {
            if (cpu != self) {
                cpu_exit(cpu);
            }
        }
    }
}

/* Called with jitdomain_lock held */
static void jitdomain_bump_gen(void)
{
    qatomic_set(&jitdomain_gen, jitdomain_gen + 1);
}

/*
 * DOM0 gets RWX on keys 0-6, the other domains nothing: the reset values
 * would not even let DOM0 fetch its own code.
 */
static abi_long jitdomain_enable(CPUArchState *env)
{
    if (!riscv_cpu_cfg(env)->ext_xjitdomain) {
        return -TARGET_EINVAL;
    }
    qemu_mutex_lock(&jitdomain_lock);
    if (jitdomain_enabled) {
        qemu_mutex_unlock(&jitdomain_lock);
        return 0;
    }
    jitdomain_enabled = true;
    memset(&jitdomain_matrices, 0, sizeof(jitdomain_matrices));
    jitdomain_matrices.drights[0] =
        MAKE_64BIT_MASK(0, 3 * JITDOMAIN_DRSKEY);
    jitdomain_matrices.dtarget = xjitdomain_dtarget_identity();
    jitdomain_bump_gen();
    qemu_mutex_unlock(&jitdomain_lock);
    jitdomain_publish(env);
    return 0;
}

static abi_long jitdomain_set_matrices(CPUArchState *env, abi_ulong addr)
{
    JitDomainMatrices m;

    for (int i = 0; i < 3; i++) {
        if (get_user_u64(m.drights[i], addr + 8 * i)) {
            return -TARGET_EFAULT;
        }
    }
    if (get_user_u64(m.dtarget, addr + 24) ||
        get_user_u64(m.dgate, addr + 32)) {
        return -TARGET_EFAULT;
    }

    /* No domain may get a right on the DRS key */
    for (unsigned d = 0; d < JITDOMAIN_NDOMS; d++) {
        if (jitdomain_rights(&m, d, JITDOMAIN_DRSKEY)) {
            return -TARGET_EINVAL;
        }
    }
    if (m.dtarget & ~MAKE_64BIT_MASK(0, 3 * JITDOMAIN_NDOMS)) {
        return -TARGET_EINVAL;
    }

    qemu_mutex_lock(&jitdomain_lock);
    if (!jitdomain_enabled) {
        qemu_mutex_unlock(&jitdomain_lock);
        return -TARGET_EINVAL;
    }
    jitdomain_matrices = m;
    jitdomain_bump_gen();
    qemu_mutex_unlock(&jitdomain_lock);
    jitdomain_publish(env);
    return 0;
}

/* Before ENABLE, the reset values */
static abi_long jitdomain_get_matrices(CPUArchState *env, abi_ulong addr)
{
    JitDomainMatrices m = { .dtarget = xjitdomain_dtarget_identity() };

    qemu_mutex_lock(&jitdomain_lock);
    if (jitdomain_enabled) {
        m = jitdomain_matrices;
    }
    qemu_mutex_unlock(&jitdomain_lock);

    for (int i = 0; i < 3; i++) {
        if (put_user_u64(m.drights[i], addr + 8 * i)) {
            return -TARGET_EFAULT;
        }
    }
    if (put_user_u64(m.dtarget, addr + 24) ||
        put_user_u64(m.dgate, addr + 32)) {
        return -TARGET_EFAULT;
    }
    return 0;
}

abi_long do_prctl_riscv_jitdomain(CPUArchState *env, abi_ulong op,
                                  abi_ulong arg3, abi_ulong arg4,
                                  abi_ulong arg5)
{
    switch (op) {
    case PR_JITDOMAIN_ENABLE:
        if (arg3 || arg4 || arg5) {
            return -TARGET_EINVAL;
        }
        return jitdomain_enable(env);
    case PR_JITDOMAIN_SET_MATRICES:
        if (arg4 || arg5) {
            return -TARGET_EINVAL;
        }
        return jitdomain_set_matrices(env, arg3);
    case PR_JITDOMAIN_GET_MATRICES:
        if (arg4 || arg5) {
            return -TARGET_EINVAL;
        }
        return jitdomain_get_matrices(env, arg3);
    default:
        return -TARGET_EINVAL;
    }
}
