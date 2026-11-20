/*
 * JITDomain (xjitdomain) user ABI for linux-user.
 *
 * EN, the matrices and the allocated keys belong to the process. Each
 * thread runs with a copy of the matrices in its env, refreshed from the
 * process copy when it returns to the guest after a change, as a kernel
 * would load them on its next return to U mode.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/atomic.h"
#include "qemu/units.h"
#include "qemu/rcu.h"
#include "qemu/thread.h"
#include "qemu.h"
#include "user-internals.h"
#include "user-mmap.h"
#include "user/page-protection.h"
#include "exec/page-protection.h"
#include "exec/mmap-lock.h"
#include "jitdomain.h"

/* Key of the DRS pages, never handed out by pkey_alloc */
#define JITDOMAIN_DRSKEY        7
#define JITDOMAIN_FIRST_KEY     1
/* DRS_ALLOC with size 0: 8192 records */
#define JITDOMAIN_DRS_DEFAULT   (64 * KiB)

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
/* Keys handed out by pkey_alloc, one bit per key; guarded by mmap_lock */
static unsigned jitdomain_keys;

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

/* Page flags for a key */
static int jitdomain_key_flags(unsigned key)
{
    return key << ctz32(PAGE_DOMKEY);
}

static bool jitdomain_is_enabled(void)
{
    bool enabled;

    qemu_mutex_lock(&jitdomain_lock);
    enabled = jitdomain_enabled;
    qemu_mutex_unlock(&jitdomain_lock);
    return enabled;
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

/*
 * A DRS for the calling thread: size bytes rounded up to pages, with the
 * DRS key, between two PROT_NONE guard pages, so that an overflow or an
 * underflow is a plain SIGSEGV/SEGV_ACCERR. Being mapped, the guard pages
 * are never handed out by a later mmap. dsp and dspbase start at the top.
 */
static abi_long jitdomain_drs_alloc(CPUArchState *env, abi_ulong size)
{
    TaskState *ts = get_task_state(env_cpu(env));
    abi_ulong guard = TARGET_PAGE_SIZE;
    abi_long base, ret;

    if (!jitdomain_is_enabled()) {
        return -TARGET_EINVAL;
    }
    if (ts->drs_size) {
        return -TARGET_EBUSY;
    }
    if (!size) {
        size = JITDOMAIN_DRS_DEFAULT;
    }
    if (size > (abi_ulong)-1 - 3 * guard) {
        return -TARGET_ENOMEM;
    }
    size = TARGET_PAGE_ALIGN(size);

    mmap_lock();
    base = target_mmap(0, size + 2 * guard, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == -1) {
        ret = get_errno(base);
        mmap_unlock();
        return ret;
    }
    target_mprotect(base, guard, PROT_NONE);
    target_mprotect(base + guard + size, guard, PROT_NONE);
    base += guard;
    page_set_flags(base, base + size - 1,
                   jitdomain_key_flags(JITDOMAIN_DRSKEY), PAGE_DOMKEY);
    mmap_unlock();

    ts->drs_base = base;
    ts->drs_size = size;
    env->dsp = base + size;
    env->dspbase = base + size;
    return 0;
}

/* A guard page the thread has left as it was */
static void jitdomain_drs_free_guard(abi_ulong p)
{
    int flags = page_get_flags(p);

    if ((flags & PAGE_VALID) && !(flags & (PAGE_RWX | PAGE_DOMKEY))) {
        target_munmap(p, TARGET_PAGE_SIZE);
    }
}

/*
 * The pages of the DRS that still carry the DRS key, and the guard pages
 * still PROT_NONE: the thread may have unmapped the rest, and something
 * else may be mapped there now.
 */
void jitdomain_drs_free(TaskState *ts)
{
    abi_ulong end = ts->drs_base + ts->drs_size;
    abi_ulong run = 0;
    bool in_run = false;

    if (!ts->drs_size) {
        return;
    }
    mmap_lock();
    jitdomain_drs_free_guard(ts->drs_base - TARGET_PAGE_SIZE);
    jitdomain_drs_free_guard(end);
    for (abi_ulong p = ts->drs_base; p < end; p += TARGET_PAGE_SIZE) {
        bool drs = (page_get_flags(p) & (PAGE_VALID | PAGE_DOMKEY)) ==
                   (PAGE_VALID | jitdomain_key_flags(JITDOMAIN_DRSKEY));

        if (drs && !in_run) {
            run = p;
            in_run = true;
        } else if (!drs && in_run) {
            target_munmap(run, p - run);
            in_run = false;
        }
    }
    if (in_run) {
        target_munmap(run, end - run);
    }
    mmap_unlock();
    ts->drs_size = 0;
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
    case PR_JITDOMAIN_DRS_ALLOC:
        if (arg4 || arg5) {
            return -TARGET_EINVAL;
        }
        return jitdomain_drs_alloc(env, arg3);
    default:
        return -TARGET_EINVAL;
    }
}

/* The lowest free key in 1-6 */
abi_long do_riscv_pkey_alloc(abi_ulong flags, abi_ulong init_rights)
{
    abi_long ret = -TARGET_ENOSPC;

    if (!jitdomain_is_enabled() || flags || init_rights) {
        return -TARGET_EINVAL;
    }
    mmap_lock();
    for (int k = JITDOMAIN_FIRST_KEY; k < JITDOMAIN_DRSKEY; k++) {
        if (!(jitdomain_keys & (1u << k))) {
            jitdomain_keys |= 1u << k;
            ret = k;
            break;
        }
    }
    mmap_unlock();
    return ret;
}

/* Pages that still carry the key keep it, as with Linux pkeys */
abi_long do_riscv_pkey_free(abi_long key)
{
    abi_long ret = -TARGET_EINVAL;

    if (!jitdomain_is_enabled()) {
        return -TARGET_EINVAL;
    }
    mmap_lock();
    if (key >= JITDOMAIN_FIRST_KEY && key < JITDOMAIN_DRSKEY &&
        (jitdomain_keys & (1u << key))) {
        jitdomain_keys &= ~(1u << key);
        ret = 0;
    }
    mmap_unlock();
    return ret;
}

typedef struct JitDomainRange {
    abi_ulong start, last;
} JitDomainRange;

static int jitdomain_find_drs(void *priv, vaddr start, vaddr end, int flags)
{
    JitDomainRange *r = priv;

    return start <= r->last && end - 1 >= r->start &&
           (flags & PAGE_DOMKEY) == jitdomain_key_flags(JITDOMAIN_DRSKEY);
}

/*
 * mprotect, then tag the pages with key. Key -1 leaves the keys alone, as
 * in Linux; key 0 is always allocated. DRS pages cannot be retagged.
 */
abi_long do_riscv_pkey_mprotect(abi_ulong start, abi_ulong len,
                                abi_ulong prot, abi_long key)
{
    JitDomainRange r = { start, start + TARGET_PAGE_ALIGN(len) - 1 };
    abi_long ret;

    if (!jitdomain_is_enabled()) {
        return -TARGET_EINVAL;
    }
    mmap_lock();
    if (key != -1 &&
        (key < 0 || key >= JITDOMAIN_DRSKEY ||
         (key > 0 && !(jitdomain_keys & (1u << key))))) {
        ret = -TARGET_EINVAL;
        goto out;
    }
    if (len && r.last >= r.start &&
        walk_memory_regions(&r, jitdomain_find_drs)) {
        ret = -TARGET_EINVAL;
        goto out;
    }
    ret = target_mprotect(start, len, prot);
    if (ret == 0 && len && key != -1) {
        page_set_flags(r.start, r.last, jitdomain_key_flags(key),
                       PAGE_DOMKEY);
    }
out:
    mmap_unlock();
    return ret;
}
