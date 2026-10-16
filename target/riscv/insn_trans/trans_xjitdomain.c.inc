/*
 * RISC-V translation routines for the xjitdomain extension.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define REQUIRE_XJITDOMAIN(ctx) do {           \
    if (!ctx->cfg_ptr->ext_xjitdomain) {       \
        return false;                          \
    }                                          \
} while (0)

/*
 * Typed loads and stores: the base access, checked for the domain
 * dtarget[curdom] instead of curdom
 */
static bool gen_dom_load(DisasContext *ctx, arg_i *a, MemOp memop)
{
    REQUIRE_XJITDOMAIN(ctx);
    gen_dom_access(ctx, XJITDOMAIN_ACCESS_TYPED);
    gen_load(ctx, a, memop);
    gen_dom_access(ctx, XJITDOMAIN_ACCESS_ORDINARY);
    return true;
}

static bool gen_dom_store(DisasContext *ctx, arg_s *a, MemOp memop)
{
    REQUIRE_XJITDOMAIN(ctx);
    gen_dom_access(ctx, XJITDOMAIN_ACCESS_TYPED);
    gen_store(ctx, a, memop);
    gen_dom_access(ctx, XJITDOMAIN_ACCESS_ORDINARY);
    return true;
}

static bool trans_dlb(DisasContext *ctx, arg_dlb *a)
{
    return gen_dom_load(ctx, a, MO_SB);
}

static bool trans_dlh(DisasContext *ctx, arg_dlh *a)
{
    return gen_dom_load(ctx, a, MO_SW);
}

static bool trans_dlw(DisasContext *ctx, arg_dlw *a)
{
    return gen_dom_load(ctx, a, MO_SL);
}

static bool trans_dld(DisasContext *ctx, arg_dld *a)
{
    return gen_dom_load(ctx, a, MO_SQ);
}

static bool trans_dlbu(DisasContext *ctx, arg_dlbu *a)
{
    return gen_dom_load(ctx, a, MO_UB);
}

static bool trans_dlhu(DisasContext *ctx, arg_dlhu *a)
{
    return gen_dom_load(ctx, a, MO_UW);
}

static bool trans_dlwu(DisasContext *ctx, arg_dlwu *a)
{
    return gen_dom_load(ctx, a, MO_UL);
}

static bool trans_dsb(DisasContext *ctx, arg_dsb *a)
{
    return gen_dom_store(ctx, a, MO_SB);
}

static bool trans_dsh(DisasContext *ctx, arg_dsh *a)
{
    return gen_dom_store(ctx, a, MO_SW);
}

static bool trans_dsw(DisasContext *ctx, arg_dsw *a)
{
    return gen_dom_store(ctx, a, MO_SL);
}

static bool trans_dsd(DisasContext *ctx, arg_dsd *a)
{
    return gen_dom_store(ctx, a, MO_UQ);
}

/*
 * Domain transitions. domcall and domret jump, and all three may change the
 * pending entry that decides how the next TB starts, so each ends the TB.
 */
static bool trans_domcall(DisasContext *ctx, arg_domcall *a)
{
    REQUIRE_XJITDOMAIN(ctx);
#ifndef CONFIG_USER_ONLY
    TCGv target = tcg_temp_new();
    /* Not rd yet: a faulting domcall leaves rd unchanged */
    TCGv link = tcg_temp_new();

    decode_save_opc(ctx, 0);
    gen_pc_plus_diff(link, ctx, ctx->cur_insn_len);
    gen_helper_domcall(target, tcg_env, get_gpr(ctx, a->rs1, EXT_NONE),
                       tcg_constant_i32(a->dom), tcg_constant_i32(a->label),
                       link);
    gen_set_gpr(ctx, a->rd, link);
    tcg_gen_mov_tl(cpu_pc, target);
    lookup_and_goto_ptr(ctx);
    ctx->base.is_jmp = DISAS_NORETURN;
    return true;
#else
    return false;
#endif
}

static bool trans_domret(DisasContext *ctx, arg_domret *a)
{
    REQUIRE_XJITDOMAIN(ctx);
#ifndef CONFIG_USER_ONLY
    decode_save_opc(ctx, 0);
    gen_helper_domret(cpu_pc, tcg_env);
    lookup_and_goto_ptr(ctx);
    ctx->base.is_jmp = DISAS_NORETURN;
    return true;
#else
    return false;
#endif
}

/*
 * Outside a pending entry, domlpad is a no-op. With one pending, a 4-byte
 * aligned domlpad completes it if the domain and label match; anything
 * else leaves dpend_expected set, and riscv_tr_translate_insn() raises the
 * LPAD fault.
 */
static bool trans_domlpad(DisasContext *ctx, arg_domlpad *a)
{
    REQUIRE_XJITDOMAIN(ctx);
#ifndef CONFIG_USER_ONLY
    if (!ctx->dpend_expected || (ctx->base.pc_next & 3)) {
        return true;
    }
    ctx->dpend_expected = false;
    decode_save_opc(ctx, 0);
    gen_helper_domlpad(tcg_env, tcg_constant_i32(a->dom),
                       tcg_constant_i32(a->label));
    gen_update_pc(ctx, ctx->cur_insn_len);
    lookup_and_goto_ptr(ctx);
    ctx->base.is_jmp = DISAS_NORETURN;
#endif
    return true;
}
