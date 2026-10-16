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
