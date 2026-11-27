#ifndef NODE_CERT_H
#define NODE_CERT_H

#include "flow_ir_builder.h"
#include "flow_ir_io.h"
#include "flow_wire_pack.h"
#include "node.h"

#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef flow_ir_builder_ws_t node_cert_ws_t;

typedef struct {
    size_t legacy_fir1_bytes;
    size_t packed_fir2_bytes;
} node_cert_size_stats_t;

static inline bool node_cert_progs_equal(const flow_ir_prog_t *a, const flow_ir_prog_t *b) {
    if (a == NULL || b == NULL) {
        return false;
    }
    if (a->mult != b->mult || a->flags != b->flags || a->num_vals != b->num_vals ||
        a->num_inputs != b->num_inputs || a->num_outputs != b->num_outputs ||
        a->num_ops != b->num_ops || a->num_lut_u64 != b->num_lut_u64) {
        return false;
    }
    if (strncmp(a->name, b->name, sizeof(a->name)) != 0) {
        return false;
    }
    for (uint32_t i = 0U; i < a->num_vals; ++i) {
        if (a->vals[i].width != b->vals[i].width ||
            a->vals[i].is_classical != b->vals[i].is_classical ||
            strncmp(a->vals[i].name, b->vals[i].name, sizeof(a->vals[i].name)) != 0) {
            return false;
        }
    }
    for (uint32_t i = 0U; i < a->num_inputs; ++i) {
        if (a->inputs[i] != b->inputs[i]) {
            return false;
        }
    }
    for (uint32_t i = 0U; i < a->num_outputs; ++i) {
        if (a->outputs[i] != b->outputs[i]) {
            return false;
        }
    }
    for (uint32_t i = 0U; i < a->num_ops; ++i) {
        const flow_ir_op_t *oa = &a->ops[i];
        const flow_ir_op_t *ob = &b->ops[i];
        if (oa->kind != ob->kind || oa->num_ins != ob->num_ins || oa->out_val != ob->out_val ||
            oa->lut_off != ob->lut_off || oa->lut_len != ob->lut_len || oa->p0 != ob->p0 ||
            oa->p1 != ob->p1 || oa->p2 != ob->p2 || oa->p3 != ob->p3) {
            return false;
        }
        for (uint16_t k = 0U; k < oa->num_ins && k < FLOW_IR_MAX_INS; ++k) {
            if (oa->ins[k] != ob->ins[k]) {
                return false;
            }
        }
    }
    for (uint32_t i = 0U; i < a->num_lut_u64; ++i) {
        if (a->lut_pool[i] != b->lut_pool[i]) {
            return false;
        }
    }
    return true;
}

static inline bool node_cert_load_auto_bytes(flow_ir_prog_t *out, const uint8_t *buf, size_t len) {
    /* flow_ir_load_bytes_fiber transparently decodes both legacy "FIR1" and packed "FIR2". */
    return flow_ir_load_bytes_fiber(out, buf, len) == FLOW_IR_FIBER_COMMITTED;
}

static inline bool node_cert_load_auto_file(flow_ir_prog_t *out, const char *path,
                                            uint8_t *scratch_buf, size_t scratch_cap) {
    return flow_ir_load_file(out, path, scratch_buf, scratch_cap);
}

static inline bool node_cert_seal_cartesian_fir2(node_cert_ws_t *ws, const char *out_fir_path,
                                                 node_cert_size_stats_t *stats) {
    static uint8_t fir1_buf[FLOW_IR_MAX_FILE_BYTES];
    static uint8_t rt_buf[FLOW_IR_MAX_FILE_BYTES];
    static flow_ir_prog_t legacy_reloaded;
    if (ws == NULL || out_fir_path == NULL) {
        return false;
    }
    ws->ir_prog.mult = FLOW_IR_MULT_CARTESIAN;
    ws->ir_prog.flags = FLOW_IR_FLAG_CLEAN;

    size_t fir1_len = 0U;
    if (!flow_ir_encode_bytes(&ws->ir_prog, fir1_buf, sizeof(fir1_buf), &fir1_len)) {
        return false;
    }
    if (!flow_ir_encode_packed_bytes(&ws->ir_prog, ws->wire_buf, sizeof(ws->wire_buf),
                                     &ws->wire_len)) {
        return false;
    }
    if (!node_cert_load_auto_bytes(&ws->ir_reloaded, ws->wire_buf, ws->wire_len)) {
        return false;
    }
    if (!node_cert_progs_equal(&ws->ir_prog, &ws->ir_reloaded)) {
        return false;
    }
    size_t rt_len = 0U;
    if (!flow_ir_encode_packed_bytes(&ws->ir_reloaded, rt_buf, sizeof(rt_buf), &rt_len) ||
        rt_len != ws->wire_len || memcmp(rt_buf, ws->wire_buf, ws->wire_len) != 0) {
        return false;
    }
    if (!node_cert_load_auto_bytes(&legacy_reloaded, fir1_buf, fir1_len) ||
        !node_cert_progs_equal(&ws->ir_prog, &legacy_reloaded)) {
        return false;
    }
    if (!flow_ir_encode_bytes(&ws->ir_reloaded, rt_buf, sizeof(rt_buf), &rt_len) ||
        rt_len != fir1_len || memcmp(rt_buf, fir1_buf, fir1_len) != 0) {
        return false;
    }
    if (stats != NULL) {
        stats->legacy_fir1_bytes = fir1_len;
        stats->packed_fir2_bytes = ws->wire_len;
    }
    return flow_ir_write_bytes_file(out_fir_path, ws->wire_buf, ws->wire_len);
}

static inline bool node_cert_seal_cartesian_fir(node_cert_ws_t *ws, const char *out_fir_path) {
    return node_cert_seal_cartesian_fir2(ws, out_fir_path, NULL);
}

static inline uint32_t node_cert_emit_concat2(flow_ir_prog_t *p, uint16_t width, uint32_t lo,
                                              uint32_t hi, const char *name) {
    return flow_ir_emit_op2(p, FLOW_IR_OP_CONCAT, width, lo, hi, name);
}

static inline uint32_t node_cert_or2(flow_ir_prog_t *p, uint32_t a, uint32_t b, uint32_t one1,
                                     const char *name) {
    uint32_t na = flow_ir_emit_op1(p, FLOW_IR_OP_NOT_VEC, 1U, a, 0ULL, "na");
    uint32_t nb = flow_ir_emit_op1(p, FLOW_IR_OP_NOT_VEC, 1U, b, 0ULL, "nb");
    uint32_t nab = flow_ir_emit_op2(p, FLOW_IR_OP_AND_VEC, 1U, na, nb, "nab");
    uint32_t res = flow_ir_emit_op1(p, FLOW_IR_OP_NOT_VEC, 1U, nab, 0ULL, name);
    (void)one1;
    return res;
}

static inline uint32_t node_cert_mul4_mod16(flow_ir_prog_t *p, uint32_t x, uint32_t y,
                                            uint32_t zero4, uint32_t zero1, uint32_t zero2,
                                            uint32_t zero3, const char *name) {
    uint32_t b0 = flow_ir_emit_op1(p, FLOW_IR_OP_SLICE, 1U, y, 0ULL, "mb0");
    uint32_t b1 = flow_ir_emit_op1(p, FLOW_IR_OP_SLICE, 1U, y, 1ULL, "mb1");
    uint32_t b2 = flow_ir_emit_op1(p, FLOW_IR_OP_SLICE, 1U, y, 2ULL, "mb2");
    uint32_t b3 = flow_ir_emit_op1(p, FLOW_IR_OP_SLICE, 1U, y, 3ULL, "mb3");

    uint32_t pp0 = flow_ir_emit_sel(p, 4U, b0, zero4, x, "pp0");

    uint32_t s1 = flow_ir_emit_sel(p, 4U, b1, zero4, x, "s1");
    uint32_t s1_lo = flow_ir_emit_op1(p, FLOW_IR_OP_SLICE, 3U, s1, 0ULL, "s1lo");
    uint32_t pp1 = node_cert_emit_concat2(p, 4U, zero1, s1_lo, "pp1");

    uint32_t s2 = flow_ir_emit_sel(p, 4U, b2, zero4, x, "s2");
    uint32_t s2_lo = flow_ir_emit_op1(p, FLOW_IR_OP_SLICE, 2U, s2, 0ULL, "s2lo");
    uint32_t pp2 = node_cert_emit_concat2(p, 4U, zero2, s2_lo, "pp2");

    uint32_t s3 = flow_ir_emit_sel(p, 4U, b3, zero4, x, "s3");
    uint32_t s3_lo = flow_ir_emit_op1(p, FLOW_IR_OP_SLICE, 1U, s3, 0ULL, "s3lo");
    uint32_t pp3 = node_cert_emit_concat2(p, 4U, zero3, s3_lo, "pp3");

    uint32_t a01 = flow_ir_emit_op2(p, FLOW_IR_OP_ADD, 4U, pp0, pp1, "m01");
    uint32_t a23 = flow_ir_emit_op2(p, FLOW_IR_OP_ADD, 4U, pp2, pp3, "m23");
    return flow_ir_emit_op2(p, FLOW_IR_OP_ADD, 4U, a01, a23, name);
}

/* ============================================================================
 * 1. Layer 1 Cert: Capability Attenuation Non-Escalation (`cap_isolation`)
 * ============================================================================ */

static inline bool node_cert_emit_cap_fir(node_cert_ws_t *ws, const char *out_fir_path) {
    if (ws == NULL || out_fir_path == NULL) {
        return false;
    }
    flow_ir_builder_init(ws, "node_cap_isolation");
    flow_ir_prog_t *p = &ws->ir_prog;
    p->num_inputs = 1U;
    p->inputs[0] = 0U;
    p->vals[0].width = 16U;
    p->vals[0].is_classical = 1U;
    (void)snprintf(p->vals[0].name, sizeof(p->vals[0].name), "cap_pair16");
    p->num_vals = 1U;

    uint32_t p_rights = flow_ir_emit_op1(p, FLOW_IR_OP_SLICE, 4U, 0U, 0ULL, "p_rights");
    uint32_t c_rights = flow_ir_emit_op1(p, FLOW_IR_OP_SLICE, 4U, 0U, 4ULL, "c_rights");
    uint32_t p_end = flow_ir_emit_op1(p, FLOW_IR_OP_SLICE, 4U, 0U, 8ULL, "p_end");
    uint32_t c_end = flow_ir_emit_op1(p, FLOW_IR_OP_SLICE, 4U, 0U, 12ULL, "c_end");

    uint32_t zero1 = flow_ir_emit_const(p, 1U, 0ULL, "z1");
    uint32_t one1 = flow_ir_emit_const(p, 1U, 1ULL, "o1");

    uint32_t grant_ok = flow_ir_emit_op1(p, FLOW_IR_OP_SLICE, 1U, p_rights, 3ULL, "grant_ok");
    uint32_t np_rights = flow_ir_emit_op1(p, FLOW_IR_OP_NOT_VEC, 4U, p_rights, 0ULL, "np_r");
    uint32_t r_diff = flow_ir_emit_op2(p, FLOW_IR_OP_AND_VEC, 4U, c_rights, np_rights, "r_diff");
    uint32_t rights_ok = flow_ir_emit_op1(p, FLOW_IR_OP_EQ_ZERO, 1U, r_diff, 0ULL, "r_ok");
    uint32_t r_bad = flow_ir_emit_op1(p, FLOW_IR_OP_OR_REDUCE, 1U, r_diff, 0ULL, "r_bad");

    uint32_t p_end5 = node_cert_emit_concat2(p, 5U, p_end, zero1, "p_end5");
    uint32_t c_end5 = node_cert_emit_concat2(p, 5U, c_end, zero1, "c_end5");
    uint32_t diff5 = flow_ir_emit_op2(p, FLOW_IR_OP_SUB, 5U, p_end5, c_end5, "diff5");
    uint32_t c_gt_p = flow_ir_emit_op1(p, FLOW_IR_OP_SLICE, 1U, diff5, 4ULL, "c_gt_p");
    uint32_t end_ok = flow_ir_emit_op1(p, FLOW_IR_OP_NOT_VEC, 1U, c_gt_p, 0ULL, "end_ok");

    uint32_t allowed0 = flow_ir_emit_op2(p, FLOW_IR_OP_AND_VEC, 1U, grant_ok, rights_ok, "allow0");
    uint32_t allowed = flow_ir_emit_op2(p, FLOW_IR_OP_AND_VEC, 1U, allowed0, end_ok, "allowed");
    uint32_t bad = node_cert_or2(p, r_bad, c_gt_p, one1, "bad_att");
    uint32_t viol = flow_ir_emit_op2(p, FLOW_IR_OP_AND_VEC, 1U, allowed, bad, "viol");

    p->num_outputs = 1U;
    p->outputs[0] = viol;
    return node_cert_seal_cartesian_fir(ws, out_fir_path);
}

static inline bool node_cert_emit_cap_lean(const char *path) {
    FILE *fp = fopen(path, "wb");
    if (fp == NULL) {
        return false;
    }
    fprintf(fp, "import Node.Theory\n\n");
    fprintf(fp, "namespace Node.CertCapIsolation\n\n");
    fprintf(fp, "open Node.Sandbox\n\n");
    fprintf(
        fp,
        "def parentCap : Cap := { regionId := 0, base := 0, len := 64, rights := ⟨true, true, false, true⟩ }\n");
    fprintf(fp, "def roChild : Rights := ⟨true, false, false, false⟩\n\n");
    fprintf(fp, "theorem witness_attenuate_preserves_bounds (c' : Cap)\n");
    fprintf(fp, "    (h : attenuateCap parentCap 8 16 roChild = some c') :\n");
    fprintf(
        fp,
        "    parentCap.base ≤ c'.base ∧ c'.base + c'.len ≤ parentCap.base + parentCap.len :=\n");
    fprintf(fp, "  attenuate_subset_bounds h\n\n");
    fprintf(fp, "theorem witness_attenuate_non_escalation (c' : Cap)\n");
    fprintf(fp, "    (h : attenuateCap parentCap 8 16 roChild = some c') :\n");
    fprintf(fp, "    subRights c'.rights parentCap.rights :=\n");
    fprintf(fp, "  attenuate_subset_rights h\n\n");
    fprintf(fp, "end Node.CertCapIsolation\n");
    return fclose(fp) == 0;
}

/* ============================================================================
 * 2. Layer 3 Cert: BFT 3f+1 Quorum Safety & Buggy Quorum Witness
 * ============================================================================ */

static inline uint32_t node_cert_pop4(flow_ir_prog_t *p, uint32_t v4, uint32_t zero2) {
    uint32_t b0 = flow_ir_emit_op1(p, FLOW_IR_OP_SLICE, 1U, v4, 0ULL, "pb0");
    uint32_t b1 = flow_ir_emit_op1(p, FLOW_IR_OP_SLICE, 1U, v4, 1ULL, "pb1");
    uint32_t b2 = flow_ir_emit_op1(p, FLOW_IR_OP_SLICE, 1U, v4, 2ULL, "pb2");
    uint32_t b3 = flow_ir_emit_op1(p, FLOW_IR_OP_SLICE, 1U, v4, 3ULL, "pb3");
    uint32_t e0 = node_cert_emit_concat2(p, 3U, b0, zero2, "pe0");
    uint32_t e1 = node_cert_emit_concat2(p, 3U, b1, zero2, "pe1");
    uint32_t e2 = node_cert_emit_concat2(p, 3U, b2, zero2, "pe2");
    uint32_t e3 = node_cert_emit_concat2(p, 3U, b3, zero2, "pe3");
    uint32_t s01 = flow_ir_emit_op2(p, FLOW_IR_OP_ADD, 3U, e0, e1, "ps01");
    uint32_t s23 = flow_ir_emit_op2(p, FLOW_IR_OP_ADD, 3U, e2, e3, "ps23");
    return flow_ir_emit_op2(p, FLOW_IR_OP_ADD, 3U, s01, s23, "pop4");
}

static inline bool node_cert_emit_bft_fir(node_cert_ws_t *ws, const char *out_fir_path,
                                          bool buggy_quorum2) {
    if (ws == NULL || out_fir_path == NULL) {
        return false;
    }
    flow_ir_builder_init(ws, buggy_quorum2 ? "node_bft_buggy" : "node_bft_safe");
    flow_ir_prog_t *p = &ws->ir_prog;
    p->num_inputs = 1U;
    p->inputs[0] = 0U;
    p->vals[0].width = 12U;
    p->vals[0].is_classical = 1U;
    (void)snprintf(p->vals[0].name, sizeof(p->vals[0].name), "quorum_tri12");
    p->num_vals = 1U;

    uint32_t q1 = flow_ir_emit_op1(p, FLOW_IR_OP_SLICE, 4U, 0U, 0ULL, "q1");
    uint32_t q2 = flow_ir_emit_op1(p, FLOW_IR_OP_SLICE, 4U, 0U, 4ULL, "q2");
    uint32_t byz = flow_ir_emit_op1(p, FLOW_IR_OP_SLICE, 4U, 0U, 8ULL, "byz");
    uint32_t zero2 = flow_ir_emit_const(p, 2U, 0ULL, "z2");
    uint32_t one1 = flow_ir_emit_const(p, 1U, 1ULL, "o1");

    uint32_t pop1 = node_cert_pop4(p, q1, zero2);
    uint32_t pop2 = node_cert_pop4(p, q2, zero2);
    uint32_t popb = node_cert_pop4(p, byz, zero2);

    uint32_t q1_p1 = flow_ir_emit_op1(p, FLOW_IR_OP_SLICE, 1U, pop1, 1ULL, "q1_p1");
    uint32_t q1_p2 = flow_ir_emit_op1(p, FLOW_IR_OP_SLICE, 1U, pop1, 2ULL, "q1_p2");
    uint32_t q2_p1 = flow_ir_emit_op1(p, FLOW_IR_OP_SLICE, 1U, pop2, 1ULL, "q2_p1");
    uint32_t q2_p2 = flow_ir_emit_op1(p, FLOW_IR_OP_SLICE, 1U, pop2, 2ULL, "q2_p2");

    uint32_t q1_ok = UINT32_MAX;
    uint32_t q2_ok = UINT32_MAX;
    if (buggy_quorum2) {
        q1_ok = node_cert_or2(p, q1_p2, q1_p1, one1, "q1_ge2");
        q2_ok = node_cert_or2(p, q2_p2, q2_p1, one1, "q2_ge2");
    } else {
        uint32_t q1_p0 = flow_ir_emit_op1(p, FLOW_IR_OP_SLICE, 1U, pop1, 0ULL, "q1_p0");
        uint32_t q2_p0 = flow_ir_emit_op1(p, FLOW_IR_OP_SLICE, 1U, pop2, 0ULL, "q2_p0");
        uint32_t q1_10 = flow_ir_emit_op2(p, FLOW_IR_OP_AND_VEC, 1U, q1_p1, q1_p0, "q1_10");
        uint32_t q2_10 = flow_ir_emit_op2(p, FLOW_IR_OP_AND_VEC, 1U, q2_p1, q2_p0, "q2_10");
        q1_ok = node_cert_or2(p, q1_p2, q1_10, one1, "q1_ge3");
        q2_ok = node_cert_or2(p, q2_p2, q2_10, one1, "q2_ge3");
    }

    uint32_t qb_p1 = flow_ir_emit_op1(p, FLOW_IR_OP_SLICE, 1U, popb, 1ULL, "qb_p1");
    uint32_t qb_p2 = flow_ir_emit_op1(p, FLOW_IR_OP_SLICE, 1U, popb, 2ULL, "qb_p2");
    uint32_t byz_ge2 = node_cert_or2(p, qb_p2, qb_p1, one1, "byz_ge2");
    uint32_t byz_ok = flow_ir_emit_op1(p, FLOW_IR_OP_NOT_VEC, 1U, byz_ge2, 0ULL, "byz_le1");

    uint32_t q12 = flow_ir_emit_op2(p, FLOW_IR_OP_AND_VEC, 4U, q1, q2, "q12");
    uint32_t nbyz = flow_ir_emit_op1(p, FLOW_IR_OP_NOT_VEC, 4U, byz, 0ULL, "nbyz");
    uint32_t hon_int = flow_ir_emit_op2(p, FLOW_IR_OP_AND_VEC, 4U, q12, nbyz, "hon_int");
    uint32_t no_honest = flow_ir_emit_op1(p, FLOW_IR_OP_EQ_ZERO, 1U, hon_int, 0ULL, "no_honest");

    uint32_t qs_ok = flow_ir_emit_op2(p, FLOW_IR_OP_AND_VEC, 1U, q1_ok, q2_ok, "qs_ok");
    uint32_t pre_ok = flow_ir_emit_op2(p, FLOW_IR_OP_AND_VEC, 1U, qs_ok, byz_ok, "pre_ok");
    uint32_t viol = flow_ir_emit_op2(p, FLOW_IR_OP_AND_VEC, 1U, pre_ok, no_honest, "viol");

    p->num_outputs = 1U;
    p->outputs[0] = viol;
    return node_cert_seal_cartesian_fir(ws, out_fir_path);
}

static inline bool node_cert_emit_bft_lean(const char *path) {
    FILE *fp = fopen(path, "wb");
    if (fp == NULL) {
        return false;
    }
    fprintf(fp, "import Node.Theory\n\n");
    fprintf(fp, "namespace Node.CertBftQuorum\n\n");
    fprintf(fp, "open Node.Consensus Node.Dst\n\n");
    fprintf(fp, "theorem witness_n4_f1_honest_intersection (q1 q2 byz : Nat → Bool)\n");
    fprintf(fp, "    (hq1 : 3 ≤ countPred 4 q1) (hq2 : 3 ≤ countPred 4 q2)\n");
    fprintf(fp, "    (hb : countPred 4 byz ≤ 1) :\n");
    fprintf(fp, "    ∃ i, i < 4 ∧ q1 i = true ∧ q2 i = true ∧ byz i = false :=\n");
    fprintf(fp, "  dst_bft_valid_quorum_nogo_witness q1 q2 byz hq1 hq2 hb\n\n");
    fprintf(fp, "end Node.CertBftQuorum\n");
    return fclose(fp) == 0;
}

/* ============================================================================
 * 3. Layer 2 Cert: DBSP Bilinear Join Delta Identity (`dbsp_join_delta`)
 * ============================================================================ */

static inline bool node_cert_emit_dbsp_fir(node_cert_ws_t *ws, const char *out_fir_path) {
    if (ws == NULL || out_fir_path == NULL) {
        return false;
    }
    flow_ir_builder_init(ws, "node_dbsp_join_delta");
    flow_ir_prog_t *p = &ws->ir_prog;
    p->num_inputs = 1U;
    p->inputs[0] = 0U;
    p->vals[0].width = 16U;
    p->vals[0].is_classical = 1U;
    (void)snprintf(p->vals[0].name, sizeof(p->vals[0].name), "ab_pair16");
    p->num_vals = 1U;

    uint32_t a0 = flow_ir_emit_op1(p, FLOW_IR_OP_SLICE, 4U, 0U, 0ULL, "a0");
    uint32_t a1 = flow_ir_emit_op1(p, FLOW_IR_OP_SLICE, 4U, 0U, 4ULL, "a1");
    uint32_t b0 = flow_ir_emit_op1(p, FLOW_IR_OP_SLICE, 4U, 0U, 8ULL, "b0");
    uint32_t b1 = flow_ir_emit_op1(p, FLOW_IR_OP_SLICE, 4U, 0U, 12ULL, "b1");

    uint32_t zero4 = flow_ir_emit_const(p, 4U, 0ULL, "z4");
    uint32_t zero1 = flow_ir_emit_const(p, 1U, 0ULL, "z1");
    uint32_t zero2 = flow_ir_emit_const(p, 2U, 0ULL, "z2");
    uint32_t zero3 = flow_ir_emit_const(p, 3U, 0ULL, "z3");

    uint32_t p_new = node_cert_mul4_mod16(p, a1, b1, zero4, zero1, zero2, zero3, "a1b1");
    uint32_t p_old = node_cert_mul4_mod16(p, a0, b0, zero4, zero1, zero2, zero3, "a0b0");
    uint32_t lhs = flow_ir_emit_op2(p, FLOW_IR_OP_SUB, 4U, p_new, p_old, "lhs");

    uint32_t da = flow_ir_emit_op2(p, FLOW_IR_OP_SUB, 4U, a1, a0, "da");
    uint32_t db = flow_ir_emit_op2(p, FLOW_IR_OP_SUB, 4U, b1, b0, "db");
    uint32_t t1 = node_cert_mul4_mod16(p, da, b0, zero4, zero1, zero2, zero3, "da_b0");
    uint32_t t2 = node_cert_mul4_mod16(p, a0, db, zero4, zero1, zero2, zero3, "a0_db");
    uint32_t t3 = node_cert_mul4_mod16(p, da, db, zero4, zero1, zero2, zero3, "da_db");
    uint32_t s12 = flow_ir_emit_op2(p, FLOW_IR_OP_ADD, 4U, t1, t2, "s12");
    uint32_t rhs = flow_ir_emit_op2(p, FLOW_IR_OP_ADD, 4U, s12, t3, "rhs");

    uint32_t xdiff = flow_ir_emit_op2(p, FLOW_IR_OP_XOR_VEC, 4U, lhs, rhs, "xdiff");
    uint32_t mismatch = flow_ir_emit_op1(p, FLOW_IR_OP_OR_REDUCE, 1U, xdiff, 0ULL, "mismatch");

    p->num_outputs = 1U;
    p->outputs[0] = mismatch;
    return node_cert_seal_cartesian_fir(ws, out_fir_path);
}

static inline bool node_cert_emit_dbsp_lean(const char *path) {
    FILE *fp = fopen(path, "wb");
    if (fp == NULL) {
        return false;
    }
    fprintf(fp, "import Node.Theory\n\n");
    fprintf(fp, "namespace Node.CertDbspJoin\n\n");
    fprintf(fp, "open Node.Dbsp\n\n");
    fprintf(
        fp,
        "theorem witness_incremental_join_exact {α : Type} (a b : Stream (ZSet α)) (t : Nat) (k : α) :\n");
    fprintf(fp, "    integ (dbspBilinearJoinStep a b) t k = zJoin (a t) (b t) k :=\n");
    fprintf(fp, "  dbsp_incremental_join_matches_full a b t k\n\n");
    fprintf(fp, "end Node.CertDbspJoin\n");
    return fclose(fp) == 0;
}

static inline bool node_cert_emit_json(const char *path, const char *name, const char *fir_name,
                                       const char *lean_name, uint32_t in_bits,
                                       const char *expect) {
    FILE *fp = fopen(path, "wb");
    if (fp == NULL) {
        return false;
    }
    fprintf(fp, "{\n");
    fprintf(fp, "  \"cert\": \"%s\",\n", name);
    fprintf(fp, "  \"fir\": \"%s\",\n", fir_name);
    fprintf(fp, "  \"lean\": \"%s\",\n", lean_name);
    fprintf(fp, "  \"input_bits\": %u,\n", in_bits);
    fprintf(fp, "  \"expected_verdict\": \"%s\"\n", expect);
    fprintf(fp, "}\n");
    return fclose(fp) == 0;
}

#ifdef __cplusplus
}
#endif

#endif /* NODE_CERT_H */
