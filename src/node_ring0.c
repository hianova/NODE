#include "node.h"
#include "flow_sha256.h"

/* ============================================================================
 * NODE v1.0.0 — Freestanding Pure-GPR Ring-0 Systems Core
 * ============================================================================
 * Zero libc, zero memcpy/memset, zero heap, zero floats/SIMD, zero udiv/sdiv,
 * zero blr/jump-tables (`-ffreestanding -nostdlib -mgeneral-regs-only`).
 * ============================================================================ */

static void node_zero_bytes(void *dst, size_t n) {
    volatile uint8_t *p = (volatile uint8_t *)dst;
    for (size_t i = 0U; i < n; ++i) {
        p[i] = UINT8_C(0);
    }
}

static void node_copy_bytes(void *dst, const void *src, size_t n) {
    volatile uint8_t *d = (volatile uint8_t *)dst;
    const volatile uint8_t *s = (const volatile uint8_t *)src;
    for (size_t i = 0U; i < n; ++i) {
        d[i] = s[i];
    }
}

static uint64_t node_sha256_u64(const void *buf, size_t len) {
    flow_sha256_ctx_t ctx;
    uint8_t digest[32];
    node_zero_bytes(&ctx, sizeof(ctx));
    node_zero_bytes(digest, sizeof(digest));
    flow_sha256_init(&ctx);
    flow_sha256_update(&ctx, (const uint8_t *)buf, len);
    flow_sha256_final(&ctx, digest);
    return ((uint64_t)digest[0]) | ((uint64_t)digest[1] << 8U) | ((uint64_t)digest[2] << 16U) |
           ((uint64_t)digest[3] << 24U) | ((uint64_t)digest[4] << 32U) |
           ((uint64_t)digest[5] << 40U) | ((uint64_t)digest[6] << 48U) |
           ((uint64_t)digest[7] << 56U);
}

static void node_hash_u64_pair(const uint8_t left[32], const uint8_t right[32], uint8_t out[32]) {
    flow_sha256_ctx_t ctx;
    uint8_t tag = UINT8_C(0x01);
    node_zero_bytes(&ctx, sizeof(ctx));
    flow_sha256_init(&ctx);
    flow_sha256_update(&ctx, &tag, 1U);
    flow_sha256_update(&ctx, left, 32U);
    flow_sha256_update(&ctx, right, 32U);
    flow_sha256_final(&ctx, out);
}

static void node_hash_u64_leaf(uint32_t idx, uint64_t val, uint8_t out[32]) {
    flow_sha256_ctx_t ctx;
    uint8_t buf[13];
    node_zero_bytes(&ctx, sizeof(ctx));
    buf[0] = UINT8_C(0x00);
    buf[1] = (uint8_t)(idx & 0xFFU);
    buf[2] = (uint8_t)((idx >> 8U) & 0xFFU);
    buf[3] = (uint8_t)((idx >> 16U) & 0xFFU);
    buf[4] = (uint8_t)((idx >> 24U) & 0xFFU);
    for (uint32_t b = 0U; b < 8U; ++b) {
        buf[5U + b] = (uint8_t)((val >> (b * 8U)) & UINT64_C(0xFF));
    }
    flow_sha256_init(&ctx);
    flow_sha256_update(&ctx, buf, sizeof(buf));
    flow_sha256_final(&ctx, out);
}

static uint32_t node_wrap_small(uint32_t x, uint32_t n) {
    if (n == 0U) {
        return 0U;
    }
    while (x >= n) {
        x -= n;
    }
    return x;
}

uint64_t node_prng_next(uint64_t *state) {
    uint64_t x = (state != NULL) ? *state : UINT64_C(0x9E3779B97F4A7C15);
    if (x == UINT64_C(0)) {
        x = UINT64_C(0x9E3779B97F4A7C15);
    }
    x ^= x >> 12U;
    x ^= x << 25U;
    x ^= x >> 27U;
    if (state != NULL) {
        *state = x;
    }
    return x * UINT64_C(0x2545F4914F6CDD1D);
}

/* ============================================================================
 * LAYER 1: Deterministic Capability Micro-VM & O(1) Snapshot Replay
 * ============================================================================ */

void node_vm_init(node_vm_t *vm, uint32_t fuel_budget) {
    if (vm == NULL) {
        return;
    }
    node_zero_bytes(vm, sizeof(*vm));
    vm->state.fuel = fuel_budget;
    vm->fuel_budget = fuel_budget;
}

bool node_vm_grant_cap(node_vm_t *vm, uint32_t slot, uint32_t region_id, uint32_t base,
                       uint32_t len, uint32_t rights) {
    if (vm == NULL || slot >= NODE_VM_MAX_CAPS || base > NODE_VM_MEM_WORDS ||
        len > NODE_VM_MEM_WORDS - base) {
        return false;
    }
    vm->state.caps[slot].region_id = region_id;
    vm->state.caps[slot].base = base;
    vm->state.caps[slot].len = len;
    vm->state.caps[slot].rights = rights;
    return true;
}

bool node_vm_attenuate_cap(node_vm_t *vm, uint32_t dst_slot, uint32_t src_slot, uint32_t new_base,
                           uint32_t new_len, uint32_t new_rights) {
    if (vm == NULL || dst_slot >= NODE_VM_MAX_CAPS || src_slot >= NODE_VM_MAX_CAPS) {
        return false;
    }
    const node_cap_t src = vm->state.caps[src_slot];
    if ((src.rights & NODE_CAP_G) == 0U) {
        return false;
    }
    if ((new_rights & src.rights) != new_rights) {
        return false;
    }
    if (new_base < src.base || new_len > src.len || new_base > src.base + src.len ||
        new_base + new_len > src.base + src.len) {
        return false;
    }
    vm->state.caps[dst_slot].region_id = src.region_id;
    vm->state.caps[dst_slot].base = new_base;
    vm->state.caps[dst_slot].len = new_len;
    vm->state.caps[dst_slot].rights = new_rights;
    return true;
}

static bool vm_check_cap(const node_cap_t *c, uint32_t addr, uint32_t req_right) {
    if (c == NULL || (c->rights & req_right) != req_right) {
        return false;
    }
    if (addr < c->base || addr >= c->base + c->len || addr >= NODE_VM_MEM_WORDS) {
        return false;
    }
    return true;
}

void node_vm_step(node_vm_t *vm, const node_vm_prog_t *prog) {
    if (vm == NULL || prog == NULL) {
        return;
    }
    if (vm->state.halted != 0U) {
        return;
    }
    if (vm->state.fuel == 0U) {
        vm->state.halted = 1U;
        vm->state.fault = NODE_FAULT_FUEL;
        return;
    }
    vm->state.fuel--;
    vm->state.steps++;

    if (vm->state.pc >= prog->len || vm->state.pc >= NODE_VM_MAX_INSNS) {
        vm->state.halted = 1U;
        vm->state.fault = (prog->len == 0U) ? NODE_FAULT_NONE : NODE_FAULT_PC;
        return;
    }

    const node_vm_insn_t insn = prog->insns[vm->state.pc];
    uint32_t op = insn.op;
    uint32_t dst = (uint32_t)insn.dst & (NODE_VM_NUM_REGS - 1U);
    uint32_t s1 = (uint32_t)insn.src1 & (NODE_VM_NUM_REGS - 1U);
    uint32_t s2 = (uint32_t)insn.src2 & (NODE_VM_NUM_REGS - 1U);

    if (op == NODE_OP_HALT) {
        vm->state.halted = 1U;
    } else if (op == NODE_OP_MOVI) {
        vm->state.regs[dst] = insn.imm;
        vm->state.pc++;
    } else if (op == NODE_OP_ADD) {
        vm->state.regs[dst] = vm->state.regs[s1] + vm->state.regs[s2];
        vm->state.pc++;
    } else if (op == NODE_OP_SUB) {
        vm->state.regs[dst] = vm->state.regs[s1] - vm->state.regs[s2];
        vm->state.pc++;
    } else if (op == NODE_OP_XOR) {
        vm->state.regs[dst] = vm->state.regs[s1] ^ vm->state.regs[s2];
        vm->state.pc++;
    } else if (op == NODE_OP_AND) {
        vm->state.regs[dst] = vm->state.regs[s1] & vm->state.regs[s2];
        vm->state.pc++;
    } else if (op == NODE_OP_SHL) {
        vm->state.regs[dst] = vm->state.regs[s1] << (vm->state.regs[s2] & UINT64_C(63));
        vm->state.pc++;
    } else if (op == NODE_OP_SHR) {
        vm->state.regs[dst] = vm->state.regs[s1] >> (vm->state.regs[s2] & UINT64_C(63));
        vm->state.pc++;
    } else if (op == NODE_OP_LOAD_CAP) {
        uint32_t cidx = (uint32_t)insn.src1;
        uint32_t off = (uint32_t)insn.imm;
        if (cidx >= NODE_VM_MAX_CAPS || !vm_check_cap(&vm->state.caps[cidx], off, NODE_CAP_R)) {
            vm->state.halted = 1U;
            vm->state.fault = NODE_FAULT_CAP;
            return;
        }
        vm->state.regs[dst] = vm->state.mem[off];
        vm->state.pc++;
    } else if (op == NODE_OP_STORE_CAP) {
        uint32_t cidx = (uint32_t)insn.dst;
        uint32_t off = (uint32_t)insn.imm;
        if (cidx >= NODE_VM_MAX_CAPS || !vm_check_cap(&vm->state.caps[cidx], off, NODE_CAP_W)) {
            vm->state.halted = 1U;
            vm->state.fault = NODE_FAULT_CAP;
            return;
        }
        vm->state.mem[off] = vm->state.regs[s1];
        vm->state.pc++;
    } else if (op == NODE_OP_ATTENUATE) {
        uint32_t c_dst = (uint32_t)insn.dst;
        uint32_t c_src = (uint32_t)insn.src1;
        uint32_t new_rights = (uint32_t)insn.src2;
        uint32_t new_base = (uint32_t)(insn.imm & UINT64_C(0xFFFFFFFF));
        uint32_t new_len = (uint32_t)((insn.imm >> 32U) & UINT64_C(0xFFFFFFFF));
        if (!node_vm_attenuate_cap(vm, c_dst, c_src, new_base, new_len, new_rights)) {
            vm->state.halted = 1U;
            vm->state.fault = NODE_FAULT_CAP;
            return;
        }
        vm->state.pc++;
    } else if (op == NODE_OP_JNZ) {
        if (vm->state.regs[dst] != UINT64_C(0)) {
            vm->state.pc = (uint32_t)insn.imm;
        } else {
            vm->state.pc++;
        }
    } else if (op == NODE_OP_EMIT) {
        if (vm->state.emit_len < NODE_VM_LOG_CAP) {
            vm->state.emit_log[vm->state.emit_len++] = vm->state.regs[s1];
        }
        vm->state.pc++;
    } else {
        vm->state.halted = 1U;
        vm->state.fault = NODE_FAULT_OP;
    }
}

void node_vm_run(node_vm_t *vm, const node_vm_prog_t *prog, uint32_t max_steps) {
    if (vm == NULL || prog == NULL) {
        return;
    }
    for (uint32_t i = 0U; i < max_steps; ++i) {
        if (vm->state.halted != 0U) {
            break;
        }
        node_vm_step(vm, prog);
    }
}

bool node_vm_snap_push(node_vm_t *vm) {
    if (vm == NULL) {
        return false;
    }
    uint32_t idx = vm->snap_head & (NODE_VM_SNAP_CAP - 1U);
    node_copy_bytes(&vm->snaps[idx], &vm->state, sizeof(vm->state));
    vm->snap_head++;
    if (vm->snap_count < NODE_VM_SNAP_CAP) {
        vm->snap_count++;
    }
    return true;
}

bool node_vm_snap_restore(node_vm_t *vm, uint32_t rev_idx) {
    if (vm == NULL || rev_idx >= vm->snap_count || vm->snap_head == 0U) {
        return false;
    }
    uint32_t pos = (vm->snap_head - 1U - rev_idx) & (NODE_VM_SNAP_CAP - 1U);
    node_copy_bytes(&vm->state, &vm->snaps[pos], sizeof(vm->state));
    return true;
}

uint64_t node_vm_state_hash(const node_vm_t *vm) {
    if (vm == NULL) {
        return UINT64_C(0);
    }
    return node_sha256_u64(&vm->state, sizeof(vm->state));
}

/* ============================================================================
 * LAYER 2: DBSP Z-Sets, WCOJ Triangle Join & Merkle Crash-Safe WAL
 * ============================================================================ */

void node_zset_init(node_zset_t *z) {
    if (z == NULL) {
        return;
    }
    node_zero_bytes(z, sizeof(*z));
}

bool node_zset_add_entry(node_zset_t *z, uint64_t key, int64_t weight) {
    if (z == NULL) {
        return false;
    }
    if (weight == INT64_C(0)) {
        return true;
    }
    uint32_t lo = 0U;
    uint32_t hi = z->len;
    while (lo < hi) {
        uint32_t mid = lo + ((hi - lo) >> 1U);
        if (z->entries[mid].key < key) {
            lo = mid + 1U;
        } else {
            hi = mid;
        }
    }
    if (lo < z->len && z->entries[lo].key == key) {
        int64_t nw = z->entries[lo].weight + weight;
        if (nw == INT64_C(0)) {
            for (uint32_t k = lo; k + 1U < z->len; ++k) {
                z->entries[k].key = z->entries[k + 1U].key;
                z->entries[k].weight = z->entries[k + 1U].weight;
            }
            z->len--;
        } else {
            z->entries[lo].weight = nw;
        }
        return true;
    }
    if (z->len >= NODE_ZSET_CAP) {
        return false;
    }
    for (uint32_t k = z->len; k > lo; --k) {
        z->entries[k].key = z->entries[k - 1U].key;
        z->entries[k].weight = z->entries[k - 1U].weight;
    }
    z->entries[lo].key = key;
    z->entries[lo].weight = weight;
    z->len++;
    return true;
}

static bool zset_linear_combine(const node_zset_t *a, const node_zset_t *b, int64_t b_sign,
                                node_zset_t *out) {
    if (a == NULL || b == NULL || out == NULL) {
        return false;
    }
    node_zset_init(out);
    uint32_t i = 0U;
    uint32_t j = 0U;
    while (i < a->len && j < b->len) {
        uint64_t ka = a->entries[i].key;
        uint64_t kb = b->entries[j].key;
        if (ka < kb) {
            if (out->len >= NODE_ZSET_CAP) {
                return false;
            }
            out->entries[out->len].key = ka;
            out->entries[out->len].weight = a->entries[i].weight;
            out->len++;
            i++;
        } else if (kb < ka) {
            if (out->len >= NODE_ZSET_CAP) {
                return false;
            }
            out->entries[out->len].key = kb;
            out->entries[out->len].weight = b_sign * b->entries[j].weight;
            out->len++;
            j++;
        } else {
            int64_t w = a->entries[i].weight + b_sign * b->entries[j].weight;
            if (w != INT64_C(0)) {
                if (out->len >= NODE_ZSET_CAP) {
                    return false;
                }
                out->entries[out->len].key = ka;
                out->entries[out->len].weight = w;
                out->len++;
            }
            i++;
            j++;
        }
    }
    while (i < a->len) {
        if (out->len >= NODE_ZSET_CAP) {
            return false;
        }
        out->entries[out->len].key = a->entries[i].key;
        out->entries[out->len].weight = a->entries[i].weight;
        out->len++;
        i++;
    }
    while (j < b->len) {
        if (out->len >= NODE_ZSET_CAP) {
            return false;
        }
        out->entries[out->len].key = b->entries[j].key;
        out->entries[out->len].weight = b_sign * b->entries[j].weight;
        out->len++;
        j++;
    }
    return true;
}

bool node_zset_add(const node_zset_t *a, const node_zset_t *b, node_zset_t *out) {
    return zset_linear_combine(a, b, INT64_C(1), out);
}

bool node_zset_sub(const node_zset_t *a, const node_zset_t *b, node_zset_t *out) {
    return zset_linear_combine(a, b, INT64_C(-1), out);
}

bool node_zset_filter_even(const node_zset_t *in, node_zset_t *out) {
    if (in == NULL || out == NULL) {
        return false;
    }
    node_zset_init(out);
    for (uint32_t i = 0U; i < in->len; ++i) {
        if ((in->entries[i].key & UINT64_C(1)) == UINT64_C(0)) {
            out->entries[out->len].key = in->entries[i].key;
            out->entries[out->len].weight = in->entries[i].weight;
            out->len++;
        }
    }
    return true;
}

static bool zset_bsearch(const node_zset_t *hay, uint64_t key, int64_t *w_out, uint64_t *ops) {
    uint32_t lo = 0U;
    uint32_t hi = hay->len;
    while (lo < hi) {
        uint32_t mid = lo + ((hi - lo) >> 1U);
        (*ops)++;
        if (hay->entries[mid].key < key) {
            lo = mid + 1U;
        } else if (hay->entries[mid].key > key) {
            hi = mid;
        } else {
            *w_out = hay->entries[mid].weight;
            return true;
        }
    }
    return false;
}

bool node_zset_join(const node_zset_t *a, const node_zset_t *b, node_zset_t *out,
                    uint64_t *ops_out) {
    if (a == NULL || b == NULL || out == NULL) {
        return false;
    }
    node_zset_init(out);
    uint64_t ops = UINT64_C(0);
    if (a->len == 0U || b->len == 0U) {
        if (ops_out != NULL) {
            *ops_out = ops;
        }
        return true;
    }
    if ((a->len << 3U) < b->len) {
        for (uint32_t i = 0U; i < a->len; ++i) {
            int64_t wb = 0;
            if (zset_bsearch(b, a->entries[i].key, &wb, &ops)) {
                int64_t pw = a->entries[i].weight * wb;
                if (pw != INT64_C(0)) {
                    out->entries[out->len].key = a->entries[i].key;
                    out->entries[out->len].weight = pw;
                    out->len++;
                }
            }
        }
    } else if ((b->len << 3U) < a->len) {
        for (uint32_t j = 0U; j < b->len; ++j) {
            int64_t wa = 0;
            if (zset_bsearch(a, b->entries[j].key, &wa, &ops)) {
                int64_t pw = wa * b->entries[j].weight;
                if (pw != INT64_C(0)) {
                    out->entries[out->len].key = b->entries[j].key;
                    out->entries[out->len].weight = pw;
                    out->len++;
                }
            }
        }
    } else {
        uint32_t i = 0U;
        uint32_t j = 0U;
        while (i < a->len && j < b->len) {
            ops++;
            if (a->entries[i].key < b->entries[j].key) {
                i++;
            } else if (b->entries[j].key < a->entries[i].key) {
                j++;
            } else {
                int64_t pw = a->entries[i].weight * b->entries[j].weight;
                if (pw != INT64_C(0)) {
                    out->entries[out->len].key = a->entries[i].key;
                    out->entries[out->len].weight = pw;
                    out->len++;
                }
                i++;
                j++;
            }
        }
    }
    if (ops_out != NULL) {
        *ops_out = ops;
    }
    return true;
}

bool node_zset_equal(const node_zset_t *a, const node_zset_t *b) {
    if (a == NULL || b == NULL || a->len != b->len) {
        return false;
    }
    for (uint32_t i = 0U; i < a->len; ++i) {
        if (a->entries[i].key != b->entries[i].key ||
            a->entries[i].weight != b->entries[i].weight) {
            return false;
        }
    }
    return true;
}

uint64_t node_zset_hash(const node_zset_t *z) {
    if (z == NULL) {
        return UINT64_C(0);
    }
    flow_sha256_ctx_t ctx;
    uint8_t digest[32];
    node_zero_bytes(&ctx, sizeof(ctx));
    flow_sha256_init(&ctx);
    flow_sha256_update(&ctx, (const uint8_t *)&z->len, sizeof(z->len));
    if (z->len > 0U && z->len <= NODE_ZSET_CAP) {
        flow_sha256_update(&ctx, (const uint8_t *)z->entries,
                           (size_t)z->len * sizeof(node_zset_entry_t));
    }
    flow_sha256_final(&ctx, digest);
    return ((uint64_t)digest[0]) | ((uint64_t)digest[1] << 8U) | ((uint64_t)digest[2] << 16U) |
           ((uint64_t)digest[3] << 24U) | ((uint64_t)digest[4] << 32U) |
           ((uint64_t)digest[5] << 40U) | ((uint64_t)digest[6] << 48U) |
           ((uint64_t)digest[7] << 56U);
}

void node_dbsp_join_init(node_dbsp_join_state_t *st) {
    if (st == NULL) {
        return;
    }
    node_zero_bytes(st, sizeof(*st));
}

bool node_dbsp_join_step(node_dbsp_join_state_t *st, const node_zset_t *da, const node_zset_t *db,
                         node_zset_t *delta_out) {
    if (st == NULL || da == NULL || db == NULL || delta_out == NULL) {
        return false;
    }
    uint64_t o1 = 0U;
    uint64_t o2 = 0U;
    uint64_t o3 = 0U;
    if (!node_zset_join(da, &st->b_state, &st->ws_da_b, &o1)) {
        return false;
    }
    if (!node_zset_join(&st->a_state, db, &st->ws_a_db, &o2)) {
        return false;
    }
    if (!node_zset_join(da, db, &st->ws_da_db, &o3)) {
        return false;
    }
    if (!node_zset_add(&st->ws_da_b, &st->ws_a_db, &st->ws_sum)) {
        return false;
    }
    if (!node_zset_add(&st->ws_sum, &st->ws_da_db, delta_out)) {
        return false;
    }

    if (!node_zset_add(&st->a_state, da, &st->ws_sum)) {
        return false;
    }
    node_copy_bytes(&st->a_state, &st->ws_sum, sizeof(st->a_state));

    if (!node_zset_add(&st->b_state, db, &st->ws_sum)) {
        return false;
    }
    node_copy_bytes(&st->b_state, &st->ws_sum, sizeof(st->b_state));

    if (!node_zset_add(&st->out_state, delta_out, &st->ws_sum)) {
        return false;
    }
    node_copy_bytes(&st->out_state, &st->ws_sum, sizeof(st->out_state));

    st->epoch++;
    st->inc_ops += o1 + o2 + o3;
    st->full_ops += (uint64_t)st->a_state.len + (uint64_t)st->b_state.len;
    return true;
}

/* --- WCOJ Triangle Query (Leapfrog / Chiba-Nishizeki Min-Branch Probing) --- */

void node_graph_init(node_graph_t *g, uint32_t num_verts) {
    if (g == NULL) {
        return;
    }
    node_zero_bytes(g, sizeof(*g));
    g->num_verts = (num_verts > NODE_WCOJ_MAX_VERTS) ? NODE_WCOJ_MAX_VERTS : num_verts;
}

bool node_graph_add_edge(node_graph_t *g, uint32_t u, uint32_t v) {
    if (g == NULL || u >= g->num_verts || v >= g->num_verts ||
        g->edge_count >= NODE_WCOJ_MAX_EDGES) {
        return false;
    }
    g->src_buf[g->edge_count] = u;
    g->dst_buf[g->edge_count] = v;
    g->edge_count++;
    g->finalized = 0U;
    return true;
}

bool node_graph_finalize(node_graph_t *g) {
    if (g == NULL || g->num_verts > NODE_WCOJ_MAX_VERTS || g->edge_count > NODE_WCOJ_MAX_EDGES) {
        return false;
    }
    for (uint32_t v = 0U; v <= g->num_verts; ++v) {
        g->row_off[v] = 0U;
    }
    for (uint32_t e = 0U; e < g->edge_count; ++e) {
        uint32_t u = g->src_buf[e];
        if (u < g->num_verts) {
            g->row_off[u + 1U]++;
        }
    }
    for (uint32_t u = 0U; u < g->num_verts; ++u) {
        g->row_off[u + 1U] += g->row_off[u];
    }
    uint32_t cursor[NODE_WCOJ_MAX_VERTS];
    for (uint32_t u = 0U; u < g->num_verts; ++u) {
        cursor[u] = g->row_off[u];
    }
    for (uint32_t e = 0U; e < g->edge_count; ++e) {
        uint32_t u = g->src_buf[e];
        if (u < g->num_verts) {
            uint32_t pos = cursor[u]++;
            g->adj[pos] = g->dst_buf[e];
        }
    }
    for (uint32_t u = 0U; u < g->num_verts; ++u) {
        uint32_t s = g->row_off[u];
        uint32_t e = g->row_off[u + 1U];
        for (uint32_t i = s + 1U; i < e; ++i) {
            uint32_t key = g->adj[i];
            uint32_t j = i;
            while (j > s && g->adj[j - 1U] > key) {
                g->adj[j] = g->adj[j - 1U];
                j--;
            }
            g->adj[j] = key;
        }
    }
    g->finalized = 1U;
    return true;
}

static bool csr_contains(const node_graph_t *g, uint32_t u, uint32_t target, uint64_t *probes) {
    if (u >= g->num_verts) {
        return false;
    }
    uint32_t lo = g->row_off[u];
    uint32_t hi = g->row_off[u + 1U];
    while (lo < hi) {
        uint32_t mid = lo + ((hi - lo) >> 1U);
        (*probes)++;
        if (g->adj[mid] < target) {
            lo = mid + 1U;
        } else if (g->adj[mid] > target) {
            hi = mid;
        } else {
            return true;
        }
    }
    return false;
}

uint64_t node_wcoj_count_triangles(const node_graph_t *g, uint64_t *probes_out) {
    if (g == NULL || g->finalized == 0U) {
        if (probes_out != NULL) {
            *probes_out = 0U;
        }
        return UINT64_C(0);
    }
    uint64_t tris = UINT64_C(0);
    uint64_t probes = UINT64_C(0);
    for (uint32_t u = 0U; u < g->num_verts; ++u) {
        uint32_t u_beg = g->row_off[u];
        uint32_t u_end = g->row_off[u + 1U];
        uint32_t deg_u = u_end - u_beg;
        for (uint32_t ei = u_beg; ei < u_end; ++ei) {
            uint32_t v = g->adj[ei];
            if (v >= g->num_verts) {
                continue;
            }
            uint32_t v_beg = g->row_off[v];
            uint32_t v_end = g->row_off[v + 1U];
            uint32_t deg_v = v_end - v_beg;
            if (deg_u == 0U || deg_v == 0U) {
                continue;
            }
            if ((deg_u << 2U) < deg_v) {
                for (uint32_t k = u_beg; k < u_end; ++k) {
                    if (csr_contains(g, v, g->adj[k], &probes)) {
                        tris++;
                    }
                }
            } else if ((deg_v << 2U) < deg_u) {
                for (uint32_t k = v_beg; k < v_end; ++k) {
                    if (csr_contains(g, u, g->adj[k], &probes)) {
                        tris++;
                    }
                }
            } else {
                uint32_t p = u_beg;
                uint32_t q = v_beg;
                while (p < u_end && q < v_end) {
                    probes++;
                    if (g->adj[p] < g->adj[q]) {
                        p++;
                    } else if (g->adj[q] < g->adj[p]) {
                        q++;
                    } else {
                        tris++;
                        p++;
                        q++;
                    }
                }
            }
        }
    }
    if (probes_out != NULL) {
        *probes_out = probes;
    }
    return tris;
}

uint64_t node_binjoin_count_triangles(const node_graph_t *g, uint64_t *wedges_out,
                                      uint64_t *probes_out) {
    if (g == NULL || g->finalized == 0U) {
        if (wedges_out != NULL) {
            *wedges_out = 0U;
        }
        if (probes_out != NULL) {
            *probes_out = 0U;
        }
        return UINT64_C(0);
    }
    uint64_t tris = UINT64_C(0);
    uint64_t wedges = UINT64_C(0);
    uint64_t probes = UINT64_C(0);
    for (uint32_t u = 0U; u < g->num_verts; ++u) {
        uint32_t u_beg = g->row_off[u];
        uint32_t u_end = g->row_off[u + 1U];
        for (uint32_t ei = u_beg; ei < u_end; ++ei) {
            uint32_t v = g->adj[ei];
            if (v >= g->num_verts) {
                continue;
            }
            uint32_t v_beg = g->row_off[v];
            uint32_t v_end = g->row_off[v + 1U];
            for (uint32_t ej = v_beg; ej < v_end; ++ej) {
                wedges++;
                uint32_t w = g->adj[ej];
                if (csr_contains(g, u, w, &probes)) {
                    tris++;
                }
            }
        }
    }
    if (wedges_out != NULL) {
        *wedges_out = wedges;
    }
    if (probes_out != NULL) {
        *probes_out = probes;
    }
    return tris;
}

/* --- Merkle Crash-Safe Write-Ahead Log --- */

static uint64_t wal_hash_rec(const node_wal_rec_t *r) {
    return node_sha256_u64(r, offsetof(node_wal_rec_t, rec_hash));
}

void node_wal_init(node_wal_t *w) {
    if (w == NULL) {
        return;
    }
    node_zero_bytes(w, sizeof(*w));
    w->next_tx_id = 1U;
    w->chain_hash = UINT64_C(0x4E4F444557414C31);
}

bool node_wal_append_data(node_wal_t *w, uint32_t tx_id, uint32_t key, uint64_t val) {
    if (w == NULL || w->len >= NODE_WAL_MAX_RECS || key >= NODE_PAGE_COUNT) {
        return false;
    }
    uint32_t idx = w->len;
    w->recs[idx].lsn = idx;
    w->recs[idx].tx_id = tx_id;
    w->recs[idx].key = key;
    w->recs[idx].flags = NODE_WAL_FLAG_DATA;
    w->recs[idx].val = val;
    w->recs[idx].prev_hash = w->chain_hash;
    w->recs[idx].rec_hash = wal_hash_rec(&w->recs[idx]);
    w->chain_hash = w->recs[idx].rec_hash;
    w->len++;
    return true;
}

bool node_wal_append_commit(node_wal_t *w, uint32_t tx_id) {
    if (w == NULL || w->len >= NODE_WAL_MAX_RECS) {
        return false;
    }
    uint32_t idx = w->len;
    w->recs[idx].lsn = idx;
    w->recs[idx].tx_id = tx_id;
    w->recs[idx].key = 0U;
    w->recs[idx].flags = NODE_WAL_FLAG_COMMIT;
    w->recs[idx].val = UINT64_C(0);
    w->recs[idx].prev_hash = w->chain_hash;
    w->recs[idx].rec_hash = wal_hash_rec(&w->recs[idx]);
    w->chain_hash = w->recs[idx].rec_hash;
    w->len++;
    return true;
}

void node_merkle_root64(const uint64_t pages[NODE_PAGE_COUNT], uint8_t root_out[32]) {
    uint8_t level[NODE_PAGE_COUNT][32];
    uint8_t next_level[NODE_PAGE_COUNT][32];
    for (uint32_t i = 0U; i < NODE_PAGE_COUNT; ++i) {
        uint64_t v = (pages != NULL) ? pages[i] : UINT64_C(0);
        node_hash_u64_leaf(i, v, level[i]);
    }
    uint32_t width = NODE_PAGE_COUNT;
    while (width > 1U) {
        uint32_t half = width >> 1U;
        for (uint32_t i = 0U; i < half; ++i) {
            size_t idx2 = (size_t)i * 2U;
            node_hash_u64_pair(level[idx2], level[idx2 + 1U], next_level[i]);
        }
        for (uint32_t i = 0U; i < half; ++i) {
            node_copy_bytes(level[i], next_level[i], 32U);
        }
        width = half;
    }
    node_copy_bytes(root_out, level[0], 32U);
}

bool node_merkle_proof64(const uint64_t pages[NODE_PAGE_COUNT], uint32_t leaf_idx,
                         node_merkle_proof_t *proof_out) {
    if (pages == NULL || proof_out == NULL || leaf_idx >= NODE_PAGE_COUNT) {
        return false;
    }
    uint8_t level[NODE_PAGE_COUNT][32];
    uint8_t next_level[NODE_PAGE_COUNT][32];
    node_zero_bytes(proof_out, sizeof(*proof_out));
    proof_out->leaf_idx = leaf_idx;
    proof_out->depth = 6U;
    proof_out->leaf_val = pages[leaf_idx];
    for (uint32_t i = 0U; i < NODE_PAGE_COUNT; ++i) {
        node_hash_u64_leaf(i, pages[i], level[i]);
    }
    uint32_t width = NODE_PAGE_COUNT;
    uint32_t cur = leaf_idx;
    for (uint32_t lvl = 0U; lvl < 6U; ++lvl) {
        uint32_t sib = cur ^ 1U;
        node_copy_bytes(proof_out->siblings[lvl], level[sib], 32U);
        uint32_t half = width >> 1U;
        for (uint32_t i = 0U; i < half; ++i) {
            size_t idx2 = (size_t)i * 2U;
            node_hash_u64_pair(level[idx2], level[idx2 + 1U], next_level[i]);
        }
        for (uint32_t i = 0U; i < half; ++i) {
            node_copy_bytes(level[i], next_level[i], 32U);
        }
        cur >>= 1U;
        width = half;
    }
    return true;
}

bool node_merkle_verify_proof64(const node_merkle_proof_t *proof, const uint8_t root[32]) {
    if (proof == NULL || root == NULL || proof->leaf_idx >= NODE_PAGE_COUNT || proof->depth != 6U) {
        return false;
    }
    uint8_t cur_hash[32];
    uint8_t next_hash[32];
    node_hash_u64_leaf(proof->leaf_idx, proof->leaf_val, cur_hash);
    uint32_t idx = proof->leaf_idx;
    for (uint32_t lvl = 0U; lvl < 6U; ++lvl) {
        if ((idx & 1U) == 0U) {
            node_hash_u64_pair(cur_hash, proof->siblings[lvl], next_hash);
        } else {
            node_hash_u64_pair(proof->siblings[lvl], cur_hash, next_hash);
        }
        node_copy_bytes(cur_hash, next_hash, 32U);
        idx >>= 1U;
    }
    for (uint32_t b = 0U; b < 32U; ++b) {
        if (cur_hash[b] != root[b]) {
            return false;
        }
    }
    return true;
}

uint32_t node_wal_recover(const node_wal_t *w, uint32_t prefix_len, uint32_t corrupt_idx,
                          uint64_t corrupt_mask, uint64_t pages_out[NODE_PAGE_COUNT],
                          uint32_t *recovered_txs_out, uint64_t *merkle_root_out) {
    if (w == NULL || pages_out == NULL) {
        return 0U;
    }
    for (uint32_t i = 0U; i < NODE_PAGE_COUNT; ++i) {
        pages_out[i] = UINT64_C(0);
    }
    uint32_t limit = (prefix_len < w->len) ? prefix_len : w->len;
    if (limit > NODE_WAL_MAX_RECS) {
        limit = NODE_WAL_MAX_RECS;
    }

    uint64_t stage_val[NODE_PAGE_COUNT];
    uint8_t stage_dirty[NODE_PAGE_COUNT];
    uint32_t stage_tx = 0U;
    node_zero_bytes(stage_val, sizeof(stage_val));
    node_zero_bytes(stage_dirty, sizeof(stage_dirty));

    uint64_t expected_prev = UINT64_C(0x4E4F444557414C31);
    uint32_t valid_lsn = 0U;
    uint32_t recovered_txs = 0U;

    for (uint32_t i = 0U; i < limit; ++i) {
        node_wal_rec_t rec;
        node_copy_bytes(&rec, &w->recs[i], sizeof(rec));
        if (i == corrupt_idx && corrupt_mask != UINT64_C(0)) {
            rec.val ^= corrupt_mask;
        }
        uint64_t expect_hash = wal_hash_rec(&rec);
        if (rec.prev_hash != expected_prev || rec.rec_hash != expect_hash) {
            break;
        }
        expected_prev = rec.rec_hash;
        valid_lsn = i + 1U;
        if (rec.flags == NODE_WAL_FLAG_DATA) {
            if (stage_tx != rec.tx_id) {
                node_zero_bytes(stage_dirty, sizeof(stage_dirty));
                stage_tx = rec.tx_id;
            }
            if (rec.key < NODE_PAGE_COUNT) {
                stage_val[rec.key] = rec.val;
                stage_dirty[rec.key] = UINT8_C(1);
            }
        } else if (rec.flags == NODE_WAL_FLAG_COMMIT) {
            if (stage_tx == rec.tx_id) {
                for (uint32_t k = 0U; k < NODE_PAGE_COUNT; ++k) {
                    if (stage_dirty[k] != UINT8_C(0)) {
                        pages_out[k] = stage_val[k];
                        stage_dirty[k] = UINT8_C(0);
                    }
                }
                recovered_txs++;
                stage_tx = 0U;
            }
        }
    }

    if (recovered_txs_out != NULL) {
        *recovered_txs_out = recovered_txs;
    }
    if (merkle_root_out != NULL) {
        uint8_t root[32];
        node_merkle_root64(pages_out, root);
        *merkle_root_out = ((uint64_t)root[0]) | ((uint64_t)root[1] << 8U) |
                           ((uint64_t)root[2] << 16U) | ((uint64_t)root[3] << 24U) |
                           ((uint64_t)root[4] << 32U) | ((uint64_t)root[5] << 40U) |
                           ((uint64_t)root[6] << 48U) | ((uint64_t)root[7] << 56U);
    }
    return valid_lsn;
}

/* ============================================================================
 * LAYER 3: CALM Semilattice CRDTs, Raft Majority, BFT 3f+1 & DST
 * ============================================================================ */

void node_gcounter_init(node_gcounter_t *c) {
    if (c != NULL) {
        node_zero_bytes(c, sizeof(*c));
    }
}

void node_gcounter_inc(node_gcounter_t *c, uint32_t node_idx, uint64_t delta) {
    if (c != NULL && node_idx < NODE_CRDT_NODES) {
        c->slots[node_idx] += delta;
    }
}

void node_gcounter_merge(node_gcounter_t *dst, const node_gcounter_t *src) {
    if (dst == NULL || src == NULL) {
        return;
    }
    for (uint32_t i = 0U; i < NODE_CRDT_NODES; ++i) {
        if (src->slots[i] > dst->slots[i]) {
            dst->slots[i] = src->slots[i];
        }
    }
}

uint64_t node_gcounter_value(const node_gcounter_t *c) {
    if (c == NULL) {
        return UINT64_C(0);
    }
    uint64_t s = UINT64_C(0);
    for (uint32_t i = 0U; i < NODE_CRDT_NODES; ++i) {
        s += c->slots[i];
    }
    return s;
}

bool node_gcounter_equal(const node_gcounter_t *a, const node_gcounter_t *b) {
    if (a == NULL || b == NULL) {
        return false;
    }
    for (uint32_t i = 0U; i < NODE_CRDT_NODES; ++i) {
        if (a->slots[i] != b->slots[i]) {
            return false;
        }
    }
    return true;
}

void node_pncounter_init(node_pncounter_t *c) {
    if (c != NULL) {
        node_zero_bytes(c, sizeof(*c));
    }
}

void node_pncounter_inc(node_pncounter_t *c, uint32_t node_idx, uint64_t delta) {
    if (c != NULL) {
        node_gcounter_inc(&c->pos, node_idx, delta);
    }
}

void node_pncounter_dec(node_pncounter_t *c, uint32_t node_idx, uint64_t delta) {
    if (c != NULL) {
        node_gcounter_inc(&c->neg, node_idx, delta);
    }
}

void node_pncounter_merge(node_pncounter_t *dst, const node_pncounter_t *src) {
    if (dst == NULL || src == NULL) {
        return;
    }
    node_gcounter_merge(&dst->pos, &src->pos);
    node_gcounter_merge(&dst->neg, &src->neg);
}

int64_t node_pncounter_value(const node_pncounter_t *c) {
    if (c == NULL) {
        return INT64_C(0);
    }
    return (int64_t)node_gcounter_value(&c->pos) - (int64_t)node_gcounter_value(&c->neg);
}

bool node_pncounter_equal(const node_pncounter_t *a, const node_pncounter_t *b) {
    if (a == NULL || b == NULL) {
        return false;
    }
    return node_gcounter_equal(&a->pos, &b->pos) && node_gcounter_equal(&a->neg, &b->neg);
}

void node_lww_init(node_lww_reg_t *r, uint64_t ts, uint64_t node_id, uint64_t val) {
    if (r == NULL) {
        return;
    }
    node_zero_bytes(r, sizeof(*r));
    r->ts = ts;
    r->node_id = node_id;
    r->val = val;
}

void node_lww_merge(node_lww_reg_t *dst, const node_lww_reg_t *src) {
    if (dst == NULL || src == NULL) {
        return;
    }
    bool take = (src->ts > dst->ts) || (src->ts == dst->ts && src->node_id > dst->node_id) ||
                (src->ts == dst->ts && src->node_id == dst->node_id && src->val > dst->val);
    if (take) {
        dst->ts = src->ts;
        dst->node_id = src->node_id;
        dst->val = src->val;
    }
}

bool node_lww_equal(const node_lww_reg_t *a, const node_lww_reg_t *b) {
    if (a == NULL || b == NULL) {
        return false;
    }
    return a->ts == b->ts && a->node_id == b->node_id && a->val == b->val;
}

/* --- Raft Deterministic Consensus Engine --- */

#define RAFT_ROLE_FOLLOWER  0U
#define RAFT_ROLE_CANDIDATE 1U
#define RAFT_ROLE_LEADER    2U

#define RAFT_MSG_REQ_VOTE   1U
#define RAFT_MSG_VOTE_RESP  2U
#define RAFT_MSG_APPEND     3U
#define RAFT_MSG_APP_RESP   4U

static uint32_t raft_quorum(const node_raft_cluster_t *r) {
    return (r->broken_quorum != 0U) ? 2U : 3U;
}

static void raft_send_msg(node_raft_cluster_t *r, uint32_t kind, uint32_t src, uint32_t dst,
                          uint32_t term, uint32_t index, uint32_t prev_term, uint32_t success,
                          uint32_t val, uint32_t entry_term, uint32_t leader_commit,
                          uint32_t delay) {
    for (uint32_t i = 0U; i < NODE_NET_MAX_MSGS; ++i) {
        if (r->net[i].valid == 0U) {
            r->net[i].valid = 1U;
            r->net[i].kind = kind;
            r->net[i].src = src;
            r->net[i].dst = dst;
            r->net[i].term = term;
            r->net[i].index = index;
            r->net[i].prev_term = prev_term;
            r->net[i].success = success;
            r->net[i].val = val;
            r->net[i].entry_term = entry_term;
            r->net[i].leader_commit = leader_commit;
            r->net[i].deliver_tick = r->tick + delay;
            return;
        }
    }
}

void node_raft_init(node_raft_cluster_t *r, uint64_t seed, uint32_t broken_quorum) {
    if (r == NULL) {
        return;
    }
    node_zero_bytes(r, sizeof(*r));
    r->n = NODE_RAFT_N;
    r->broken_quorum = broken_quorum;
    r->prng = (seed != UINT64_C(0)) ? seed : UINT64_C(0xD57C0FFEE1234567);
    r->first_violation_tick = UINT32_MAX;
    for (uint32_t i = 0U; i < NODE_RAFT_N; ++i) {
        r->voted_for[i] = UINT32_MAX;
        r->election_timer[i] = 2U + i;
    }
}

bool node_raft_check_safety(node_raft_cluster_t *r) {
    if (r == NULL) {
        return false;
    }
    bool ok = true;
    for (uint32_t t = 0U; t < 256U; ++t) {
        uint32_t mask = r->leader_mask_by_term[t];
        uint32_t cnt = 0U;
        for (uint32_t i = 0U; i < NODE_RAFT_N; ++i) {
            if (((mask >> i) & 1U) != 0U) {
                cnt++;
            }
        }
        if (cnt > 1U) {
            ok = false;
        }
    }
    for (uint32_t i = 0U; i < NODE_RAFT_N; ++i) {
        for (uint32_t j = i + 1U; j < NODE_RAFT_N; ++j) {
            uint32_t lim =
                (r->commit_index[i] < r->commit_index[j]) ? r->commit_index[i] : r->commit_index[j];
            for (uint32_t k = 0U; k < lim && k < NODE_RAFT_LOG_CAP; ++k) {
                if (k < r->log_len[i] && k < r->log_len[j] &&
                    r->logs[i][k].cmd != r->logs[j][k].cmd) {
                    ok = false;
                }
            }
        }
    }
    if (!ok) {
        r->safety_violations++;
        if (r->tick < r->first_violation_tick) {
            r->first_violation_tick = r->tick;
        }
    }
    return ok;
}

void node_raft_tick(node_raft_cluster_t *r, uint32_t cmd_if_leader) {
    if (r == NULL) {
        return;
    }
    r->tick++;
    uint32_t q = raft_quorum(r);

    for (uint32_t i = 0U; i < NODE_NET_MAX_MSGS; ++i) {
        if (r->net[i].valid == 0U || r->net[i].deliver_tick > r->tick) {
            continue;
        }
        node_net_msg_t m;
        node_copy_bytes(&m, &r->net[i], sizeof(m));
        r->net[i].valid = 0U;

        if (m.dst >= NODE_RAFT_N || m.src >= NODE_RAFT_N) {
            continue;
        }
        if (r->crashed[m.dst] != 0U || r->partition_group[m.src] != r->partition_group[m.dst]) {
            continue;
        }
        if (m.term > r->current_term[m.dst]) {
            r->current_term[m.dst] = m.term;
            r->role[m.dst] = RAFT_ROLE_FOLLOWER;
            r->voted_for[m.dst] = UINT32_MAX;
        }

        if (m.kind == RAFT_MSG_REQ_VOTE) {
            bool can_vote = (m.term == r->current_term[m.dst]) &&
                            (r->voted_for[m.dst] == UINT32_MAX || r->voted_for[m.dst] == m.src);
            uint32_t my_last_idx = r->log_len[m.dst];
            uint32_t my_last_term = (my_last_idx > 0U) ? r->logs[m.dst][my_last_idx - 1U].term : 0U;
            bool up_to_date = (m.prev_term > my_last_term) ||
                              (m.prev_term == my_last_term && m.index >= my_last_idx);
            if (can_vote && up_to_date) {
                r->voted_for[m.dst] = m.src;
                r->election_timer[m.dst] =
                    4U + node_wrap_small((uint32_t)node_prng_next(&r->prng), 3U);
                raft_send_msg(r, RAFT_MSG_VOTE_RESP, m.dst, m.src, r->current_term[m.dst], 0U, 0U,
                              1U, 0U, 0U, 0U, 1U);
            }
        } else if (m.kind == RAFT_MSG_VOTE_RESP) {
            if (r->role[m.dst] == RAFT_ROLE_CANDIDATE && m.term == r->current_term[m.dst] &&
                m.success != 0U) {
                uint32_t bit = UINT32_C(1) << m.src;
                if ((r->votes_got[m.dst] & bit) == 0U) {
                    r->votes_got[m.dst] |= bit;
                    uint32_t vcnt = 0U;
                    for (uint32_t k = 0U; k < NODE_RAFT_N; ++k) {
                        if (((r->votes_got[m.dst] >> k) & 1U) != 0U) {
                            vcnt++;
                        }
                    }
                    if (vcnt >= q) {
                        r->role[m.dst] = RAFT_ROLE_LEADER;
                        if (r->current_term[m.dst] < 256U) {
                            r->leader_mask_by_term[r->current_term[m.dst]] |=
                                (UINT32_C(1) << m.dst);
                        }
                        for (uint32_t p = 0U; p < NODE_RAFT_N; ++p) {
                            r->next_idx[m.dst][p] = r->log_len[m.dst];
                            r->match_idx[m.dst][p] = 0U;
                        }
                        r->match_idx[m.dst][m.dst] = r->log_len[m.dst];
                    }
                }
            }
        } else if (m.kind == RAFT_MSG_APPEND) {
            if (m.term == r->current_term[m.dst]) {
                r->role[m.dst] = RAFT_ROLE_FOLLOWER;
                r->election_timer[m.dst] = 4U + m.dst;
                bool prev_ok = (m.index <= r->log_len[m.dst]) &&
                               (m.index == 0U || r->logs[m.dst][m.index - 1U].term == m.prev_term);
                if (!prev_ok) {
                    raft_send_msg(r, RAFT_MSG_APP_RESP, m.dst, m.src, r->current_term[m.dst],
                                  m.index, 0U, 0U, 0U, 0U, 0U, 1U);
                } else {
                    uint32_t last_new = m.index;
                    if (m.success != 0U && m.index < NODE_RAFT_LOG_CAP) {
                        if (m.index < r->log_len[m.dst] &&
                            r->logs[m.dst][m.index].term != m.entry_term) {
                            r->log_len[m.dst] = m.index;
                        }
                        r->logs[m.dst][m.index].term = m.entry_term;
                        r->logs[m.dst][m.index].cmd = m.val;
                        if (m.index + 1U > r->log_len[m.dst]) {
                            r->log_len[m.dst] = m.index + 1U;
                        }
                        last_new = m.index + 1U;
                    }
                    uint32_t c_cand = (m.leader_commit < last_new) ? m.leader_commit : last_new;
                    if (c_cand > r->commit_index[m.dst]) {
                        r->commit_index[m.dst] = c_cand;
                    }
                    raft_send_msg(r, RAFT_MSG_APP_RESP, m.dst, m.src, r->current_term[m.dst],
                                  last_new, 0U, 1U, 0U, 0U, 0U, 1U);
                }
            }
        } else if (m.kind == RAFT_MSG_APP_RESP) {
            if (r->role[m.dst] == RAFT_ROLE_LEADER && m.term == r->current_term[m.dst]) {
                if (m.success == 0U) {
                    if (r->next_idx[m.dst][m.src] > 0U) {
                        r->next_idx[m.dst][m.src]--;
                    }
                } else {
                    if (m.index > r->match_idx[m.dst][m.src]) {
                        r->match_idx[m.dst][m.src] = m.index;
                    }
                    r->next_idx[m.dst][m.src] = r->match_idx[m.dst][m.src];
                    for (uint32_t N = r->commit_index[m.dst] + 1U; N <= r->log_len[m.dst]; ++N) {
                        if (r->logs[m.dst][N - 1U].term == r->current_term[m.dst]) {
                            uint32_t cnt = 0U;
                            for (uint32_t p = 0U; p < NODE_RAFT_N; ++p) {
                                if (r->match_idx[m.dst][p] >= N) {
                                    cnt++;
                                }
                            }
                            if (cnt >= q) {
                                r->commit_index[m.dst] = N;
                                r->commits++;
                            }
                        }
                    }
                }
            }
        }
    }

    for (uint32_t i = 0U; i < NODE_RAFT_N; ++i) {
        if (r->crashed[i] != 0U) {
            continue;
        }
        if (r->role[i] == RAFT_ROLE_LEADER) {
            if (cmd_if_leader != 0U && r->log_len[i] < NODE_RAFT_LOG_CAP) {
                uint32_t slot = r->log_len[i]++;
                r->logs[i][slot].term = r->current_term[i];
                r->logs[i][slot].cmd = cmd_if_leader;
                r->match_idx[i][i] = r->log_len[i];
            }
            for (uint32_t peer = 0U; peer < NODE_RAFT_N; ++peer) {
                if (peer != i) {
                    uint32_t slot = (r->next_idx[i][peer] < r->log_len[i]) ? r->next_idx[i][peer]
                                                                           : r->log_len[i];
                    uint32_t p_term = (slot > 0U) ? r->logs[i][slot - 1U].term : 0U;
                    uint32_t has_entry = (slot < r->log_len[i]) ? 1U : 0U;
                    uint32_t e_term = (has_entry != 0U) ? r->logs[i][slot].term : 0U;
                    uint32_t e_cmd = (has_entry != 0U) ? r->logs[i][slot].cmd : 0U;
                    raft_send_msg(r, RAFT_MSG_APPEND, i, peer, r->current_term[i], slot, p_term,
                                  has_entry, e_cmd, e_term, r->commit_index[i], 1U);
                }
            }
        } else {
            if (r->election_timer[i] > 0U) {
                r->election_timer[i]--;
            }
            if (r->election_timer[i] == 0U) {
                r->current_term[i]++;
                r->role[i] = RAFT_ROLE_CANDIDATE;
                r->voted_for[i] = i;
                r->votes_got[i] = (UINT32_C(1) << i);
                r->election_timer[i] = 3U + node_wrap_small((uint32_t)node_prng_next(&r->prng), 4U);
                uint32_t last_idx = r->log_len[i];
                uint32_t last_term = (last_idx > 0U) ? r->logs[i][last_idx - 1U].term : 0U;
                for (uint32_t peer = 0U; peer < NODE_RAFT_N; ++peer) {
                    if (peer != i) {
                        raft_send_msg(r, RAFT_MSG_REQ_VOTE, i, peer, r->current_term[i], last_idx,
                                      last_term, 0U, 0U, 0U, 0U, 1U);
                    }
                }
            }
        }
    }

    (void)node_raft_check_safety(r);
}

/* --- BFT 3f+1 Deterministic Engine --- */

void node_bft_init(node_bft_cluster_t *b, uint32_t n, uint32_t f, uint32_t byz_mask,
                   uint32_t broken_quorum, uint64_t seed) {
    if (b == NULL) {
        return;
    }
    node_zero_bytes(b, sizeof(*b));
    b->n = (n > NODE_BFT_MAX_N) ? NODE_BFT_MAX_N : n;
    b->f = f;
    b->broken_quorum = broken_quorum;
    b->quorum = (broken_quorum != 0U) ? (2U * f) : (2U * f + 1U);
    b->byz_mask = byz_mask;
    b->first_violation_tick = UINT32_MAX;
    b->prng = (seed != UINT64_C(0)) ? seed : UINT64_C(0xBF73F001CAFEBABE);
}

void node_bft_step_round(node_bft_cluster_t *b, uint64_t val_a, uint64_t val_b,
                         const uint32_t part_split[NODE_BFT_MAX_N]) {
    if (b == NULL) {
        return;
    }
    b->round++;
    uint32_t votes_a = 0U;
    uint32_t votes_b = 0U;
    uint64_t commit_val[NODE_BFT_MAX_N];
    uint32_t commit_ok[NODE_BFT_MAX_N];
    node_zero_bytes(commit_val, sizeof(commit_val));
    node_zero_bytes(commit_ok, sizeof(commit_ok));

    for (uint32_t i = 0U; i < b->n; ++i) {
        if (b->crashed[i] != 0U) {
            continue;
        }
        bool is_byz = (((b->byz_mask >> i) & 1U) != 0U);
        if (is_byz) {
            votes_a++;
            votes_b++;
        } else {
            uint32_t p = (part_split != NULL) ? part_split[i] : 0U;
            if ((p & 1U) == 0U) {
                votes_a++;
            } else {
                votes_b++;
            }
        }
    }

    bool committed_a = (votes_a >= b->quorum);
    bool committed_b = (votes_b >= b->quorum);

    for (uint32_t i = 0U; i < b->n; ++i) {
        if (b->crashed[i] != 0U || (((b->byz_mask >> i) & 1U) != 0U)) {
            continue;
        }
        uint32_t p = (part_split != NULL) ? part_split[i] : 0U;
        if ((p & 1U) == 0U && committed_a) {
            commit_val[i] = val_a;
            commit_ok[i] = 1U;
            b->committed_hash[i] = val_a;
            b->committed_valid[i] = 1U;
            b->commit_count++;
        } else if ((p & 1U) != 0U && committed_b) {
            commit_val[i] = val_b;
            commit_ok[i] = 1U;
            b->committed_hash[i] = val_b;
            b->committed_valid[i] = 1U;
            b->commit_count++;
        }
    }

    for (uint32_t i = 0U; i < b->n; ++i) {
        if (commit_ok[i] == 0U) {
            continue;
        }
        for (uint32_t j = i + 1U; j < b->n; ++j) {
            if (commit_ok[j] != 0U && commit_val[i] != commit_val[j]) {
                b->safety_violations++;
                if (b->round < b->first_violation_tick) {
                    b->first_violation_tick = b->round;
                }
            }
        }
    }
}

/* --- Multi-Universe Deterministic Simulation Testing (DST) --- */

void node_dst_run(const node_dst_cfg_t *cfg, node_dst_report_t *out, node_raft_cluster_t *raft_ws,
                  node_bft_cluster_t *bft_ws, node_wal_t *wal_ws) {
    if (cfg == NULL || out == NULL || raft_ws == NULL || bft_ws == NULL || wal_ws == NULL) {
        return;
    }
    node_zero_bytes(out, sizeof(*out));
    out->seed = cfg->seed;
    out->universes = cfg->universes;
    out->min_witness_tick = UINT64_MAX;

    uint64_t rng = (cfg->seed != UINT64_C(0)) ? cfg->seed : UINT64_C(0x13572468ACE02468);
    uint64_t root_acc = UINT64_C(0x4E4F444544535431);

    for (uint32_t u = 0U; u < cfg->universes; ++u) {
        uint64_t u_seed = node_prng_next(&rng);
        node_raft_init(raft_ws, u_seed, cfg->broken_quorum);
        node_bft_init(bft_ws, 4U, 1U, UINT32_C(8), cfg->broken_quorum, u_seed ^ UINT64_C(0x55));
        node_wal_init(wal_ws);

        node_gcounter_t gc_a;
        node_gcounter_t gc_b;
        node_gcounter_t gc_c;
        node_gcounter_init(&gc_a);
        node_gcounter_init(&gc_b);
        node_gcounter_init(&gc_c);

        uint32_t bft_split[NODE_BFT_MAX_N];
        for (uint32_t k = 0U; k < NODE_BFT_MAX_N; ++k) {
            bft_split[k] = (k < 2U) ? 0U : 1U;
        }

        for (uint32_t t = 0U; t < cfg->ticks_per_universe; ++t) {
            out->ticks_total++;
            uint64_t ev = node_prng_next(&rng);
            uint32_t roll = (uint32_t)(ev & UINT64_C(127));
            if (roll < cfg->fault_prob_128) {
                out->faults_injected++;
                uint32_t kind = (uint32_t)((ev >> 8U) & UINT64_C(3));
                if (kind == 0U || kind == 1U) {
                    out->partitions++;
                    uint32_t pcut = (uint32_t)((ev >> 12U) & UINT64_C(3)) + 1U;
                    for (uint32_t n = 0U; n < NODE_RAFT_N; ++n) {
                        raft_ws->partition_group[n] = (n < pcut) ? 0U : 1U;
                    }
                } else {
                    out->crashes++;
                    uint32_t victim =
                        node_wrap_small((uint32_t)((ev >> 16U) & UINT64_C(7)), NODE_RAFT_N);
                    raft_ws->crashed[victim] ^= 1U;
                }
            } else {
                for (uint32_t n = 0U; n < NODE_RAFT_N; ++n) {
                    raft_ws->partition_group[n] = 0U;
                    raft_ws->crashed[n] = 0U;
                }
            }

            uint32_t cmd = ((t & 3U) == 0U) ? (100U + t + u) : 0U;
            node_raft_tick(raft_ws, cmd);
            node_bft_step_round(bft_ws, UINT64_C(0xAAAA0000) + (uint64_t)t,
                                UINT64_C(0xBBBB0000) + (uint64_t)t, bft_split);

            uint32_t ni = node_wrap_small((uint32_t)(ev & UINT64_C(7)), NODE_CRDT_NODES);
            uint64_t dv = ((ev >> 20U) & UINT64_C(7)) + UINT64_C(1);
            if ((t & 1U) == 0U) {
                node_gcounter_inc(&gc_a, ni, dv);
            } else {
                node_gcounter_inc(&gc_b, ni, dv);
            }
            node_gcounter_merge(&gc_c, &gc_a);
            node_gcounter_merge(&gc_c, &gc_b);

            if ((t & 3U) == 1U && wal_ws->len + 2U <= NODE_WAL_MAX_RECS) {
                uint32_t txid = wal_ws->next_tx_id++;
                uint32_t page_k = (uint32_t)((ev >> 24U) & UINT64_C(63));
                (void)node_wal_append_data(wal_ws, txid, page_k, ev);
                (void)node_wal_append_commit(wal_ws, txid);
            }
        }

        node_gcounter_merge(&gc_a, &gc_b);
        node_gcounter_merge(&gc_b, &gc_a);
        node_gcounter_merge(&gc_c, &gc_a);
        if (node_gcounter_equal(&gc_a, &gc_b) && node_gcounter_equal(&gc_b, &gc_c)) {
            out->crdt_converged++;
        }

        uint64_t pages_a[NODE_PAGE_COUNT];
        uint64_t pages_b[NODE_PAGE_COUNT];
        uint32_t txs_a = 0U;
        uint32_t txs_b = 0U;
        uint64_t mr_a = UINT64_C(0);
        uint64_t mr_b = UINT64_C(0);
        (void)node_wal_recover(wal_ws, wal_ws->len, UINT32_MAX, UINT64_C(0), pages_a, &txs_a,
                               &mr_a);
        (void)node_wal_recover(wal_ws, wal_ws->len, wal_ws->len, UINT64_C(0), pages_b, &txs_b,
                               &mr_b);
        if (txs_a == txs_b && mr_a == mr_b) {
            out->wal_recoveries_ok++;
        }

        out->commits += (uint64_t)raft_ws->commits + (uint64_t)bft_ws->commit_count;
        uint32_t u_viols = raft_ws->safety_violations + bft_ws->safety_violations;
        out->violations_found += (uint64_t)u_viols;
        if (u_viols > 0U) {
            uint32_t wtick = (raft_ws->first_violation_tick < bft_ws->first_violation_tick)
                                 ? raft_ws->first_violation_tick
                                 : bft_ws->first_violation_tick;
            if ((uint64_t)wtick < out->min_witness_tick) {
                out->min_witness_tick = (uint64_t)wtick;
                out->witness_universe = (uint64_t)u;
            }
        }

        root_acc ^= mr_a;
        root_acc *= UINT64_C(0x100000001B3);
        root_acc ^= (uint64_t)raft_ws->commits + ((uint64_t)u_viols << 32U);
    }

    if (out->violations_found == UINT64_C(0)) {
        out->min_witness_tick = UINT64_C(0);
    }
    out->state_root = node_sha256_u64(&root_acc, sizeof(root_acc)) ^ root_acc;
}

void node_arena_fill_summary(NodeArena *arena, const node_vm_t *vm,
                             const node_dbsp_join_state_t *dbsp, const node_wal_t *wal,
                             const node_dst_report_t *dst) {
    if (arena == NULL) {
        return;
    }
    node_zero_bytes(arena, sizeof(*arena));
    arena->map.hdr.magic = NODE_SCHEMA_MAGIC;
    arena->map.hdr.version = NODE_SCHEMA_VERSION;
    if (vm != NULL) {
        arena->map.vm_meta.pc = (uint64_t)vm->state.pc;
        arena->map.vm_meta.fuel_budget = (uint64_t)vm->fuel_budget;
        arena->map.vm_meta.fuel_used = (uint64_t)(vm->fuel_budget - vm->state.fuel);
        arena->map.vm_meta.fault_code = (uint64_t)vm->state.fault;
        arena->map.vm_meta.reg_hash = node_vm_state_hash(vm);
        arena->map.vm_meta.snap_count = (uint64_t)vm->snap_count;
    }
    if (dbsp != NULL) {
        arena->map.dbsp_meta[0].epoch = dbsp->epoch;
        arena->map.dbsp_meta[0].base_rows = (uint64_t)dbsp->out_state.len;
        arena->map.dbsp_meta[0].inc_ops = dbsp->inc_ops;
        arena->map.dbsp_meta[0].full_ops = dbsp->full_ops;
        arena->map.dbsp_meta[0].state_root = node_zset_hash(&dbsp->out_state);
    }
    if (wal != NULL) {
        arena->map.wal_meta[0].committed_lsn = (uint64_t)wal->len;
        arena->map.wal_meta[0].last_crc = wal->chain_hash;
    }
    if (dst != NULL) {
        arena->map.dst_meta[0].seed = dst->seed;
        arena->map.dst_meta[0].universes = dst->universes;
        arena->map.dst_meta[0].ticks_total = dst->ticks_total;
        arena->map.dst_meta[0].faults_injected = dst->faults_injected;
        arena->map.dst_meta[0].partitions = dst->partitions;
        arena->map.dst_meta[0].crashes = dst->crashes;
        arena->map.dst_meta[0].violations_found = dst->violations_found;
        arena->map.dst_meta[0].min_witness_tick = dst->min_witness_tick;
    }
}
