#if defined(__linux__) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "node.h"
#include "node_cert.h"
#include "node_disk_wal.h"
#include "node_net_udp.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Zero heap allocations: all large state structs live statically in .bss. */
static node_vm_t g_vm;
static node_vm_t g_vm2;
static node_vm_prog_t g_prog;
static node_dbsp_join_state_t g_dbsp;
static node_zset_t g_full_a;
static node_zset_t g_full_b;
static node_zset_t g_full_join;
static node_zset_t g_da;
static node_zset_t g_db;
static node_zset_t g_delta_out;
static node_zset_t g_tmp_z1;
static node_zset_t g_tmp_z2;
static node_graph_t g_graph;
static node_wal_t g_wal;
static node_raft_cluster_t g_raft;
static node_bft_cluster_t g_bft;
static node_cert_ws_t g_cert_ws;
static NodeArena g_arena;
static node_dbsp_reach_t g_reach;
static node_dyn_tri_t g_tri;
static node_replay_win_t g_win;

static void build_demo_vm_prog(node_vm_prog_t *prog) {
    memset(prog, 0, sizeof(*prog));
    uint32_t k = 0U;
    prog->insns[k++] = (node_vm_insn_t){NODE_OP_MOVI, 0U, 0U, 0U, UINT64_C(42)};
    prog->insns[k++] = (node_vm_insn_t){NODE_OP_MOVI, 1U, 0U, 0U, UINT64_C(99)};
    prog->insns[k++] = (node_vm_insn_t){NODE_OP_ADD, 2U, 0U, 1U, UINT64_C(0)};
    prog->insns[k++] = (node_vm_insn_t){NODE_OP_STORE_CAP, 0U, 2U, 0U, UINT64_C(4)};
    prog->insns[k++] = (node_vm_insn_t){NODE_OP_LOAD_CAP, 3U, 0U, 0U, UINT64_C(4)};
    prog->insns[k++] = (node_vm_insn_t){NODE_OP_EMIT, 0U, 3U, 0U, UINT64_C(0)};
    prog->insns[k++] = (node_vm_insn_t){NODE_OP_ATTENUATE, 1U, 0U, (uint16_t)(NODE_CAP_R),
                                        (uint64_t)UINT32_C(0) | ((uint64_t)UINT32_C(16) << 32U)};
    prog->insns[k++] = (node_vm_insn_t){NODE_OP_LOAD_CAP, 4U, 1U, 0U, UINT64_C(4)};
    prog->insns[k++] = (node_vm_insn_t){NODE_OP_EMIT, 0U, 4U, 0U, UINT64_C(0)};
    prog->insns[k++] = (node_vm_insn_t){NODE_OP_HALT, 0U, 0U, 0U, UINT64_C(0)};
    prog->len = k;
}

static bool test_01_vm_caps(void) {
    node_vm_init(&g_vm, 64U);
    if (!node_vm_grant_cap(&g_vm, 0U, 0U, 10U, 8U, NODE_CAP_R | NODE_CAP_W)) {
        return false;
    }
    g_vm.state.mem[40] = UINT64_C(0xDEADBEEF);
    memset(&g_prog, 0, sizeof(g_prog));
    g_prog.insns[0] = (node_vm_insn_t){NODE_OP_MOVI, 0U, 0U, 0U, UINT64_C(777)};
    g_prog.insns[1] = (node_vm_insn_t){NODE_OP_STORE_CAP, 0U, 0U, 0U, UINT64_C(12)};
    g_prog.insns[2] = (node_vm_insn_t){NODE_OP_LOAD_CAP, 1U, 0U, 0U, UINT64_C(12)};
    g_prog.insns[3] = (node_vm_insn_t){NODE_OP_HALT, 0U, 0U, 0U, UINT64_C(0)};
    g_prog.len = 4U;
    node_vm_run(&g_vm, &g_prog, 16U);
    if (g_vm.state.fault != NODE_FAULT_NONE || g_vm.state.regs[1] != UINT64_C(777) ||
        g_vm.state.mem[40] != UINT64_C(0xDEADBEEF)) {
        return false;
    }

    /* Missing NODE_CAP_W must fault and leave target untouched */
    node_vm_init(&g_vm, 32U);
    (void)node_vm_grant_cap(&g_vm, 0U, 0U, 10U, 8U, NODE_CAP_R);
    g_vm.state.mem[12] = UINT64_C(111);
    memset(&g_prog, 0, sizeof(g_prog));
    g_prog.insns[0] = (node_vm_insn_t){NODE_OP_MOVI, 0U, 0U, 0U, UINT64_C(999)};
    g_prog.insns[1] = (node_vm_insn_t){NODE_OP_STORE_CAP, 0U, 0U, 0U, UINT64_C(12)};
    g_prog.len = 2U;
    node_vm_run(&g_vm, &g_prog, 8U);
    if (g_vm.state.fault != NODE_FAULT_CAP || g_vm.state.mem[12] != UINT64_C(111)) {
        return false;
    }

    /* Missing NODE_CAP_R must fault */
    node_vm_init(&g_vm, 32U);
    (void)node_vm_grant_cap(&g_vm, 0U, 0U, 10U, 8U, NODE_CAP_W);
    g_prog.insns[0] = (node_vm_insn_t){NODE_OP_LOAD_CAP, 0U, 0U, 0U, UINT64_C(12)};
    g_prog.len = 1U;
    node_vm_run(&g_vm, &g_prog, 8U);
    if (g_vm.state.fault != NODE_FAULT_CAP) {
        return false;
    }

    /* Out-of-bounds below base or >= base+len must fault */
    node_vm_init(&g_vm, 32U);
    (void)node_vm_grant_cap(&g_vm, 0U, 0U, 10U, 8U, NODE_CAP_R | NODE_CAP_W);
    g_prog.insns[0] = (node_vm_insn_t){NODE_OP_STORE_CAP, 0U, 0U, 0U, UINT64_C(9)};
    g_prog.len = 1U;
    node_vm_run(&g_vm, &g_prog, 4U);
    if (g_vm.state.fault != NODE_FAULT_CAP) {
        return false;
    }

    node_vm_init(&g_vm, 32U);
    (void)node_vm_grant_cap(&g_vm, 0U, 0U, 10U, 8U, NODE_CAP_R | NODE_CAP_W);
    g_prog.insns[0] = (node_vm_insn_t){NODE_OP_STORE_CAP, 0U, 0U, 0U, UINT64_C(18)};
    g_prog.len = 1U;
    node_vm_run(&g_vm, &g_prog, 4U);
    return g_vm.state.fault == NODE_FAULT_CAP;
}

static bool test_02_vm_attenuate(void) {
    node_vm_init(&g_vm, 32U);
    (void)node_vm_grant_cap(&g_vm, 0U, 7U, 16U, 32U, NODE_CAP_R | NODE_CAP_W | NODE_CAP_G);
    (void)node_vm_grant_cap(&g_vm, 2U, 7U, 16U, 32U, NODE_CAP_R | NODE_CAP_W);

    /* Without NODE_CAP_G cannot attenuate */
    if (node_vm_attenuate_cap(&g_vm, 3U, 2U, 16U, 8U, NODE_CAP_R)) {
        return false;
    }
    /* Cannot escalate NODE_CAP_X not in parent */
    if (node_vm_attenuate_cap(&g_vm, 3U, 0U, 16U, 8U, NODE_CAP_R | NODE_CAP_X)) {
        return false;
    }
    /* Cannot widen base below src.base or end above src.base + src.len */
    if (node_vm_attenuate_cap(&g_vm, 3U, 0U, 15U, 8U, NODE_CAP_R)) {
        return false;
    }
    if (node_vm_attenuate_cap(&g_vm, 3U, 0U, 32U, 17U, NODE_CAP_R)) {
        return false;
    }
    /* Valid strict sub-slice succeeds and inherits region_id */
    if (!node_vm_attenuate_cap(&g_vm, 1U, 0U, 20U, 12U, NODE_CAP_R)) {
        return false;
    }
    return g_vm.state.caps[1].region_id == 7U && g_vm.state.caps[1].base == 20U &&
           g_vm.state.caps[1].len == 12U && g_vm.state.caps[1].rights == NODE_CAP_R;
}

static bool test_03_vm_fuel_replay(void) {
    /* Infinite loop program must halt strictly with NODE_FAULT_FUEL in 10 steps */
    node_vm_init(&g_vm, 10U);
    memset(&g_prog, 0, sizeof(g_prog));
    g_prog.insns[0] = (node_vm_insn_t){NODE_OP_MOVI, 0U, 0U, 0U, UINT64_C(1)};
    g_prog.insns[1] = (node_vm_insn_t){NODE_OP_ADD, 1U, 1U, 0U, UINT64_C(0)};
    g_prog.insns[2] = (node_vm_insn_t){NODE_OP_JNZ, 0U, 0U, 0U, UINT64_C(1)};
    g_prog.len = 3U;
    node_vm_run(&g_vm, &g_prog, 100U);
    if (g_vm.state.halted != 1U || g_vm.state.fault != NODE_FAULT_FUEL || g_vm.state.fuel != 0U ||
        g_vm.state.steps != 10U) {
        return false;
    }

    /* Deterministic snapshot + post-snap corruption + restore + replay */
    build_demo_vm_prog(&g_prog);
    node_vm_init(&g_vm, 64U);
    (void)node_vm_grant_cap(&g_vm, 0U, 0U, 0U, 32U, NODE_CAP_R | NODE_CAP_W | NODE_CAP_G);
    node_vm_run(&g_vm, &g_prog, 4U);
    if (!node_vm_snap_push(&g_vm)) {
        return false;
    }
    uint64_t snap_h = node_vm_state_hash(&g_vm);
    node_vm_run(&g_vm, &g_prog, 32U);
    uint64_t full_h = node_vm_state_hash(&g_vm);
    if (full_h == snap_h) {
        return false;
    }
    if (!node_vm_snap_restore(&g_vm, 0U)) {
        return false;
    }
    if (node_vm_state_hash(&g_vm) != snap_h) {
        return false;
    }
    node_vm_run(&g_vm, &g_prog, 32U);
    return node_vm_state_hash(&g_vm) == full_h && g_vm.state.emit_len == 2U &&
           g_vm.state.emit_log[0] == UINT64_C(141);
}

static bool test_04_zset_abelian(void) {
    node_zset_init(&g_full_a);
    node_zset_init(&g_full_b);
    (void)node_zset_add_entry(&g_full_a, 10U, 3);
    (void)node_zset_add_entry(&g_full_a, 20U, -2);
    (void)node_zset_add_entry(&g_full_a, 10U, -3); /* cancels to 0 */
    if (g_full_a.len != 1U || g_full_a.entries[0].key != 20U || g_full_a.entries[0].weight != -2) {
        return false;
    }
    (void)node_zset_add_entry(&g_full_a, 30U, 5);
    (void)node_zset_add_entry(&g_full_b, 20U, 2);
    (void)node_zset_add_entry(&g_full_b, 40U, 7);

    if (!node_zset_add(&g_full_a, &g_full_b, &g_tmp_z1)) {
        return false;
    }
    /* Expect keys 30:5, 40:7 (key 20 cancelled!) */
    if (g_tmp_z1.len != 2U || g_tmp_z1.entries[0].key != 30U || g_tmp_z1.entries[1].key != 40U) {
        return false;
    }
    /* (A - B) + B == A */
    if (!node_zset_sub(&g_full_a, &g_full_b, &g_tmp_z1) ||
        !node_zset_add(&g_tmp_z1, &g_full_b, &g_tmp_z2) || !node_zset_equal(&g_tmp_z2, &g_full_a)) {
        return false;
    }
    /* A - A == 0 */
    if (!node_zset_sub(&g_full_a, &g_full_a, &g_tmp_z1)) {
        return false;
    }
    return g_tmp_z1.len == 0U;
}

static bool test_05_dbsp_bilinear(void) {
    node_dbsp_join_init(&g_dbsp);
    node_zset_init(&g_full_a);
    node_zset_init(&g_full_b);

    for (uint32_t ep = 0U; ep < 10U; ++ep) {
        node_zset_init(&g_da);
        node_zset_init(&g_db);
        for (uint32_t k = 1U; k <= 16U; ++k) {
            if (((k + ep) % 3U) == 0U) {
                (void)node_zset_add_entry(&g_da, k, (ep & 1U) ? 2 : -1);
            }
            if (((k * 2U + ep) % 5U) == 0U || ep == 0U) {
                (void)node_zset_add_entry(&g_db, k, ((ep + k) & 1U) ? 1 : -1);
            }
        }
        /* Ensure simultaneous non-zero deltas in both A and B on same key! */
        (void)node_zset_add_entry(&g_da, 100U, (int64_t)ep + 1);
        (void)node_zset_add_entry(&g_db, 100U, (ep & 1U) ? -2 : 3);

        if (!node_dbsp_join_step(&g_dbsp, &g_da, &g_db, &g_delta_out)) {
            return false;
        }
        if (!node_zset_add(&g_full_a, &g_da, &g_tmp_z1)) {
            return false;
        }
        g_full_a = g_tmp_z1;
        if (!node_zset_add(&g_full_b, &g_db, &g_tmp_z1)) {
            return false;
        }
        g_full_b = g_tmp_z1;
        uint64_t ops = 0U;
        if (!node_zset_join(&g_full_a, &g_full_b, &g_full_join, &ops)) {
            return false;
        }
        if (!node_zset_equal(&g_dbsp.out_state, &g_full_join)) {
            return false;
        }
    }
    return g_dbsp.epoch == 10U;
}

static bool test_06_wcoj_leapfrog(void) {
    /* Graph combining balanced clique (0..4), forward skew hub (1->10..59), and reverse skew */
    node_graph_init(&g_graph, 64U);
    /* K4 on 0..3 oriented u < v => C(4,3) = 4 triangles */
    for (uint32_t u = 0U; u < 4U; ++u) {
        for (uint32_t v = u + 1U; v < 4U; ++v) {
            (void)node_graph_add_edge(&g_graph, u, v);
        }
    }
    /* Hub vertex 5 has deg_out = 50 (5 -> 10..59); vertices 6..8 point into 5 and 10..11 */
    for (uint32_t w = 10U; w < 60U; ++w) {
        (void)node_graph_add_edge(&g_graph, 5U, w);
    }
    /* (4 -> 5, 4 -> 10, 4 -> 11) -> 2 more triangles (4,5,10),(4,5,11) triggering deg_u << 2 <
     * deg_v */
    (void)node_graph_add_edge(&g_graph, 4U, 5U);
    (void)node_graph_add_edge(&g_graph, 4U, 10U);
    (void)node_graph_add_edge(&g_graph, 4U, 11U);
    /* High-degree source 0 also exercises (deg_v << 2) < deg_u against leaf 6..7 */
    for (uint32_t t = 20U; t < 40U; ++t) {
        (void)node_graph_add_edge(&g_graph, 0U, t);
    }
    (void)node_graph_add_edge(&g_graph, 20U, 21U); /* adds triangle (0, 20, 21) */
    (void)node_graph_add_edge(&g_graph, 20U, 22U); /* adds triangle (0, 20, 22) */

    if (!node_graph_finalize(&g_graph)) {
        return false;
    }
    if (node_graph_add_edge(&g_graph, 999U, 0U)) {
        return false;
    }
    uint64_t w_probes = 0U;
    uint64_t wedges = 0U;
    uint64_t b_probes = 0U;
    uint64_t wt = node_wcoj_count_triangles(&g_graph, &w_probes);
    uint64_t bt = node_binjoin_count_triangles(&g_graph, &wedges, &b_probes);
    return wt == 10U && bt == 10U && w_probes > 0U && wedges > 0U;
}

static bool test_07_merkle_wal_chain(void) {
    node_wal_init(&g_wal);
    (void)node_wal_append_data(&g_wal, 1U, 3U, UINT64_C(0x1111));
    (void)node_wal_append_data(&g_wal, 1U, 7U, UINT64_C(0x2222));
    (void)node_wal_append_commit(&g_wal, 1U);
    (void)node_wal_append_data(&g_wal, 2U, 3U, UINT64_C(0x9999));
    (void)node_wal_append_commit(&g_wal, 2U);

    uint64_t pages[NODE_PAGE_COUNT];
    uint32_t txs = 0U;
    uint64_t mr = 0U;
    uint32_t valid = node_wal_recover(&g_wal, g_wal.len, UINT32_MAX, UINT64_C(0), pages, &txs, &mr);
    if (valid != 5U || txs != 2U || pages[3] != UINT64_C(0x9999) || pages[7] != UINT64_C(0x2222)) {
        return false;
    }

    /* Splice a self-consistent forged record from a divergent chain (valid rec_hash, wrong
     * prev_hash) */
    static node_wal_t g_wal_forge;
    node_wal_init(&g_wal_forge);
    g_wal_forge.chain_hash ^= UINT64_C(0xF00D);
    (void)node_wal_append_data(&g_wal_forge, 2U, 3U, UINT64_C(0x8888));
    node_wal_rec_t saved_rec = g_wal.recs[3];
    g_wal.recs[3] = g_wal_forge.recs[0];
    valid = node_wal_recover(&g_wal, g_wal.len, UINT32_MAX, UINT64_C(0), pages, &txs, &mr);
    g_wal.recs[3] = saved_rec;
    if (valid != 3U || txs != 1U || pages[3] != UINT64_C(0x1111)) {
        return false;
    }

    /* Corrupt via mask at index 3 */
    valid = node_wal_recover(&g_wal, g_wal.len, 3U, UINT64_C(0x80), pages, &txs, &mr);
    if (valid != 3U || txs != 1U || pages[3] != UINT64_C(0x1111)) {
        return false;
    }

    /* Merkle tree proof & single-bit tamper rejection */
    uint8_t root[32];
    node_merkle_root64(pages, root);
    node_merkle_proof_t prf;
    if (!node_merkle_proof64(pages, 3U, &prf) || !node_merkle_verify_proof64(&prf, root)) {
        return false;
    }
    prf.leaf_val ^= UINT64_C(1);
    if (node_merkle_verify_proof64(&prf, root)) {
        return false;
    }
    prf.leaf_val ^= UINT64_C(1);
    prf.siblings[4][0] ^= UINT8_C(1);
    return !node_merkle_verify_proof64(&prf, root);
}

static bool test_08_wal_crash_recover(void) {
    node_wal_init(&g_wal);
    (void)node_wal_append_data(&g_wal, 1U, 10U, UINT64_C(100));
    (void)node_wal_append_commit(&g_wal, 1U);
    /* tx2 staged then never committed, followed by tx3 committed on different key! */
    (void)node_wal_append_data(&g_wal, 2U, 10U, UINT64_C(200));
    (void)node_wal_append_data(&g_wal, 3U, 11U, UINT64_C(300));
    (void)node_wal_append_commit(&g_wal, 3U);

    uint64_t pages[NODE_PAGE_COUNT];
    uint32_t txs = 0U;
    uint64_t mr = 0U;
    /* Cut before commit 1 -> 0 committed */
    (void)node_wal_recover(&g_wal, 1U, UINT32_MAX, UINT64_C(0), pages, &txs, &mr);
    if (txs != 0U || pages[10] != UINT64_C(0)) {
        return false;
    }
    /* Full replay: tx1 applies key10=100; uncommitted tx2 write to key10 MUST NOT apply when tx3
     * commits key11=300! */
    (void)node_wal_recover(&g_wal, g_wal.len, UINT32_MAX, UINT64_C(0), pages, &txs, &mr);
    return txs == 2U && pages[10] == UINT64_C(100) && pages[11] == UINT64_C(300);
}

static bool test_09_crdt_semilattice(void) {
    node_gcounter_t a, b, c;
    node_gcounter_init(&a);
    node_gcounter_init(&b);
    node_gcounter_inc(&a, 0U, 5U);
    node_gcounter_inc(&a, 1U, 2U);
    node_gcounter_inc(&b, 0U, 5U); /* overlap on slot 0: max(5,5)=5, NOT 10! */
    node_gcounter_inc(&b, 2U, 7U);
    c = a;
    node_gcounter_merge(&c, &b);
    if (node_gcounter_value(&c) != UINT64_C(14) || c.slots[0] != UINT64_C(5)) {
        return false;
    }

    node_pncounter_t pn1, pn2;
    node_pncounter_init(&pn1);
    node_pncounter_init(&pn2);
    node_pncounter_inc(&pn1, 0U, 10U);
    node_pncounter_dec(&pn2, 1U, 4U);
    node_pncounter_merge(&pn1, &pn2);
    if (node_pncounter_value(&pn1) != INT64_C(6)) {
        return false;
    }

    node_lww_reg_t l1, l2;
    node_lww_init(&l1, 50U, 1U, 111U);
    node_lww_init(&l2, 50U, 2U, 222U); /* Equal ts: higher node_id wins */
    node_lww_merge(&l1, &l2);
    return l1.val == UINT64_C(222) && l1.node_id == UINT64_C(2);
}

static bool test_10_raft_quorum_safety(void) {
    node_raft_init(&g_raft, UINT64_C(12345), 0U);
    for (uint32_t t = 0U; t < 40U; ++t) {
        if (t == 15U) {
            g_raft.partition_group[3] = 1U;
            g_raft.partition_group[4] = 1U;
        }
        if (t == 28U) {
            g_raft.partition_group[3] = 0U;
            g_raft.partition_group[4] = 0U;
        }
        node_raft_tick(&g_raft, 1000U + t);
    }
    if (g_raft.safety_violations != 0U || g_raft.commits == 0U) {
        return false;
    }
    /* Duplicate vote check on same term */
    node_raft_init(&g_raft, UINT64_C(999), 0U);
    g_raft.current_term[1] = 2U;
    g_raft.voted_for[1] = 0U;
    memset(&g_raft.net[0], 0, sizeof(g_raft.net[0]));
    g_raft.net[0].valid = 1U;
    g_raft.net[0].kind = 1U; /* REQ_VOTE */
    g_raft.net[0].src = 4U;
    g_raft.net[0].dst = 1U;
    g_raft.net[0].term = 2U;
    g_raft.net[0].deliver_tick = 1U;
    node_raft_tick(&g_raft, 0U);
    if (g_raft.voted_for[1] != 0U) {
        return false;
    }
    /* Higher-term REQ_VOTE must reset voted_for to allow new candidate in term 5 */
    node_raft_init(&g_raft, UINT64_C(999), 0U);
    g_raft.current_term[1] = 2U;
    g_raft.voted_for[1] = 0U;
    memset(&g_raft.net[0], 0, sizeof(g_raft.net[0]));
    g_raft.net[0].valid = 1U;
    g_raft.net[0].kind = 1U; /* REQ_VOTE */
    g_raft.net[0].src = 4U;
    g_raft.net[0].dst = 1U;
    g_raft.net[0].term = 5U;
    g_raft.net[0].deliver_tick = 1U;
    node_raft_tick(&g_raft, 0U);
    if (g_raft.voted_for[1] != 4U || g_raft.current_term[1] != 5U) {
        return false;
    }
    /* Clean broken_quorum=0 must NOT allow 2 leaders in same term */
    node_raft_init(&g_raft, UINT64_C(555), 0U);
    g_raft.partition_group[0] = 0U;
    g_raft.partition_group[1] = 0U;
    g_raft.partition_group[2] = 1U;
    g_raft.partition_group[3] = 1U;
    g_raft.partition_group[4] = 1U;
    for (uint32_t t = 0U; t < 16U; ++t) {
        node_raft_tick(&g_raft, 50U + t);
    }
    if (g_raft.safety_violations != 0U) {
        return false;
    }
    return true;
}

static bool test_11_bft_equivocation(void) {
    uint32_t split[NODE_BFT_MAX_N] = {0U, 0U, 1U, 1U, 0U, 0U, 0U, 0U};
    /* Clean N=4, f=1, q=3, node 3 is Byzantine equivocating */
    node_bft_init(&g_bft, 4U, 1U, UINT32_C(8), 0U, UINT64_C(77));
    node_bft_step_round(&g_bft, UINT64_C(0xAA), UINT64_C(0xBB), split);
    if (g_bft.safety_violations != 0U) {
        return false;
    }
    /* Broken quorum q=2 -> votes_a=3, votes_b=2 -> both A and B commit -> safety violation! */
    node_bft_init(&g_bft, 4U, 1U, UINT32_C(8), 1U, UINT64_C(77));
    node_bft_step_round(&g_bft, UINT64_C(0xAA), UINT64_C(0xBB), split);
    return g_bft.safety_violations > 0U && g_bft.first_violation_tick == 1U;
}

static bool test_12_dst_prng_faults(void) {
    node_dst_cfg_t cfg = {UINT64_C(20261123), 8U, 32U, 0U, 40U};
    node_dst_report_t r1, r2;
    node_dst_run(&cfg, &r1, &g_raft, &g_bft, &g_wal);
    node_dst_run(&cfg, &r2, &g_raft, &g_bft, &g_wal);
    if (r1.state_root != r2.state_root || r1.commits != r2.commits || r1.violations_found != 0U ||
        r1.faults_injected == 0U || r1.partitions == 0U || r1.crashes == 0U ||
        r1.crdt_converged != 8U || r1.wal_recoveries_ok != 8U) {
        return false;
    }
    cfg.broken_quorum = 1U;
    node_dst_run(&cfg, &r2, &g_raft, &g_bft, &g_wal);
    return r2.violations_found > 0U && r2.min_witness_tick > 0U && r2.min_witness_tick <= 32U;
}

static bool test_13_pncounter_merge_dups(void) {
    node_pncounter_t x, y, z;
    node_pncounter_init(&x);
    node_pncounter_init(&y);
    node_pncounter_inc(&x, 3U, 20U);
    node_pncounter_dec(&x, 4U, 5U);
    y = x;
    node_pncounter_dec(&y, 4U, 2U);
    z = x;
    node_pncounter_merge(&z, &y);
    node_pncounter_merge(&z, &y);
    return node_pncounter_value(&z) == INT64_C(13);
}

static bool test_14_arena_schema_fill(void) {
    node_arena_fill_summary(&g_arena, &g_vm, &g_dbsp, &g_wal, NULL);
    return sizeof(g_arena) == 16384U && g_arena.map.hdr.magic == NODE_SCHEMA_MAGIC &&
           g_arena.map.hdr.version == NODE_SCHEMA_VERSION && g_arena.map.dbsp_meta[0].epoch == 10U;
}

static bool test_15_certs_fir_eval(void) {
    flow_ir_builder_init(&g_cert_ws, "cap_chk");
    flow_ir_prog_t *p = &g_cert_ws.ir_prog;
    p->mult = FLOW_IR_MULT_CARTESIAN;
    p->num_inputs = 1U;
    p->inputs[0] = 0U;
    p->vals[0].width = 4U;
    p->vals[0].is_classical = 1U;
    (void)snprintf(p->vals[0].name, sizeof(p->vals[0].name), "in4");
    p->num_vals = 1U;
    uint32_t c1 = flow_ir_emit_const(p, 4U, UINT64_C(5), "c5");
    uint32_t xr = flow_ir_emit_op2(p, FLOW_IR_OP_XOR_VEC, 4U, 0U, c1, "xr");
    p->num_outputs = 1U;
    p->outputs[0] = xr;
    if (!flow_ir_encode_bytes(p, g_cert_ws.wire_buf, sizeof(g_cert_ws.wire_buf),
                              &g_cert_ws.wire_len)) {
        return false;
    }
    if (flow_ir_load_bytes_fiber(&g_cert_ws.ir_reloaded, g_cert_ws.wire_buf, g_cert_ws.wire_len) !=
        FLOW_IR_FIBER_COMMITTED) {
        return false;
    }
    uint64_t ins[1] = {UINT64_C(3)};
    uint64_t outs[1] = {UINT64_C(0)};
    if (!flow_ir_eval_u64(&g_cert_ws.ir_reloaded, ins, outs) || outs[0] != UINT64_C(6)) {
        return false;
    }

    /* Constant-time MAC, eq32 & Z-set overflow checks */
    uint8_t key[32];
    uint8_t tag[32];
    for (size_t i = 0U; i < 32U; ++i) {
        key[i] = (uint8_t)(i * 7U + 3U);
    }
    node_net_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.valid = 1U;
    msg.kind = 3U;
    msg.src = 0U;
    msg.dst = 2U;
    msg.term = 5U;
    msg.val = 0xCAFEU;
    node_net_msg_mac(key, &msg, tag);
    if (!node_net_msg_verify(key, &msg, tag)) {
        return false;
    }
    msg.term ^= 1U;
    if (node_net_msg_verify(key, &msg, tag)) {
        return false;
    }
    node_zset_init(&g_tmp_z1);
    if (node_zset_add_entry(&g_tmp_z1, 1U, INT64_MAX)) {
        return false;
    }
    return true;
}

static bool test_16_replay_kdf_wire(void) {
    node_replay_win_init(&g_win, 5U);
    if (!node_replay_win_check_and_mark(&g_win, 5U, UINT64_C(100)) ||
        node_replay_win_check_and_mark(&g_win, 5U, UINT64_C(100)) ||
        !node_replay_win_check_and_mark(&g_win, 5U, UINT64_C(80)) ||
        node_replay_win_check_and_mark(&g_win, 5U, UINT64_C(80)) ||
        node_replay_win_check_and_mark(&g_win, 5U, UINT64_C(36)) ||
        node_replay_win_check_and_mark(&g_win, 4U, UINT64_C(101)) ||
        !node_replay_win_check_and_mark(&g_win, 5U, UINT64_C(200)) ||
        node_replay_win_check_and_mark(&g_win, 5U, UINT64_C(135))) {
        return false;
    }

    uint64_t psk = UINT64_C(0xDEADBEEFCAFEBABE);
    uint64_t k1 =
        node_session_derive_key(psk, 1U, 2U, UINT64_C(11), UINT64_C(22), 5U, 0x03U, 0x02U);
    uint64_t k2 =
        node_session_derive_key(psk, 1U, 2U, UINT64_C(11), UINT64_C(22), 5U, 0x03U, 0x02U);
    uint64_t k_mitm =
        node_session_derive_key(psk, 99U, 2U, UINT64_C(11), UINT64_C(22), 5U, 0x03U, 0x02U);
    uint64_t k_downgrade =
        node_session_derive_key(psk, 1U, 2U, UINT64_C(11), UINT64_C(22), 5U, 0x03U, 0x01U);
    if (k1 != k2 || k1 == k_mitm || k1 == k_downgrade) {
        return false;
    }

    uint8_t msg[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    uint8_t frame[NODE_WIRE_HDR_BYTES + NODE_WIRE_MAX_PAYLOAD];
    uint8_t out[NODE_WIRE_MAX_PAYLOAD];
    size_t flen = node_net_wire_frame_encode(k1, 5U, UINT64_C(201), 0x03U, 0x02U, msg, sizeof(msg),
                                             frame, sizeof(frame));
    if (flen != NODE_WIRE_HDR_BYTES + sizeof(msg)) {
        return false;
    }
    size_t out_len = 0U;
    uint64_t out_seq = UINT64_C(0);
    if (!node_net_wire_frame_decode_verify(k1, &g_win, frame, flen, out, sizeof(out), &out_len,
                                           &out_seq) ||
        out_len != sizeof(msg) || out_seq != UINT64_C(201) || memcmp(msg, out, sizeof(msg)) != 0) {
        return false;
    }
    /* Duplicate replay must be rejected */
    if (node_net_wire_frame_decode_verify(k1, &g_win, frame, flen, out, sizeof(out), &out_len,
                                          &out_seq)) {
        return false;
    }
    /* Tampered payload on seq 202 must fail MAC verification without accepting seq 202 */
    flen = node_net_wire_frame_encode(k1, 5U, UINT64_C(202), 0x03U, 0x02U, msg, sizeof(msg), frame,
                                      sizeof(frame));
    frame[NODE_WIRE_HDR_BYTES] ^= UINT8_C(0x80);
    if (node_net_wire_frame_decode_verify(k1, &g_win, frame, flen, out, sizeof(out), &out_len,
                                          &out_seq)) {
        return false;
    }
    frame[NODE_WIRE_HDR_BYTES] ^= UINT8_C(0x80);
    return node_net_wire_frame_decode_verify(k1, &g_win, frame, flen, out, sizeof(out), &out_len,
                                             &out_seq);
}

static uint64_t brute_tri_count(const node_dyn_tri_t *st) {
    uint64_t cnt = UINT64_C(0);
    for (uint32_t a = 0U; a < st->num_verts; ++a) {
        for (uint32_t b = a + 1U; b < st->num_verts; ++b) {
            if (((st->adj[a] >> b) & UINT64_C(1)) == UINT64_C(0)) {
                continue;
            }
            for (uint32_t c = b + 1U; c < st->num_verts; ++c) {
                if (((st->adj[a] >> c) & UINT64_C(1)) != UINT64_C(0) &&
                    ((st->adj[b] >> c) & UINT64_C(1)) != UINT64_C(0)) {
                    cnt++;
                }
            }
        }
    }
    return cnt;
}

static bool test_17_dbsp_reach_dyntri(void) {
    node_dbsp_reach_init(&g_reach, 10U);
    const uint32_t edges[][2] = {
        {0, 1}, {1, 2}, {2, 3}, {3, 1}, {3, 4}, {4, 5}, {5, 6}, {6, 7}, {0, 8}, {8, 9},
    };
    for (size_t i = 0U; i < sizeof(edges) / sizeof(edges[0]); ++i) {
        if (!node_dbsp_reach_insert_edge(&g_reach, edges[i][0], edges[i][1])) {
            return false;
        }
    }
    uint32_t iters = 0U;
    uint64_t r0 = node_dbsp_reach_from(&g_reach, 0U, &iters);
    uint64_t r4 = node_dbsp_reach_from(&g_reach, 4U, &iters);
    if (r0 != UINT64_C(0x3FF) || r4 != UINT64_C(0xF0)) {
        return false;
    }

    node_dyn_tri_init(&g_tri, 12U);
    const uint32_t ops[][3] = {
        {0, 1, 1}, {1, 2, 1}, {0, 2, 1}, {2, 3, 1}, {0, 3, 1}, {1, 3, 1}, {3, 4, 1}, {2, 4, 1},
        {0, 4, 1}, {0, 2, 0}, {1, 3, 0}, {3, 4, 0}, {4, 5, 1}, {3, 5, 1}, {2, 5, 1}, {3, 4, 1},
    };
    for (size_t i = 0U; i < sizeof(ops) / sizeof(ops[0]); ++i) {
        int32_t pm = (ops[i][2] == 1U) ? 1 : -1;
        uint64_t got = node_dyn_tri_apply_edge(&g_tri, ops[i][0], ops[i][1], pm);
        if (got != brute_tri_count(&g_tri)) {
            return false;
        }
    }
    return g_tri.triangles == brute_tri_count(&g_tri);
}

static bool test_18_udp_disk_info(void) {
    node_udp_bench_report_t udp_rep;
    if (!node_host_udp_loopback_run(64U, &udp_rep)) {
        return false;
    }
    node_disk_wal_report_t disk_rep;
    if (!node_host_disk_wal_run("/tmp/node_selftest_wal", 64U, &disk_rep)) {
        return false;
    }
    return udp_rep.passed && disk_rep.passed;
}

static int run_selftest(void) {
    struct {
        const char *name;
        bool (*fn)(void);
    } suites[18] = {
        {"01_vm_caps", test_01_vm_caps},
        {"02_vm_attenuate", test_02_vm_attenuate},
        {"03_vm_fuel_replay", test_03_vm_fuel_replay},
        {"04_zset_abelian", test_04_zset_abelian},
        {"05_dbsp_bilinear", test_05_dbsp_bilinear},
        {"06_wcoj_leapfrog", test_06_wcoj_leapfrog},
        {"07_merkle_wal_chain", test_07_merkle_wal_chain},
        {"08_wal_crash_recover", test_08_wal_crash_recover},
        {"09_crdt_semilattice", test_09_crdt_semilattice},
        {"10_raft_quorum_safety", test_10_raft_quorum_safety},
        {"11_bft_equivocation", test_11_bft_equivocation},
        {"12_dst_prng_faults", test_12_dst_prng_faults},
        {"13_pncounter_merge_dups", test_13_pncounter_merge_dups},
        {"14_arena_schema_fill", test_14_arena_schema_fill},
        {"15_certs_sanity", test_15_certs_fir_eval},
        {"16_replay_kdf_wire", test_16_replay_kdf_wire},
        {"17_dbsp_reach_dyntri", test_17_dbsp_reach_dyntri},
        {"18_udp_disk_info", test_18_udp_disk_info},
    };
    int fails = 0;
    for (int i = 0; i < 18; ++i) {
        bool ok = suites[i].fn();
        printf("[NODE SELFTEST] %-24s : %s\n", suites[i].name, ok ? "PASS" : "FAIL");
        if (!ok) {
            fails++;
        }
    }
    return (fails == 0) ? 0 : 1;
}

static int cmd_vm_demo(void) {
    build_demo_vm_prog(&g_prog);
    node_vm_init(&g_vm, 64U);
    (void)node_vm_grant_cap(&g_vm, 0U, 0U, 0U, 32U, NODE_CAP_R | NODE_CAP_W | NODE_CAP_G);
    node_vm_run(&g_vm, &g_prog, 4U);
    (void)node_vm_snap_push(&g_vm);
    uint64_t snap_hash = node_vm_state_hash(&g_vm);
    node_vm_run(&g_vm, &g_prog, 32U);
    uint64_t run1_hash = node_vm_state_hash(&g_vm);

    /* Now rewind & replay */
    (void)node_vm_snap_restore(&g_vm, 0U);
    node_vm_run(&g_vm, &g_prog, 32U);
    uint64_t replay_hash = node_vm_state_hash(&g_vm);

    /* Negative escalation check on g_vm2 */
    node_vm_init(&g_vm2, 32U);
    (void)node_vm_grant_cap(&g_vm2, 0U, 0U, 0U, 16U, NODE_CAP_R | NODE_CAP_G);
    bool esc_blocked = !node_vm_attenuate_cap(&g_vm2, 1U, 0U, 0U, 16U, NODE_CAP_R | NODE_CAP_W);

    printf("{\n");
    printf("  \"steps\": %u,\n", g_vm.state.steps);
    printf("  \"fuel_remaining\": %u,\n", g_vm.state.fuel);
    printf("  \"snap_hash\": \"0x%016" PRIx64 "\",\n", snap_hash);
    printf("  \"run_hash\": \"0x%016" PRIx64 "\",\n", run1_hash);
    printf("  \"replay_hash\": \"0x%016" PRIx64 "\",\n", replay_hash);
    printf("  \"replay_exact\": %s,\n", (run1_hash == replay_hash) ? "true" : "false");
    printf("  \"escalation_blocked\": %s,\n", esc_blocked ? "true" : "false");
    printf("  \"emit0\": %" PRIu64 ",\n", g_vm.state.emit_log[0]);
    printf("  \"emit1\": %" PRIu64 "\n", g_vm.state.emit_log[1]);
    printf("}\n");
    return (run1_hash == replay_hash && esc_blocked) ? 0 : 1;
}

static int cmd_dbsp_demo(void) {
    node_dbsp_join_init(&g_dbsp);
    node_zset_init(&g_full_a);
    node_zset_init(&g_full_b);

    uint64_t full_total_ops = 0U;
    bool all_exact = true;
    for (uint32_t ep = 0U; ep < 20U; ++ep) {
        node_zset_init(&g_da);
        node_zset_init(&g_db);
        if (ep == 0U) {
            for (uint64_t k = 1U; k <= 128U; ++k) {
                (void)node_zset_add_entry(&g_da, k, (int64_t)((k & 3U) + 1U));
                (void)node_zset_add_entry(&g_db, k, (int64_t)(((k >> 1U) & 3U) + 1U));
            }
        } else {
            uint64_t k = (uint64_t)ep * 3U + 1U;
            (void)node_zset_add_entry(&g_da, k, (ep & 1U) ? 2 : -1);
            (void)node_zset_add_entry(&g_db, k, 1);
            if ((ep & 3U) == 0U) {
                (void)node_zset_add_entry(&g_db, k + 1U, 3);
            }
        }
        (void)node_dbsp_join_step(&g_dbsp, &g_da, &g_db, &g_delta_out);
        (void)node_zset_add(&g_full_a, &g_da, &g_tmp_z1);
        g_full_a = g_tmp_z1;
        (void)node_zset_add(&g_full_b, &g_db, &g_tmp_z1);
        g_full_b = g_tmp_z1;
        uint64_t fops = 0U;
        (void)node_zset_join(&g_full_a, &g_full_b, &g_full_join, &fops);
        full_total_ops += fops;
        if (!node_zset_equal(&g_dbsp.out_state, &g_full_join)) {
            all_exact = false;
        }
    }

    /* Skew + hub triangle benchmark graph */
    node_graph_init(&g_graph, 120U);
    for (uint32_t u = 0U; u < 6U; ++u) {
        for (uint32_t v = u + 1U; v < 6U; ++v) {
            (void)node_graph_add_edge(&g_graph, u, v);
        }
    }
    for (uint32_t h = 10U; h < 14U; ++h) {
        (void)node_graph_add_edge(&g_graph, 8U, h);
        (void)node_graph_add_edge(&g_graph, 9U, h);
        for (uint32_t t = 20U; t < 115U; ++t) {
            (void)node_graph_add_edge(&g_graph, h, t);
        }
    }
    (void)node_graph_add_edge(&g_graph, 8U, 25U);
    (void)node_graph_add_edge(&g_graph, 8U, 35U);
    (void)node_graph_add_edge(&g_graph, 9U, 45U);
    (void)node_graph_finalize(&g_graph);

    uint64_t wcoj_probes = 0U;
    uint64_t bin_wedges = 0U;
    uint64_t bin_probes = 0U;
    uint64_t wt = node_wcoj_count_triangles(&g_graph, &wcoj_probes);
    uint64_t bt = node_binjoin_count_triangles(&g_graph, &bin_wedges, &bin_probes);

    printf("{\n");
    printf("  \"epochs\": %" PRIu64 ",\n", g_dbsp.epoch);
    printf("  \"dbsp_exact_match\": %s,\n", all_exact ? "true" : "false");
    printf("  \"dbsp_inc_ops\": %" PRIu64 ",\n", g_dbsp.inc_ops);
    printf("  \"full_join_ops\": %" PRIu64 ",\n", full_total_ops);
    printf("  \"wcoj_triangles\": %" PRIu64 ",\n", wt);
    printf("  \"binjoin_triangles\": %" PRIu64 ",\n", bt);
    printf("  \"wcoj_probes\": %" PRIu64 ",\n", wcoj_probes);
    printf("  \"binjoin_wedges\": %" PRIu64 ",\n", bin_wedges);
    printf("  \"binjoin_probes\": %" PRIu64 ",\n", bin_probes);
    printf("  \"dbsp_root\": \"0x%016" PRIx64 "\"\n", node_zset_hash(&g_dbsp.out_state));
    printf("}\n");
    return (all_exact && wt == bt) ? 0 : 1;
}

static int cmd_wal_audit(void) {
    node_wal_init(&g_wal);
    uint64_t golden[NODE_PAGE_COUNT];
    memset(golden, 0, sizeof(golden));
    uint32_t commit_lsn[8];
    uint32_t n_txs = 8U;
    for (uint32_t tx = 1U; tx <= n_txs; ++tx) {
        uint32_t k1 = (tx * 3U) & 63U;
        uint32_t k2 = (tx * 7U + 1U) & 63U;
        uint64_t v1 = UINT64_C(0x10000000) + (uint64_t)tx * UINT64_C(17);
        uint64_t v2 = UINT64_C(0x20000000) + (uint64_t)tx * UINT64_C(31);
        (void)node_wal_append_data(&g_wal, tx, k1, v1);
        (void)node_wal_append_data(&g_wal, tx, k2, v2);
        (void)node_wal_append_commit(&g_wal, tx);
        commit_lsn[tx - 1U] = g_wal.len;
    }

    uint32_t cuts_tested = 0U;
    uint32_t atomic_ok = 0U;
    uint32_t torn_rejected = 0U;
    for (uint32_t cut = 0U; cut <= g_wal.len; ++cut) {
        cuts_tested++;
        uint64_t rec_pages[NODE_PAGE_COUNT];
        uint32_t rtxs = 0U;
        uint64_t mr = 0U;
        (void)node_wal_recover(&g_wal, cut, UINT32_MAX, UINT64_C(0), rec_pages, &rtxs, &mr);
        /* Count how many complete transactions had commit_lsn <= cut */
        uint32_t expect_txs = 0U;
        memset(golden, 0, sizeof(golden));
        for (uint32_t tx = 1U; tx <= n_txs; ++tx) {
            if (commit_lsn[tx - 1U] <= cut) {
                expect_txs = tx;
                uint32_t k1 = (tx * 3U) & 63U;
                uint32_t k2 = (tx * 7U + 1U) & 63U;
                golden[k1] = UINT64_C(0x10000000) + (uint64_t)tx * UINT64_C(17);
                golden[k2] = UINT64_C(0x20000000) + (uint64_t)tx * UINT64_C(31);
            }
        }
        if (rtxs == expect_txs && memcmp(rec_pages, golden, sizeof(golden)) == 0) {
            atomic_ok++;
        }
        if (cut > 0U) {
            uint64_t torn_pages[NODE_PAGE_COUNT];
            uint32_t t_txs = 0U;
            uint64_t t_mr = 0U;
            uint32_t vlen =
                node_wal_recover(&g_wal, cut, cut - 1U, UINT64_C(0x01), torn_pages, &t_txs, &t_mr);
            if (vlen <= cut - 1U && t_txs <= expect_txs) {
                torn_rejected++;
            }
        }
    }

    uint8_t root[32];
    node_merkle_root64(golden, root);
    node_merkle_proof_t prf;
    (void)node_merkle_proof64(golden, 9U, &prf);
    bool proof_clean = node_merkle_verify_proof64(&prf, root);
    prf.leaf_val ^= UINT64_C(1);
    bool bitrot_caught = !node_merkle_verify_proof64(&prf, root);

    printf("{\n");
    printf("  \"wal_len\": %u,\n", g_wal.len);
    printf("  \"cuts_tested\": %u,\n", cuts_tested);
    printf("  \"atomic_ok\": %u,\n", atomic_ok);
    printf("  \"torn_rejected\": %u,\n", torn_rejected);
    printf("  \"merkle_proof_ok\": %s,\n", proof_clean ? "true" : "false");
    printf("  \"bitrot_caught\": %s\n", bitrot_caught ? "true" : "false");
    printf("}\n");
    return (atomic_ok == cuts_tested && torn_rejected == g_wal.len && proof_clean && bitrot_caught)
               ? 0
               : 1;
}

static int cmd_dst(int argc, char **argv) {
    node_dst_cfg_t cfg;
    cfg.seed = UINT64_C(0x4E4F444544535431);
    cfg.universes = 32U;
    cfg.ticks_per_universe = 64U;
    cfg.broken_quorum = 0U;
    cfg.fault_prob_128 = 36U;

    for (int i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "--universes") == 0 && i + 1 < argc) {
            cfg.universes = (uint32_t)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--ticks") == 0 && i + 1 < argc) {
            cfg.ticks_per_universe = (uint32_t)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
            cfg.seed = (uint64_t)strtoull(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "--fault-prob") == 0 && i + 1 < argc) {
            cfg.fault_prob_128 = (uint32_t)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--buggy") == 0) {
            cfg.broken_quorum = 1U;
        }
    }

    node_dst_report_t rep;
    node_dst_run(&cfg, &rep, &g_raft, &g_bft, &g_wal);
    printf("{\n");
    printf("  \"seed\": \"0x%016" PRIx64 "\",\n", rep.seed);
    printf("  \"universes\": %" PRIu64 ",\n", rep.universes);
    printf("  \"ticks_total\": %" PRIu64 ",\n", rep.ticks_total);
    printf("  \"faults_injected\": %" PRIu64 ",\n", rep.faults_injected);
    printf("  \"partitions\": %" PRIu64 ",\n", rep.partitions);
    printf("  \"crashes\": %" PRIu64 ",\n", rep.crashes);
    printf("  \"commits\": %" PRIu64 ",\n", rep.commits);
    printf("  \"crdt_converged\": %" PRIu64 ",\n", rep.crdt_converged);
    printf("  \"wal_recoveries_ok\": %" PRIu64 ",\n", rep.wal_recoveries_ok);
    printf("  \"violations_found\": %" PRIu64 ",\n", rep.violations_found);
    printf("  \"min_witness_tick\": %" PRIu64 ",\n", rep.min_witness_tick);
    printf("  \"witness_universe\": %" PRIu64 ",\n", rep.witness_universe);
    printf("  \"broken_quorum\": %u,\n", cfg.broken_quorum);
    printf("  \"state_root\": \"0x%016" PRIx64 "\"\n", rep.state_root);
    printf("}\n");
    return 0;
}

static int cmd_emit_certs(const char *dir) {
    char fir_p[512];
    char lean_p[512];
    char json_p[512];

    (void)snprintf(fir_p, sizeof(fir_p), "%s/cap_isolation.fir", dir);
    (void)snprintf(lean_p, sizeof(lean_p), "%s/cap_isolation.lean", dir);
    (void)snprintf(json_p, sizeof(json_p), "%s/cap_isolation.json", dir);
    if (!node_cert_emit_cap_fir(&g_cert_ws, fir_p) || !node_cert_emit_cap_lean(lean_p) ||
        !node_cert_emit_json(json_p, "cap_isolation", fir_p, lean_p, 16U, "UNSAT")) {
        return 1;
    }

    (void)snprintf(fir_p, sizeof(fir_p), "%s/bft_quorum_safety.fir", dir);
    (void)snprintf(lean_p, sizeof(lean_p), "%s/bft_quorum_safety.lean", dir);
    (void)snprintf(json_p, sizeof(json_p), "%s/bft_quorum_safety.json", dir);
    if (!node_cert_emit_bft_fir(&g_cert_ws, fir_p, false) || !node_cert_emit_bft_lean(lean_p) ||
        !node_cert_emit_json(json_p, "bft_quorum_safety", fir_p, lean_p, 12U, "UNSAT")) {
        return 1;
    }

    (void)snprintf(fir_p, sizeof(fir_p), "%s/bft_quorum_buggy.fir", dir);
    if (!node_cert_emit_bft_fir(&g_cert_ws, fir_p, true)) {
        return 1;
    }

    (void)snprintf(fir_p, sizeof(fir_p), "%s/dbsp_join_delta.fir", dir);
    (void)snprintf(lean_p, sizeof(lean_p), "%s/dbsp_join_delta.lean", dir);
    (void)snprintf(json_p, sizeof(json_p), "%s/dbsp_join_delta.json", dir);
    if (!node_cert_emit_dbsp_fir(&g_cert_ws, fir_p) || !node_cert_emit_dbsp_lean(lean_p) ||
        !node_cert_emit_json(json_p, "dbsp_join_delta", fir_p, lean_p, 16U, "UNSAT")) {
        return 1;
    }

    printf("[NODE CERTS] Emitted 4 .fir + 3 .lean + 3 .json certificates into %s/\n", dir);
    return 0;
}

static int cmd_audit_replay(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s audit-replay <cap-attenuate|zset-overflow|net-mac> ...\n",
                argv[0]);
        return 1;
    }
    if (strcmp(argv[2], "cap-attenuate") == 0) {
        if (argc < 7) {
            return 1;
        }
        uint32_t sbase = (uint32_t)strtoul(argv[3], NULL, 0);
        uint32_t slen = (uint32_t)strtoul(argv[4], NULL, 0);
        uint32_t nbase = (uint32_t)strtoul(argv[5], NULL, 0);
        uint32_t nlen = (uint32_t)strtoul(argv[6], NULL, 0);
        node_vm_init(&g_vm, 16U);
        g_vm.state.caps[0].region_id = 0U;
        g_vm.state.caps[0].base = sbase;
        g_vm.state.caps[0].len = slen;
        g_vm.state.caps[0].rights = NODE_CAP_R | NODE_CAP_W | NODE_CAP_G;
        bool ok = node_vm_attenuate_cap(&g_vm, 1U, 0U, nbase, nlen, NODE_CAP_R);
        printf("{\"accepted\": %s}\n", ok ? "true" : "false");
        return 0;
    }
    if (strcmp(argv[2], "zset-overflow") == 0) {
        if (argc < 5) {
            return 1;
        }
        int64_t w1 = (int64_t)strtoll(argv[3], NULL, 0);
        int64_t w2 = (int64_t)strtoll(argv[4], NULL, 0);
        node_zset_init(&g_tmp_z1);
        bool ok1 = node_zset_add_entry(&g_tmp_z1, 1U, w1);
        bool ok2 = ok1 && node_zset_add_entry(&g_tmp_z1, 1U, w2);
        printf("{\"accepted\": %s}\n", (ok1 && ok2) ? "true" : "false");
        return 0;
    }
    if (strcmp(argv[2], "net-mac") == 0) {
        uint8_t key[32];
        uint8_t tag[32];
        for (size_t i = 0U; i < 32U; ++i) {
            key[i] = (uint8_t)(UINT32_C(0xA5) ^ (uint32_t)(i * 13U));
        }
        node_net_msg_t base;
        memset(&base, 0, sizeof(base));
        base.valid = 1U;
        base.kind = 3U;
        base.src = 1U;
        base.dst = 4U;
        base.term = 11U;
        base.index = 7U;
        base.prev_term = 10U;
        base.success = 1U;
        base.val = 0x12345678U;
        base.entry_term = 11U;
        base.leader_commit = 6U;
        node_net_msg_mac(key, &base, tag);
        bool genuine_ok = node_net_msg_verify(key, &base, tag);

        uint32_t tamper_tests = 10U;
        uint32_t tamper_rejected = 0U;
        uint32_t *fields[9] = {&base.kind, &base.src,        &base.dst,
                               &base.term, &base.index,      &base.prev_term,
                               &base.val,  &base.entry_term, &base.leader_commit};
        for (uint32_t k = 0U; k < 9U; ++k) {
            *fields[k] ^= UINT32_C(1);
            if (!node_net_msg_verify(key, &base, tag)) {
                tamper_rejected++;
            }
            *fields[k] ^= UINT32_C(1);
        }
        tag[0] ^= UINT8_C(1);
        if (!node_net_msg_verify(key, &base, tag)) {
            tamper_rejected++;
        }
        printf("{\"genuine_ok\": %s, \"tamper_tests\": %u, \"tamper_rejected\": %u}\n",
               genuine_ok ? "true" : "false", tamper_tests, tamper_rejected);
        return (genuine_ok && tamper_rejected == tamper_tests) ? 0 : 1;
    }
    return 1;
}

static int cmd_udp_loopback(uint32_t count) {
    node_udp_bench_report_t rep;
    bool ok = node_host_udp_loopback_run(count, &rep);
    printf("{\n");
    printf("  \"port\": %u,\n", (unsigned)rep.port);
    printf("  \"sent_ok\": %u,\n", rep.sent_ok);
    printf("  \"recv_ok\": %u,\n", rep.recv_ok);
    printf("  \"replay_rejected\": %u,\n", rep.replay_rejected);
    printf("  \"tamper_rejected\": %u,\n", rep.tamper_rejected);
    printf("  \"post_attack_ok\": %u,\n", rep.post_attack_ok);
    printf("  \"elapsed_us\": %" PRIu64 ",\n", rep.elapsed_us);
    printf("  \"passed\": %s\n", ok ? "true" : "false");
    printf("}\n");
    return ok ? 0 : 1;
}

static int cmd_disk_compact(const char *dir_path) {
    node_disk_wal_report_t rep;
    bool ok = node_host_disk_wal_run(dir_path, 96U, &rep);
    printf("{\n");
    printf("  \"dir\": \"%s\",\n", dir_path);
    printf("  \"records_written\": %u,\n", rep.records_written);
    printf("  \"segments_written\": %u,\n", rep.segments_written);
    printf("  \"recovered_records\": %u,\n", rep.recovered_records);
    printf("  \"torn_rejected\": %u,\n", rep.torn_rejected);
    printf("  \"raw_snap_bytes\": %u,\n", rep.raw_snap_bytes);
    printf("  \"compressed_snap_bytes\": %u,\n", rep.compressed_snap_bytes);
    printf("  \"codec\": \"%s\",\n", rep.have_info_codec ? "INFO_INF1" : "RLE_FALLBACK");
    printf("  \"roundtrip_exact\": %s,\n", rep.roundtrip_exact ? "true" : "false");
    printf("  \"elapsed_us\": %" PRIu64 ",\n", rep.elapsed_us);
    printf("  \"passed\": %s\n", ok ? "true" : "false");
    printf("}\n");
    return ok ? 0 : 1;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(
            stderr,
            "Usage: %s "
            "<selftest|vm-demo|dbsp-demo|wal-audit|dst|udp-loopback|disk-compact|audit-replay|emit-certs DIR>\n",
            argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "selftest") == 0) {
        return run_selftest();
    }
    if (strcmp(argv[1], "vm-demo") == 0) {
        return cmd_vm_demo();
    }
    if (strcmp(argv[1], "dbsp-demo") == 0) {
        return cmd_dbsp_demo();
    }
    if (strcmp(argv[1], "wal-audit") == 0) {
        return cmd_wal_audit();
    }
    if (strcmp(argv[1], "dst") == 0) {
        return cmd_dst(argc, argv);
    }
    if (strcmp(argv[1], "udp-loopback") == 0) {
        uint32_t n = (argc >= 3) ? (uint32_t)strtoul(argv[2], NULL, 0) : 256U;
        return cmd_udp_loopback(n);
    }
    if (strcmp(argv[1], "disk-compact") == 0) {
        const char *dir = (argc >= 3) ? argv[2] : "/tmp/node_disk_wal";
        return cmd_disk_compact(dir);
    }
    if (strcmp(argv[1], "audit-replay") == 0) {
        return cmd_audit_replay(argc, argv);
    }
    if (strcmp(argv[1], "emit-certs") == 0) {
        const char *dir = (argc >= 3) ? argv[2] : "build/certs";
        return cmd_emit_certs(dir);
    }
    fprintf(stderr, "Unknown subcommand: %s\n", argv[1]);
    return 1;
}
