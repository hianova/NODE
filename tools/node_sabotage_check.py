#!/usr/bin/env python3
"""
tools/node_sabotage_check.py — 36-Mutant Single-Fault Sabotage Gate (Gate 6)
==============================================================================
Verifies 100.0% mutation-kill efficacy (36/36 killed, 0 compile errors) across
12 categories (3 mutants each) in `src/node_ring0.c`:
   1. vm_caps             (3)
   2. vm_attenuate        (3)
   3. vm_fuel_replay      (3)
   4. zset_abelian        (3)
   5. dbsp_bilinear       (3)
   6. wcoj_leapfrog       (3)
   7. merkle_wal_chain    (3)
   8. wal_crash_recover   (3)
   9. crdt_semilattice    (3)
  10. raft_quorum_safety  (3)
  11. bft_equivocation    (3)
  12. dst_prng_faults     (3)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

FLOW_TOOLS_DIR = (
    Path(os.environ.get("FLOW_DIR", str(Path(__file__).resolve().parents[2] / "FLOW"))).resolve()
    / "sdk"
    / "tools"
)
if str(FLOW_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(FLOW_TOOLS_DIR))

from flow_sabotage_runner import FlowMutant, run_sabotage_suite

NodeMutant = FlowMutant


def build_node_mutants() -> list[NodeMutant]:
    return [
        # --- 1. vm_caps (3) ---
        NodeMutant(
            "M01_cap_allow_missing_right",
            "vm_caps",
            "    if (c == NULL || (c->rights & req_right) != req_right) {\n        return false;\n    }",
            "    if (c == NULL) {\n        return false;\n    }\n    (void)req_right;",
        ),
        NodeMutant(
            "M02_cap_drop_lower_bound",
            "vm_caps",
            "    if (c->base > NODE_VM_MEM_WORDS || c->len > NODE_VM_MEM_WORDS - c->base || addr < c->base ||\n"
            "        (addr - c->base) >= c->len || addr >= NODE_VM_MEM_WORDS) {",
            "    if (addr >= c->base + c->len || addr >= NODE_VM_MEM_WORDS) {",
        ),
        NodeMutant(
            "M03_cap_drop_upper_bound",
            "vm_caps",
            "    if (c->base > NODE_VM_MEM_WORDS || c->len > NODE_VM_MEM_WORDS - c->base || addr < c->base ||\n"
            "        (addr - c->base) >= c->len || addr >= NODE_VM_MEM_WORDS) {\n"
            "        return false;\n"
            "    }\n"
            "    return true;",
            "    if (addr < c->base || addr >= NODE_VM_MEM_WORDS) {\n"
            "        return false;\n"
            "    }\n"
            "    return true;",
        ),
        # --- 2. vm_attenuate (3) ---
        NodeMutant(
            "M04_att_skip_grant_check",
            "vm_attenuate",
            "    if ((src.rights & NODE_CAP_G) == 0U) {\n        return false;\n    }",
            "    if (false && (src.rights & NODE_CAP_G) == 0U) {\n        return false;\n    }",
        ),
        NodeMutant(
            "M05_att_skip_rights_subset",
            "vm_attenuate",
            "    if ((new_rights & src.rights) != new_rights) {\n        return false;\n    }",
            "    if (false && (new_rights & src.rights) != new_rights) {\n        return false;\n    }",
        ),
        NodeMutant(
            "M06_att_skip_bounds_check",
            "vm_attenuate",
            "    if (new_base < src.base) {\n"
            "        return false;\n"
            "    }\n"
            "    if ((uint64_t)new_base > src_end) {\n"
            "        return false;\n"
            "    }\n"
            "    if ((uint64_t)new_base + (uint64_t)new_len > src_end) {\n"
            "        return false;\n"
            "    }",
            "    if (false && new_base < src.base && (uint64_t)new_len > src_end) {\n"
            "        return false;\n"
            "    }",
        ),
        # --- 3. vm_fuel_replay (3) ---
        NodeMutant(
            "M07_vm_drop_fuel_dec",
            "vm_fuel_replay",
            "    vm->state.fuel--;\n    vm->state.steps++;",
            "    vm->state.steps++;",
        ),
        NodeMutant(
            "M08_vm_corrupt_fuel_fault_code",
            "vm_fuel_replay",
            "    if (vm->state.fuel == 0U) {\n"
            "        vm->state.halted = 1U;\n"
            "        vm->state.fault = NODE_FAULT_FUEL;\n"
            "        return;\n"
            "    }",
            "    if (vm->state.fuel == 0U) {\n"
            "        vm->state.halted = 1U;\n"
            "        vm->state.fault = NODE_FAULT_NONE;\n"
            "        return;\n"
            "    }",
        ),
        NodeMutant(
            "M09_vm_corrupt_snap_restore",
            "vm_fuel_replay",
            "    uint32_t pos = (vm->snap_head - 1U - rev_idx) & (NODE_VM_SNAP_CAP - 1U);\n"
            "    node_copy_bytes(&vm->state, &vm->snaps[pos], sizeof(vm->state));\n"
            "    return true;",
            "    uint32_t pos = (vm->snap_head - 1U - rev_idx) & (NODE_VM_SNAP_CAP - 1U);\n"
            "    vm->state.pc = vm->snaps[pos].pc;\n"
            "    return true;",
        ),
        # --- 4. zset_abelian (3) ---
        NodeMutant(
            "M10_zset_keep_zero_weight",
            "zset_abelian",
            "        int64_t nw = (int64_t)nw128;\n        if (nw == INT64_C(0)) {",
            "        int64_t nw = (int64_t)nw128;\n        if (false && nw == INT64_C(0)) {",
        ),
        NodeMutant(
            "M11_zset_combine_keep_zero",
            "zset_abelian",
            "            int64_t w = (int64_t)w128;\n            if (w != INT64_C(0)) {",
            "            int64_t w = (int64_t)w128;\n            if (true || w != INT64_C(0)) {",
        ),
        NodeMutant(
            "M12_zset_sub_wrong_sign",
            "zset_abelian",
            "bool node_zset_sub(const node_zset_t *a, const node_zset_t *b, node_zset_t *out) {\n"
            "    return zset_linear_combine(a, b, INT64_C(-1), out);\n"
            "}",
            "bool node_zset_sub(const node_zset_t *a, const node_zset_t *b, node_zset_t *out) {\n"
            "    return zset_linear_combine(a, b, INT64_C(1), out);\n"
            "}",
        ),
        # --- 5. dbsp_bilinear (3) ---
        NodeMutant(
            "M13_dbsp_drop_da_b",
            "dbsp_bilinear",
            "    if (!node_zset_join(da, &st->b_state, &st->ws_da_b, &o1)) {\n"
            "        return false;\n"
            "    }",
            "    node_zset_init(&st->ws_da_b);\n"
            "    o1 = 0U;",
        ),
        NodeMutant(
            "M14_dbsp_drop_a_db",
            "dbsp_bilinear",
            "    if (!node_zset_join(&st->a_state, db, &st->ws_a_db, &o2)) {\n"
            "        return false;\n"
            "    }",
            "    node_zset_init(&st->ws_a_db);\n"
            "    o2 = 0U;",
        ),
        NodeMutant(
            "M15_dbsp_drop_da_db",
            "dbsp_bilinear",
            "    if (!node_zset_join(da, db, &st->ws_da_db, &o3)) {\n"
            "        return false;\n"
            "    }",
            "    node_zset_init(&st->ws_da_db);\n"
            "    o3 = 0U;",
        ),
        # --- 6. wcoj_leapfrog (3) ---
        NodeMutant(
            "M16_wcoj_invert_balanced_step",
            "wcoj_leapfrog",
            "                    if (g->adj[p] < g->adj[q]) {\n"
            "                        p++;\n"
            "                    } else if (g->adj[q] < g->adj[p]) {\n"
            "                        q++;\n"
            "                    } else {",
            "                    if (g->adj[p] < g->adj[q]) {\n"
            "                        q++;\n"
            "                    } else if (g->adj[q] < g->adj[p]) {\n"
            "                        p++;\n"
            "                    } else {",
        ),
        NodeMutant(
            "M17_wcoj_double_skew_u_lt_v",
            "wcoj_leapfrog",
            "            if ((deg_u << 2U) < deg_v) {\n"
            "                for (uint32_t k = u_beg; k < u_end; ++k) {\n"
            "                    if (csr_contains(g, v, g->adj[k], &probes)) {\n"
            "                        tris++;\n"
            "                    }\n"
            "                }",
            "            if ((deg_u << 2U) < deg_v) {\n"
            "                for (uint32_t k = u_beg; k < u_end; ++k) {\n"
            "                    if (csr_contains(g, v, g->adj[k], &probes)) {\n"
            "                        tris += UINT64_C(2);\n"
            "                    }\n"
            "                }",
        ),
        NodeMutant(
            "M18_wcoj_double_skew_v_lt_u",
            "wcoj_leapfrog",
            "            } else if ((deg_v << 2U) < deg_u) {\n"
            "                for (uint32_t k = v_beg; k < v_end; ++k) {\n"
            "                    if (csr_contains(g, u, g->adj[k], &probes)) {\n"
            "                        tris++;\n"
            "                    }\n"
            "                }",
            "            } else if ((deg_v << 2U) < deg_u) {\n"
            "                for (uint32_t k = v_beg; k < v_end; ++k) {\n"
            "                    if (csr_contains(g, u, g->adj[k], &probes)) {\n"
            "                        tris += UINT64_C(2);\n"
            "                    }\n"
            "                }",
        ),
        # --- 7. merkle_wal_chain (3) ---
        NodeMutant(
            "M19_wal_skip_prev_hash",
            "merkle_wal_chain",
            "        if (rec.prev_hash != expected_prev || rec.rec_hash != expect_hash) {",
            "        (void)expected_prev;\n        if (rec.rec_hash != expect_hash) {",
        ),
        NodeMutant(
            "M20_wal_skip_rec_hash",
            "merkle_wal_chain",
            "        uint64_t expect_hash = wal_hash_rec(&rec);\n"
            "        if (rec.prev_hash != expected_prev || rec.rec_hash != expect_hash) {",
            "        uint64_t expect_hash = wal_hash_rec(&rec);\n"
            "        (void)expect_hash;\n"
            "        if (rec.prev_hash != expected_prev) {",
        ),
        NodeMutant(
            "M21_merkle_drop_sibling_hash",
            "merkle_wal_chain",
            "        node_ct_cswap32(left, right, idx & 1U);\n"
            "        node_hash_u64_pair(left, right, next_hash);",
            "        node_ct_cswap32(left, right, idx & 1U);\n"
            "        (void)right;\n"
            "        node_hash_u64_pair(left, left, next_hash);",
        ),
        # --- 8. wal_crash_recover (3) ---
        NodeMutant(
            "M22_wal_apply_uncommitted_data",
            "wal_crash_recover",
            "            if (rec.key < NODE_PAGE_COUNT) {\n"
            "                stage_val[rec.key] = rec.val;\n"
            "                stage_dirty[rec.key] = UINT8_C(1);\n"
            "            }",
            "            if (rec.key < NODE_PAGE_COUNT) {\n"
            "                stage_val[rec.key] = rec.val;\n"
            "                stage_dirty[rec.key] = UINT8_C(1);\n"
            "                pages_out[rec.key] = rec.val;\n"
            "            }",
        ),
        NodeMutant(
            "M23_wal_leak_aborted_stage",
            "wal_crash_recover",
            "            if (stage_tx != rec.tx_id) {\n"
            "                node_zero_bytes(stage_dirty, sizeof(stage_dirty));\n"
            "                stage_tx = rec.tx_id;\n"
            "            }",
            "            if (stage_tx != rec.tx_id) {\n"
            "                stage_tx = rec.tx_id;\n"
            "            }",
        ),
        NodeMutant(
            "M24_wal_skip_commit_flush",
            "wal_crash_recover",
            "        } else if (rec.flags == NODE_WAL_FLAG_COMMIT) {\n"
            "            if (stage_tx == rec.tx_id) {",
            "        } else if (rec.flags == NODE_WAL_FLAG_COMMIT) {\n"
            "            if (false && stage_tx == rec.tx_id) {",
        ),
        # --- 9. crdt_semilattice (3) ---
        NodeMutant(
            "M25_gcounter_sum_instead_of_max",
            "crdt_semilattice",
            "        if (src->slots[i] > dst->slots[i]) {\n"
            "            dst->slots[i] = src->slots[i];\n"
            "        }",
            "        dst->slots[i] += src->slots[i];",
        ),
        NodeMutant(
            "M26_pncounter_add_neg_branch",
            "crdt_semilattice",
            "    return (int64_t)node_gcounter_value(&c->pos) - (int64_t)node_gcounter_value(&c->neg);",
            "    return (int64_t)node_gcounter_value(&c->pos) + (int64_t)node_gcounter_value(&c->neg);",
        ),
        NodeMutant(
            "M27_lww_drop_tiebreak_node",
            "crdt_semilattice",
            "    bool take = (src->ts > dst->ts) || (src->ts == dst->ts && src->node_id > dst->node_id) ||\n"
            "                (src->ts == dst->ts && src->node_id == dst->node_id && src->val > dst->val);",
            "    bool take = (src->ts > dst->ts) || (false && src->ts == dst->ts && src->node_id > dst->node_id) ||\n"
            "                (src->ts == dst->ts && src->node_id == dst->node_id && src->val > dst->val);",
        ),
        # --- 10. raft_quorum_safety (3) ---
        NodeMutant(
            "M28_raft_allow_double_vote",
            "raft_quorum_safety",
            "            bool can_vote = (m.term == r->current_term[m.dst]) &&\n"
            "                            (r->voted_for[m.dst] == UINT32_MAX || r->voted_for[m.dst] == m.src);",
            "            bool can_vote = (m.term == r->current_term[m.dst]);",
        ),
        NodeMutant(
            "M29_raft_force_broken_quorum",
            "raft_quorum_safety",
            "static uint32_t raft_quorum(const node_raft_cluster_t *r) {\n"
            "    return (r->broken_quorum != 0U) ? 2U : 3U;\n"
            "}",
            "static uint32_t raft_quorum(const node_raft_cluster_t *r) {\n"
            "    (void)r;\n"
            "    return 2U;\n"
            "}",
        ),
        NodeMutant(
            "M30_raft_drop_term_vote_reset",
            "raft_quorum_safety",
            "        if (m.term > r->current_term[m.dst]) {\n"
            "            r->current_term[m.dst] = m.term;\n"
            "            r->role[m.dst] = RAFT_ROLE_FOLLOWER;\n"
            "            r->voted_for[m.dst] = UINT32_MAX;\n"
            "        }",
            "        if (m.term > r->current_term[m.dst]) {\n"
            "            r->current_term[m.dst] = m.term;\n"
            "            r->role[m.dst] = RAFT_ROLE_FOLLOWER;\n"
            "        }",
        ),
        # --- 11. bft_equivocation (3) ---
        NodeMutant(
            "M31_bft_broken_quorum_2f",
            "bft_equivocation",
            "    b->quorum = b->n + 1U;\n"
            "    if (f <= 2U) {\n"
            "        if (broken_quorum != 0U) {\n"
            "            b->quorum = 2U * f;\n"
            "        } else if (b->n != 0U && (UINT64_C(3) * (uint64_t)f + UINT64_C(1)) <= (uint64_t)b->n) {\n"
            "            b->quorum = 2U * f + 1U;\n"
            "        }\n"
            "    }",
            "    (void)broken_quorum;\n    b->quorum = 2U * f;",
        ),
        NodeMutant(
            "M32_bft_skip_conflict_check",
            "bft_equivocation",
            "            if (commit_ok[j] != 0U && commit_val[i] != commit_val[j]) {",
            "            if (false && commit_ok[j] != 0U && commit_val[i] != commit_val[j]) {",
        ),
        NodeMutant(
            "M33_bft_double_honest_vote",
            "bft_equivocation",
            "        } else {\n"
            "            uint32_t p = (part_split != NULL) ? part_split[i] : 0U;\n"
            "            if ((p & 1U) == 0U) {\n"
            "                votes_a++;\n"
            "            } else {\n"
            "                votes_b++;\n"
            "            }\n"
            "        }",
            "        } else {\n"
            "            (void)part_split;\n"
            "            votes_a++;\n"
            "            votes_b++;\n"
            "        }",
        ),
        # --- 12. dst_prng_faults (3) ---
        NodeMutant(
            "M34_dst_freeze_prng",
            "dst_prng_faults",
            "    x ^= x >> 12U;\n    x ^= x << 25U;\n    x ^= x >> 27U;",
            "    x ^= UINT64_C(0);",
        ),
        NodeMutant(
            "M35_dst_disable_faults",
            "dst_prng_faults",
            "            if (roll < cfg->fault_prob_128) {\n"
            "                out->faults_injected++;",
            "            if (false && roll < cfg->fault_prob_128) {\n"
            "                out->faults_injected++;",
        ),
        NodeMutant(
            "M36_dst_ignore_violations",
            "dst_prng_faults",
            "        uint32_t u_viols = raft_ws->safety_violations + bft_ws->safety_violations;\n"
            "        out->violations_found += (uint64_t)u_viols;",
            "        uint32_t u_viols = raft_ws->safety_violations + bft_ws->safety_violations;\n"
            "        (void)u_viols;",
        ),
    ]


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    return run_sabotage_suite(
        ring0_path=repo_root / "src" / "node_ring0.c",
        cli_path=repo_root / "src" / "node_cli.c",
        schema_hdr=repo_root / "build" / "node_schema_abi.h",
        mutants=build_node_mutants(),
        repo_root=repo_root,
        prefix="node_mut_",
    )


if __name__ == "__main__":
    raise SystemExit(main())
