#ifndef NODE_H
#define NODE_H

#include "node_schema_abi.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * NODE v1.0.0 — Freestanding Pure-GPR Ring-0 Systems Trinity Core
 * ============================================================================
 * Layers:
 *   1. Deterministic Capability Micro-VM & O(1) Snapshot Replay
 *   2. DBSP Z-Set Algebra, WCOJ Triangle Join & Merkle Crash-Safe WAL
 *   3. CALM Join-Semilattice CRDTs, Raft Majority & BFT 3f+1 + DST
 * ============================================================================ */

#define NODE_SCHEMA_MAGIC    UINT32_C(0x4E4F4445)
#define NODE_SCHEMA_VERSION  UINT32_C(1)
#define NODE_VM_MAX_INSNS    256U
#define NODE_VM_NUM_REGS     8U
#define NODE_VM_MAX_CAPS     8U
#define NODE_VM_MEM_WORDS    256U
#define NODE_VM_LOG_CAP      64U
#define NODE_VM_SNAP_CAP     16U

#define NODE_CAP_R           UINT32_C(1)
#define NODE_CAP_W           UINT32_C(2)
#define NODE_CAP_X           UINT32_C(4)
#define NODE_CAP_G           UINT32_C(8)

#define NODE_OP_HALT         0U
#define NODE_OP_MOVI         1U
#define NODE_OP_ADD          2U
#define NODE_OP_SUB          3U
#define NODE_OP_XOR          4U
#define NODE_OP_AND          5U
#define NODE_OP_SHL          6U
#define NODE_OP_SHR          7U
#define NODE_OP_LOAD_CAP     8U
#define NODE_OP_STORE_CAP    9U
#define NODE_OP_ATTENUATE    10U
#define NODE_OP_JNZ          11U
#define NODE_OP_EMIT         12U

#define NODE_FAULT_NONE      0U
#define NODE_FAULT_FUEL      1U
#define NODE_FAULT_CAP       2U
#define NODE_FAULT_PC        3U
#define NODE_FAULT_OP        4U

#define NODE_ZSET_CAP        256U
#define NODE_ZSET_MAX_WEIGHT INT64_C(0x3FFFFFFF)
#define NODE_WCOJ_MAX_VERTS  128U
#define NODE_WCOJ_MAX_EDGES  1024U

#define NODE_WAL_MAX_RECS    256U
#define NODE_PAGE_COUNT      64U
#define NODE_WAL_FLAG_DATA   UINT32_C(1)
#define NODE_WAL_FLAG_COMMIT UINT32_C(2)

#define NODE_CRDT_NODES      8U
#define NODE_RAFT_N          5U
#define NODE_RAFT_LOG_CAP    64U
#define NODE_NET_MAX_MSGS    256U
#define NODE_BFT_MAX_N       8U

/* --- Layer 1: Capability Micro-VM & Snapshot Replay --- */

typedef struct {
    uint32_t region_id;
    uint32_t base;
    uint32_t len;
    uint32_t rights;
} node_cap_t;

typedef struct {
    uint16_t op;
    uint16_t dst;
    uint16_t src1;
    uint16_t src2;
    uint64_t imm;
} node_vm_insn_t;

typedef struct {
    node_vm_insn_t insns[NODE_VM_MAX_INSNS];
    uint32_t len;
    uint32_t pad;
} node_vm_prog_t;

typedef struct {
    uint64_t regs[NODE_VM_NUM_REGS];
    node_cap_t caps[NODE_VM_MAX_CAPS];
    uint64_t mem[NODE_VM_MEM_WORDS];
    uint64_t emit_log[NODE_VM_LOG_CAP];
    uint32_t emit_len;
    uint32_t pc;
    uint32_t fuel;
    uint32_t steps;
    uint32_t halted;
    uint32_t fault;
} node_vm_snap_t;

typedef struct {
    node_vm_snap_t state;
    uint32_t fuel_budget;
    uint32_t snap_count;
    uint32_t snap_head;
    uint32_t pad;
    node_vm_snap_t snaps[NODE_VM_SNAP_CAP];
} node_vm_t;

/* --- Layer 2: DBSP Z-Sets, WCOJ & Merkle Crash-Safe WAL --- */

typedef struct {
    uint64_t key;
    int64_t weight;
} node_zset_entry_t;

typedef struct {
    node_zset_entry_t entries[NODE_ZSET_CAP];
    uint32_t len;
    uint32_t pad;
} node_zset_t;

typedef struct {
    node_zset_t a_state;
    node_zset_t b_state;
    node_zset_t out_state;
    node_zset_t ws_da_b;
    node_zset_t ws_a_db;
    node_zset_t ws_da_db;
    node_zset_t ws_sum;
    uint64_t epoch;
    uint64_t inc_ops;
    uint64_t full_ops;
} node_dbsp_join_state_t;

typedef struct {
    uint32_t num_verts;
    uint32_t edge_count;
    uint32_t finalized;
    uint32_t pad;
    uint32_t src_buf[NODE_WCOJ_MAX_EDGES];
    uint32_t dst_buf[NODE_WCOJ_MAX_EDGES];
    uint32_t row_off[NODE_WCOJ_MAX_VERTS + 1U];
    uint32_t adj[NODE_WCOJ_MAX_EDGES];
} node_graph_t;

typedef struct {
    uint32_t lsn;
    uint32_t tx_id;
    uint32_t key;
    uint32_t flags;
    uint64_t val;
    uint64_t prev_hash;
    uint64_t rec_hash;
} node_wal_rec_t;

typedef struct {
    node_wal_rec_t recs[NODE_WAL_MAX_RECS];
    uint32_t len;
    uint32_t next_tx_id;
    uint64_t chain_hash;
} node_wal_t;

typedef struct {
    uint32_t leaf_idx;
    uint32_t depth;
    uint64_t leaf_val;
    uint8_t siblings[6][32];
} node_merkle_proof_t;

/* --- Layer 3: CALM CRDTs, Raft, BFT & DST --- */

typedef struct {
    uint64_t slots[NODE_CRDT_NODES];
} node_gcounter_t;

typedef struct {
    node_gcounter_t pos;
    node_gcounter_t neg;
} node_pncounter_t;

typedef struct {
    uint64_t ts;
    uint64_t node_id;
    uint64_t val;
    uint64_t pad;
} node_lww_reg_t;

typedef struct {
    uint32_t valid;
    uint32_t kind;
    uint32_t src;
    uint32_t dst;
    uint32_t term;
    uint32_t index;
    uint32_t prev_term;
    uint32_t success;
    uint32_t val;
    uint32_t deliver_tick;
    uint32_t entry_term;
    uint32_t leader_commit;
} node_net_msg_t;

typedef struct {
    uint32_t term;
    uint32_t cmd;
} node_raft_log_entry_t;

typedef struct {
    uint32_t n;
    uint32_t broken_quorum;
    uint32_t tick;
    uint32_t commits;
    uint32_t role[NODE_RAFT_N];
    uint32_t current_term[NODE_RAFT_N];
    uint32_t voted_for[NODE_RAFT_N];
    uint32_t votes_got[NODE_RAFT_N];
    uint32_t commit_index[NODE_RAFT_N];
    uint32_t last_applied[NODE_RAFT_N];
    uint32_t log_len[NODE_RAFT_N];
    uint32_t next_idx[NODE_RAFT_N][NODE_RAFT_N];
    uint32_t match_idx[NODE_RAFT_N][NODE_RAFT_N];
    node_raft_log_entry_t logs[NODE_RAFT_N][NODE_RAFT_LOG_CAP];
    uint32_t election_timer[NODE_RAFT_N];
    uint32_t partition_group[NODE_RAFT_N];
    uint32_t crashed[NODE_RAFT_N];
    uint32_t leader_mask_by_term[256];
    node_net_msg_t net[NODE_NET_MAX_MSGS];
    uint32_t safety_violations;
    uint32_t first_violation_tick;
    uint64_t prng;
} node_raft_cluster_t;

typedef struct {
    uint32_t n;
    uint32_t f;
    uint32_t quorum;
    uint32_t broken_quorum;
    uint32_t view;
    uint32_t round;
    uint32_t byz_mask;
    uint32_t commit_count;
    uint32_t partition_group[NODE_BFT_MAX_N];
    uint32_t crashed[NODE_BFT_MAX_N];
    uint64_t committed_hash[NODE_BFT_MAX_N];
    uint32_t committed_valid[NODE_BFT_MAX_N];
    uint32_t safety_violations;
    uint32_t first_violation_tick;
    uint64_t prng;
} node_bft_cluster_t;

typedef struct {
    uint64_t seed;
    uint32_t universes;
    uint32_t ticks_per_universe;
    uint32_t broken_quorum;
    uint32_t fault_prob_128;
} node_dst_cfg_t;

typedef struct {
    uint64_t seed;
    uint64_t universes;
    uint64_t ticks_total;
    uint64_t faults_injected;
    uint64_t partitions;
    uint64_t crashes;
    uint64_t commits;
    uint64_t crdt_converged;
    uint64_t wal_recoveries_ok;
    uint64_t violations_found;
    uint64_t min_witness_tick;
    uint64_t witness_universe;
    uint64_t state_root;
} node_dst_report_t;

/* --- Public Pure-GPR API --- */

void node_vm_init(node_vm_t *vm, uint32_t fuel_budget);
bool node_vm_grant_cap(node_vm_t *vm, uint32_t slot, uint32_t region_id, uint32_t base,
                       uint32_t len, uint32_t rights);
bool node_vm_attenuate_cap(node_vm_t *vm, uint32_t dst_slot, uint32_t src_slot, uint32_t new_base,
                           uint32_t new_len, uint32_t new_rights);
void node_vm_step(node_vm_t *vm, const node_vm_prog_t *prog);
void node_vm_run(node_vm_t *vm, const node_vm_prog_t *prog, uint32_t max_steps);
bool node_vm_snap_push(node_vm_t *vm);
bool node_vm_snap_restore(node_vm_t *vm, uint32_t rev_idx);
uint64_t node_vm_state_hash(const node_vm_t *vm);

void node_zset_init(node_zset_t *z);
bool node_zset_add_entry(node_zset_t *z, uint64_t key, int64_t weight);
bool node_zset_add(const node_zset_t *a, const node_zset_t *b, node_zset_t *out);
bool node_zset_sub(const node_zset_t *a, const node_zset_t *b, node_zset_t *out);
bool node_zset_filter_even(const node_zset_t *in, node_zset_t *out);
bool node_zset_join(const node_zset_t *a, const node_zset_t *b, node_zset_t *out,
                    uint64_t *ops_out);
bool node_zset_equal(const node_zset_t *a, const node_zset_t *b);
uint64_t node_zset_hash(const node_zset_t *z);

void node_dbsp_join_init(node_dbsp_join_state_t *st);
bool node_dbsp_join_step(node_dbsp_join_state_t *st, const node_zset_t *da, const node_zset_t *db,
                         node_zset_t *delta_out);

void node_graph_init(node_graph_t *g, uint32_t num_verts);
bool node_graph_add_edge(node_graph_t *g, uint32_t u, uint32_t v);
bool node_graph_finalize(node_graph_t *g);
uint64_t node_wcoj_count_triangles(const node_graph_t *g, uint64_t *probes_out);
uint64_t node_binjoin_count_triangles(const node_graph_t *g, uint64_t *wedges_out,
                                      uint64_t *probes_out);

void node_wal_init(node_wal_t *w);
bool node_wal_append_data(node_wal_t *w, uint32_t tx_id, uint32_t key, uint64_t val);
bool node_wal_append_commit(node_wal_t *w, uint32_t tx_id);
uint32_t node_wal_recover(const node_wal_t *w, uint32_t prefix_len, uint32_t corrupt_idx,
                          uint64_t corrupt_mask, uint64_t pages_out[NODE_PAGE_COUNT],
                          uint32_t *recovered_txs_out, uint64_t *merkle_root_out);
void node_merkle_root64(const uint64_t pages[NODE_PAGE_COUNT], uint8_t root_out[32]);
bool node_merkle_proof64(const uint64_t pages[NODE_PAGE_COUNT], uint32_t leaf_idx,
                         node_merkle_proof_t *proof_out);
bool node_merkle_verify_proof64(const node_merkle_proof_t *proof, const uint8_t root[32]);

void node_gcounter_init(node_gcounter_t *c);
void node_gcounter_inc(node_gcounter_t *c, uint32_t node_idx, uint64_t delta);
void node_gcounter_merge(node_gcounter_t *dst, const node_gcounter_t *src);
uint64_t node_gcounter_value(const node_gcounter_t *c);
bool node_gcounter_equal(const node_gcounter_t *a, const node_gcounter_t *b);

void node_pncounter_init(node_pncounter_t *c);
void node_pncounter_inc(node_pncounter_t *c, uint32_t node_idx, uint64_t delta);
void node_pncounter_dec(node_pncounter_t *c, uint32_t node_idx, uint64_t delta);
void node_pncounter_merge(node_pncounter_t *dst, const node_pncounter_t *src);
int64_t node_pncounter_value(const node_pncounter_t *c);
bool node_pncounter_equal(const node_pncounter_t *a, const node_pncounter_t *b);

void node_lww_init(node_lww_reg_t *r, uint64_t ts, uint64_t node_id, uint64_t val);
void node_lww_merge(node_lww_reg_t *dst, const node_lww_reg_t *src);
bool node_lww_equal(const node_lww_reg_t *a, const node_lww_reg_t *b);

void node_raft_init(node_raft_cluster_t *r, uint64_t seed, uint32_t broken_quorum);
void node_raft_tick(node_raft_cluster_t *r, uint32_t cmd_if_leader);
bool node_raft_check_safety(node_raft_cluster_t *r);

void node_bft_init(node_bft_cluster_t *b, uint32_t n, uint32_t f, uint32_t byz_mask,
                   uint32_t broken_quorum, uint64_t seed);
void node_bft_step_round(node_bft_cluster_t *b, uint64_t val_a, uint64_t val_b,
                         const uint32_t part_split[NODE_BFT_MAX_N]);

uint64_t node_prng_next(uint64_t *state);
void node_dst_run(const node_dst_cfg_t *cfg, node_dst_report_t *out, node_raft_cluster_t *raft_ws,
                  node_bft_cluster_t *bft_ws, node_wal_t *wal_ws);

void node_arena_fill_summary(NodeArena *arena, const node_vm_t *vm,
                             const node_dbsp_join_state_t *dbsp, const node_wal_t *wal,
                             const node_dst_report_t *dst);

bool node_ct_eq32(const uint8_t a[32], const uint8_t b[32]);
bool node_ct_eq_u64(uint64_t a, uint64_t b);
uint64_t node_ct_select_u64(uint64_t a, uint64_t b, uint32_t sel_bit);
void node_ct_cswap32(uint8_t a[32], uint8_t b[32], uint32_t swap_bit);
void node_net_msg_mac(const uint8_t key[32], const node_net_msg_t *msg, uint8_t tag_out[32]);
bool node_net_msg_verify(const uint8_t key[32], const node_net_msg_t *msg, const uint8_t tag[32]);

#ifdef __cplusplus
}
#endif

#endif /* NODE_H */
