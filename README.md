# NODE v1.0.0 — Certified Deterministic Systems Substrate

**Pure Lean 4 Formal Systems Theory (`84` Kernel-Checked Theorems, `0 sorryAx`, `0 bv_decide`, `0 Lean.ofReduceBool`) + Freestanding Pure-GPR / Zero-Float / Zero-Heap / Zero-`blr` Ring-0 C17 Systems Core (`libnode.a`) + Zero-Heap Native CLI, POSIX UDP/Disk WAL & [`../INFO`](../INFO/README.md) `"INF1"` Compactor (`build/node`, `124,152 B`) + `256`-Slot `16,384 B` Zero-`memcpy` Schema ABI (`FLOW v9.0.0`) + `36 / 36` (`100.0%`) Single-Fault Sabotage Audit + [`../Auditor`](../Auditor/README.md) LLVM IR (`-O2`) Constant-Time (`7/7`), LLVM-to-Z3, Dolev-Yao (`3/3`) & `QF_BV` (`6/6`) Audit.**

---

## Architecture — The Deterministic Systems Trinity

`NODE` unifies the three foundational layers of systems software as one deterministic, replayable, formally certified state-machine substrate:

1. **Layer 1 — Deterministic Capability Micro-VM & $O(1)$ Snapshot Replay ([`Node/Sandbox.lean`](Node/Sandbox.lean))**:
   - Unforgeable `(regionId, base, len, R/W/X/G)` capability model with monotonic attenuation (`node_vm_attenuate_cap`).
   - Provable spatial non-interference across regions (`cap_non_interference_step`, `cap_non_interference_run`), static WCET fuel upper bound (`vmRun_halts_within_fuel`), and bit-exact circular snapshot rewind/replay (`replay_from_checkpoint_exact`).
2. **Layer 2 — Incremental DBSP $\mathbb{Z}$-Set Store, Recursive Reachability, Dynamic Triangles, WCOJ & Merkle/POSIX WAL ([`Node/Dbsp.lean`](Node/Dbsp.lean), [`src/node_disk_wal.h`](src/node_disk_wal.h))**:
   - Exact DBSP Abelian $\mathbb{Z}$-set algebra (`diff`, `integ`, bilinear join delta `dbsp_bilinear_join_delta_all`, incremental-equals-full theorem `dbsp_incremental_join_matches_full`) + semi-naive transitive reachability (`reachStep_monotone`, `reachIter_monotone`, `reachIter_extensive`, `reach_fixpoint_stable`, `node_dbsp_reach_from`) and incremental SWAR dynamic triangle maintenance (`node_dyn_tri_apply_edge`).
   - Sorted Worst-Case Optimal Triangle Join (`wcoj_triangle_sound_complete`, degree-split bound `wcoj_degree_split_bound`) eliminating skew blowups without materializing 2-hop wedges.
   - SHA-256 hash-chained WAL (`wal_torn_tail_ignored`, `wal_uncommitted_tail_ignored`, `wal_recovery_idempotent`) + 64-leaf binary SHA-256 Merkle tree (`node_merkle_proof64`, `node_merkle_verify_proof64`) + POSIX segmented disk WAL (`open`/`write`/`fsync`/`ftruncate`) with static `.bss` [`../INFO`](../INFO/README.md) `"INF1"` snapshot compaction (`4096 B -> 1671 B`, exact roundtrip).
3. **Layer 3 — CALM CRDTs, Raft Majority, Anti-Replay Framing, Real UDP Loopback & Multi-Universe DST ([`Node/Consensus.lean`](Node/Consensus.lean), [`Node/Dst.lean`](Node/Dst.lean), [`src/node_net_udp.h`](src/node_net_udp.h))**:
   - Verified Join-Semilattice CRDTs (`GCounter`, `PNCounter`, `LWWReg`) + CALM monotonic persistence (`calm_monotone_persistence`, `semilattice_fold_swap`, `semilattice_fold_dup`).
   - Quorum safety (`bft_quorum_intersection`, `bft_honest_witness`, `bft_no_conflicting_commits`, `raft_majority_intersection`, `raft_election_safety`), Two-Generals impossibility (`two_generals_no_finite_protocol`), and 64-slot anti-replay sliding-window proofs (`replay_window_rejects_old`, `replay_window_accepts_advance`, `replay_window_marks_seen`, `replay_window_no_duplicate`) backing branchless CT key derivation (`node_session_derive_key`), wire framing (`node_net_wire_frame_*`), and real `127.0.0.1` UDP loopback (`udp-loopback`).
   - Full Raft §5.3 / §5.4.2 log-matching & majority-commit engine + Byzantine equivocation engine + `xorshift64*` multi-universe DST (`node_dst_run`).

---

## Pure-Theory Pillars (`Node.Theory` — 84 Theorems)

| Module | Scope | Verified Properties |
| :--- | :--- | :--- |
| [`Node/Sandbox.lean`](Node/Sandbox.lean) | Layer 1 Capability Micro-VM | Rights preorder transitivity, attenuation bounds & region preservation, non-interference across isolated regions, fuel WCET termination, deterministic snapshot replay |
| [`Node/Dbsp.lean`](Node/Dbsp.lean) | Layer 2 DBSP + Reachability + WCOJ + WAL | $\mathbb{Z}$-set Abelian group laws, `integ (diff s) = s`, `diff (integ s) = s`, linear & bilinear join incrementality, semi-naive reachability monotonicity/extensiveness/fixpoint stability, WCOJ intersection soundness & degree-split bound, torn/uncommitted WAL crash atomicity & Merkle tamper detection |
| [`Node/Consensus.lean`](Node/Consensus.lean) | Layer 3 CALM + Raft + BFT + Anti-Replay | Semilattice poset & CRDT instances (`GCounter`, `PNCounter`, `LwwReg`), fold commutativity/idempotency, $3f+1$ BFT honest intersection, Raft majority election safety, Two-Generals No-Go, 64-slot sliding-window anti-replay safety |
| [`Node/Dst.lean`](Node/Dst.lean) | Deterministic Simulation (DST) | Same-seed replay identity, bounded fault budget, minimal first-violation witness tick, constructive split-brain & BFT equivocation counterexamples |
| [`Node.lean`](Node.lean) | Pure Schema ABI (`Flow.Schema`) | `256`-cell (`16,384 B`) `NodeArena` schema (`0` local theorems/axioms, `0 memcpy`) emitting `build/node_schema_abi.h` |

---

## Verified 9-Gate Zero-Trust Audit

| Gate | Target | Verified Result (`make verify-all`) |
| :--- | :--- | :--- |
| **Gate 0** | `Node.Theory` | `84` theorems, `leanchecker` PASS on all 5 modules, `0 sorry`, `0 sorryAx`, `0 Lean.ofReduceBool`, `0 Lean.trustCompiler` |
| **Gate 1** | `Node.lean` Schema ABI | `256`-slot (`16,384 B`) `build/node_schema_abi.h`, `0 memcpy`, `leanchecker Node` PASS |
| **Gate 2** | `src/node_ring0.c` (`libnode.a`) | `-ffreestanding -nostdlib -mgeneral-regs-only`: `0` undefined symbols (`nm -u`), `0` `udiv`/`sdiv`/float/SIMD/`blr`/`br` (`otool -tV`), C++20 `include/node.h` clean, `clang-tidy` `0` warnings |
| **Gate 3** | `./build/node selftest` | `18 / 18` built-in Ring-0, anti-replay/wire, DBSP reachability/dynamic triangles, UDP loopback, POSIX WAL + INFO & certificate suites PASS |
| **Gate 4** | `build/node` Binary Audit | `124,152 B` (linking `../INFO/build/libinfo.a`), `0` `leanshared` linkage, `0` heap allocators (`malloc`/`free`/`calloc`/`realloc`) |
| **Gate 5** | `oracles/verify_node_oracle.py` | Independent Python oracle PASS (VM replay, DBSP/WCOJ, `25/25` WAL cuts, DST reproducibility, `3/3` live Lean certs replayed) |
| **Gate 6** | `tools/node_sabotage_check.py` | **`36 / 36` (`100.0%`)** single-fault mutants killed across 12 categories (`3/3` per category) in `7.71s` |
| **Gate 7** | `clang-format` | `0` formatting violations across all `.h`/`.c` sources |
| **Gate 8** | `tools/node_auditor_check.py` ([`../Auditor`](../Auditor/README.md)) | **`7/7` LLVM IR `-O2` `CONSTANT_TIME_VERIFIED`** (`node_ct_eq32`, `node_ct_eq_u64`, `node_ct_select_u64`, `node_ct_cswap32`, `node_net_msg_mac`, `node_net_msg_verify`, `node_session_derive_key`), negative control `node_leaky_auth` flagged `SECRET_BRANCH`, **`6/6` Z3 `5.3.3` `QF_BV` pairs** (`buggy=sat` + C replay rejected, `patched=unsat`), **`5/5` LLVM-to-Z3 `-O1 == -O2` & `nsw` UB + `2/2` buggy UB SAT**, **`3/3` Dolev-Yao protocol pairs (`replay_attack`, `mitm_handshake`, `downgrade_attack`)**, and **`10/10` Net MAC** bit-flip tampers rejected (`20,590.75ms`) |

---

## Verified Benchmark Results (`make experiments`)

### Layer 1–3 Systems Trinity Suite
- **Layer 1 (Micro-VM & Replay)**: `steps=10`, `replay_exact=True`, `escalation_blocked=True`, `hash=0xdec042e21803cc22`
- **Layer 2 (DBSP Incremental Join)**: `epochs=20`, `exact=True`, `inc_ops=409` vs `full_ops=2560` (**`6.26x` work reduction**)
- **Layer 2 (WCOJ Triangle Join)**: `triangles=32 == 32`, `wcoj_probes=329` vs `bin_wedges=780 + bin_probes=1717` (**`7.59x` work reduction**)
- **Layer 2 (Merkle Crash-Safe WAL)**: `cuts=25/25` (**`100.0%` atomic**), `torn_rejected=24/24`, `merkle_bitrot_caught=True`
- **Layer 2 (POSIX Disk WAL + `INFO` `"INF1"` Compaction)**: `recs=95/96`, `segs=3`, `torn_rejected=1`, `codec=INFO_INF1` (`4096 B -> 1671 B`, `exact=True`)
- **Layer 3 (Multi-Universe DST, Clean Quorum)**: `universes=128`, `ticks=16,384`, `faults=4,624`, `commits=36,467`, `crdt_conv=128/128`, **`violations=0`** (`45.18ms`)
- **Layer 3 (Multi-Universe DST, Broken Quorum `--buggy`)**: `universes=128`, **`violations=32,768`**, `min_witness_tick=1`, `witness_universe=0`
- **Layer 3 (Authenticated `127.0.0.1` UDP Loopback)**: `frames=512/512`, `replay_rejected=1`, `tamper_rejected=1` (`22,420 us`)

---

## Build & Usage

```sh
make verify-all
make experiments

./build/node selftest
./build/node vm-demo
./build/node dbsp-demo
./build/node wal-audit
./build/node dst --universes 128 --ticks 128 --seed 0x20261123
./build/node dst --universes 128 --ticks 128 --seed 0x20261123 --buggy
./build/node udp-loopback 512
./build/node disk-compact /tmp/node_disk_wal
./build/node audit-replay net-mac
./build/node emit-certs build/certs
```
