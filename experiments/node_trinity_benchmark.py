#!/usr/bin/env python3
"""
experiments/node_trinity_benchmark.py — NODE v1.0.0 Systems Trinity Benchmarks
=================================================================================
Measures and verifies:
  1. Layer 1: Capability Micro-VM WCET & O(1) Snapshot Replay Parity
  2. Layer 2: DBSP Incremental Bilinear Join op-reduction & WCOJ vs Binary Join work ratio
  3. Layer 2: Merkle Crash-Safe WAL full cut-sweep survival rate & bit-rot proof check
  4. Layer 3: Multi-Universe Deterministic Simulation Testing (clean vs broken quorum witness)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NODE_BIN = ROOT / "build" / "node"
CERTS_DIR = ROOT / "build" / "certs"


def run_json(args: list[str]) -> dict:
    p = subprocess.run([str(NODE_BIN), *args], cwd=str(ROOT), capture_output=True, text=True, check=True)
    return json.loads(p.stdout)


def main() -> int:
    CERTS_DIR.mkdir(parents=True, exist_ok=True)
    subprocess.run([str(NODE_BIN), "emit-certs", str(CERTS_DIR)], cwd=str(ROOT), check=True)

    vm = run_json(["vm-demo"])
    dbsp = run_json(["dbsp-demo"])
    wal = run_json(["wal-audit"])

    t0 = time.perf_counter()
    dst_clean = run_json(["dst", "--universes", "128", "--ticks", "128", "--seed", "0x20261123"])
    t_clean = time.perf_counter() - t0

    dst_buggy = run_json(
        ["dst", "--universes", "128", "--ticks", "128", "--seed", "0x20261123", "--buggy"]
    )
    udp = run_json(["udp-loopback", "512"])
    disk = run_json(["disk-compact", "/tmp/node_bench_wal"])

    inc_reduction = dbsp["full_join_ops"] / max(1, dbsp["dbsp_inc_ops"])
    wcoj_reduction = (dbsp["binjoin_wedges"] + dbsp["binjoin_probes"]) / max(1, dbsp["wcoj_probes"])

    print("=" * 72)
    print("NODE v1.0.0 — SYSTEMS TRINITY BENCHMARK SUITE")
    print("=" * 72)
    print(f"[Layer 1 VM]   steps={vm['steps']} replay_exact={vm['replay_exact']} escalation_blocked={vm['escalation_blocked']} hash={vm['replay_hash']}")
    print(f"[Layer 2 DBSP] epochs={dbsp['epochs']} exact={dbsp['dbsp_exact_match']} inc_ops={dbsp['dbsp_inc_ops']} vs full_ops={dbsp['full_join_ops']} ({inc_reduction:.2f}x work reduction)")
    print(f"[Layer 2 WCOJ] triangles={dbsp['wcoj_triangles']}=={dbsp['binjoin_triangles']} wcoj_probes={dbsp['wcoj_probes']} vs bin_wedges={dbsp['binjoin_wedges']}+probes={dbsp['binjoin_probes']} ({wcoj_reduction:.2f}x work reduction)")
    print(f"[Layer 2 WAL]  cuts={wal['atomic_ok']}/{wal['cuts_tested']} (100.0% atomic) torn_rejected={wal['torn_rejected']}/{wal['wal_len']} merkle_bitrot_caught={wal['bitrot_caught']}")
    print(f"[Layer 3 DST Clean] universes={dst_clean['universes']} ticks={dst_clean['ticks_total']} faults={dst_clean['faults_injected']} commits={dst_clean['commits']} crdt_conv={dst_clean['crdt_converged']}/{dst_clean['universes']} viol={dst_clean['violations_found']} ({t_clean*1000:.2f}ms)")
    print(f"[Layer 3 DST Buggy] universes={dst_buggy['universes']} viol={dst_buggy['violations_found']} min_witness_tick={dst_buggy['min_witness_tick']} witness_universe={dst_buggy['witness_universe']}")
    print(f"[Layer 3 UDP Net]   port={udp['port']} frames={udp['recv_ok']}/{udp['sent_ok']} replay_rejected={udp['replay_rejected']} tamper_rejected={udp['tamper_rejected']} ({udp['elapsed_us']} us)")
    print(f"[Layer 2 Disk WAL]  recs={disk['recovered_records']}/{disk['records_written']} segs={disk['segments_written']} torn_rejected={disk['torn_rejected']} codec={disk['codec']} ({disk['raw_snap_bytes']}B -> {disk['compressed_snap_bytes']}B, exact={disk['roundtrip_exact']})")

    assert vm["replay_exact"] and vm["escalation_blocked"]
    assert dbsp["dbsp_exact_match"] and dbsp["wcoj_triangles"] == dbsp["binjoin_triangles"]
    assert wal["atomic_ok"] == wal["cuts_tested"] and wal["bitrot_caught"]
    assert dst_clean["violations_found"] == 0 and dst_clean["crdt_converged"] == 128
    assert dst_buggy["violations_found"] > 0
    assert udp["passed"] and disk["passed"] and disk["roundtrip_exact"]

    print("=" * 72)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
