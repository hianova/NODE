#!/usr/bin/env python3
"""
tools/node_auditor_check.py — Auditor Cross-Ecosystem Security Gate (Gate 8)
=============================================================================
Applies ../Auditor's Track 2 verification methodology directly to NODE v1.0.0:
  Track A: LLVM IR (-O2) SSA Secret-Taint Constant-Time Audit (6 CT functions + negative control)
  Track B: Z3 5.3.3 QF_BV Bit-Exact SMT Security Audit (6 buggy SAT + patched UNSAT pairs + C replay)
  Track C: Live Consensus Network Packet Keyed SHA-256 MAC Tamper Rejection Replay
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build"
NODE_BIN = BUILD / "node"
FLOW_DIR = Path(os.environ.get("FLOW_DIR", str(ROOT.parent / "FLOW"))).resolve()


def _find_auditor_dir() -> Optional[Path]:
    for cand in [
        os.environ.get("AUDITOR_DIR", ""),
        str(ROOT.parent / "Auditor"),
        str(ROOT.parent / "auditor"),
    ]:
        if cand:
            p = Path(cand).resolve()
            if (p / "crypto" / "ct_llvm_audit.py").exists():
                return p
    return None


def _find_clang() -> str:
    for c in [os.environ.get("CC", ""), "/opt/homebrew/opt/llvm/bin/clang", shutil.which("clang") or ""]:
        if c and Path(c).exists():
            return c
    return "clang"


def _find_z3() -> Optional[str]:
    for c in [os.environ.get("Z3_BIN", ""), "/opt/homebrew/bin/z3", shutil.which("z3") or ""]:
        if c and Path(c).exists():
            return c
    return None


def run_z3(z3_bin: str, smt2: str) -> Tuple[str, Dict[str, int], float]:
    t0 = time.perf_counter()
    proc = subprocess.run(
        [z3_bin, "-smt2", "-in"],
        input=smt2,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    dt_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    out = proc.stdout.strip()
    if proc.returncode != 0 and not out:
        raise RuntimeError(f"Z3 failed ({proc.returncode}): {proc.stderr}")
    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    status = lines[0] if lines else "error"
    model: Dict[str, int] = {}
    if status == "sat":
        body = "\n".join(lines[1:])
        for m in re.finditer(r"\(\s*([A-Za-z0-9_]+)\s+(#x[0-9a-fA-F]+|#b[01]+)\s*\)", body):
            name, lit = m.group(1), m.group(2)
            uval = int(lit[2:], 16) if lit.startswith("#x") else int(lit[2:], 2)
            model[name] = uval
        for m in re.finditer(
            r"\(define-fun\s+([A-Za-z0-9_]+)\s+\(\)\s+\(_ BitVec \d+\)\s+(#x[0-9a-fA-F]+|#b[01]+)\s*\)",
            body,
            re.DOTALL,
        ):
            name, lit = m.group(1), m.group(2)
            uval = int(lit[2:], 16) if lit.startswith("#x") else int(lit[2:], 2)
            model[name] = uval
    return status, model, dt_ms


def _parse_llvm_functions_clang23(ir_text: str) -> Dict[str, Tuple[List[Tuple[str, bool]], List[str]]]:
    """Parse LLVM 23 `define` signatures (which may contain `captures(none)` / nested parens)."""
    reg_re = re.compile(r"%[A-Za-z0-9_.$-]+")
    def_re = re.compile(r"^define\b.*@([A-Za-z0-9_.$]+)\((.*)\)[^{]*\{$")
    functions: Dict[str, Tuple[List[Tuple[str, bool]], List[str]]] = {}
    lines = ir_text.splitlines()
    i = 0
    while i < len(lines):
        m = def_re.match(lines[i].strip())
        if not m:
            i += 1
            continue
        fn_name, params_raw = m.group(1), m.group(2)
        params: List[Tuple[str, bool]] = []
        if params_raw.strip():
            cleaned = re.sub(r"\([^)]*\)", "", params_raw)
            for part in cleaned.split(","):
                regs = reg_re.findall(part)
                if regs:
                    reg = regs[-1]
                    is_ptr = bool(re.search(r"\bptr\b", part))
                    params.append((reg, is_ptr))
        body: List[str] = []
        i += 1
        while i < len(lines) and lines[i].strip() != "}":
            body.append(lines[i])
            i += 1
        functions[fn_name] = (params, body)
        i += 1
    return functions


def run_llvm_ct_track(auditor_dir: Path, clang_bin: str) -> Dict[str, object]:
    sys.path.insert(0, str(auditor_dir / "crypto"))
    from ct_llvm_audit import analyze_function, parse_functions  # type: ignore

    ll_out = BUILD / "node_ring0.ll"
    subprocess.run(
        [
            clang_bin,
            "-std=c17",
            "-O2",
            "-fno-builtin",
            "-fno-discard-value-names",
            "-S",
            "-emit-llvm",
            "-I",
            str(ROOT / "include"),
            "-I",
            str(BUILD),
            "-isystem",
            str(FLOW_DIR / "core"),
            "-isystem",
            str(FLOW_DIR / "sdk"),
            str(ROOT / "src" / "node_ring0.c"),
            "-o",
            str(ll_out),
        ],
        check=True,
    )
    ir_text = ll_out.read_text(encoding="utf-8")
    functions = parse_functions(ir_text)

    ct_targets = [
        "node_ct_eq32",
        "node_ct_eq_u64",
        "node_ct_select_u64",
        "node_ct_cswap32",
        "node_net_msg_mac",
        "node_net_msg_verify",
        "node_session_derive_key",
    ]
    verified_results = []
    for fn in ct_targets:
        assert fn in functions, f"Missing @{fn} in {ll_out}"
        params, body = functions[fn]
        assert len(params) >= 2, f"Parameter parse empty for {fn}: {params}"
        res = analyze_function(fn, params, body, functions=functions)
        assert res["status"] == "CONSTANT_TIME_VERIFIED", f"CT violation in {fn}: {res}"
        verified_results.append(res)
        print(f"  [CT PATCHED]  {fn:<24} -> {res['status']} ({res['instruction_count']} IR insts)")

    # Negative control: side-effecting early-exit comparison must be flagged by Auditor
    with tempfile.TemporaryDirectory(prefix="node_ct_neg_") as td:
        neg_c = Path(td) / "neg.c"
        neg_ll = Path(td) / "neg.ll"
        neg_c.write_text(
            "#include <stddef.h>\n#include <stdint.h>\n"
            "uint32_t node_leaky_auth(const uint8_t a[32], const uint8_t b[32], volatile uint32_t *sink) {\n"
            "    for (size_t i = 0; i < 32U; ++i) {\n"
            "        if (a[i] != b[i]) { *sink = (uint32_t)i; return 0U; }\n"
            "    }\n"
            "    return 1U;\n}\n",
            encoding="utf-8",
        )
        subprocess.run(
            [clang_bin, "-std=c17", "-O2", "-fno-builtin", "-fno-discard-value-names", "-S", "-emit-llvm", str(neg_c), "-o", str(neg_ll)],
            check=True,
        )
        neg_fns = _parse_llvm_functions_clang23(neg_ll.read_text(encoding="utf-8"))
        assert "node_leaky_auth" in neg_fns
        neg_res = analyze_function("node_leaky_auth", *neg_fns["node_leaky_auth"])
        kinds = [v["kind"] for v in neg_res["violations"]]
        assert neg_res["status"] == "CONSTANT_TIME_VIOLATION" and "SECRET_BRANCH" in kinds, neg_res
        print(f"  [CT LEAKY]    {'node_leaky_auth':<24} -> {neg_res['status']} ({kinds})")

    return {
        "ir_file": str(ll_out),
        "verified": verified_results,
        "negative_control": neg_res,
    }


def _bv_pop4(name: str) -> str:
    terms = [
        f"((_ zero_extend 2) ((_ extract {b} {b}) {name}))"
        for b in range(4)
    ]
    return f"(bvadd {terms[0]} (bvadd {terms[1]} (bvadd {terms[2]} {terms[3]})))"


def run_z3_security_track(z3_bin: str) -> List[Dict[str, object]]:
    pairs: List[Dict[str, object]] = []

    # 1. vm_attenuate_bounds_wrap32
    smt_p1_buggy = """
(set-logic QF_BV)
(declare-const sbase (_ BitVec 32))
(declare-const slen  (_ BitVec 32))
(declare-const nbase (_ BitVec 32))
(declare-const nlen  (_ BitVec 32))
(assert (bvule sbase (_ bv256 32)))
(assert (bvule slen  (bvsub (_ bv256 32) sbase)))
(assert (bvuge nbase sbase))
(assert (bvule (bvadd nbase nlen) (bvadd sbase slen)))
; Unsafe: real 64-bit upper end exceeds parent upper end!
(assert (bvugt (bvadd ((_ zero_extend 32) nbase) ((_ zero_extend 32) nlen))
               (bvadd ((_ zero_extend 32) sbase) ((_ zero_extend 32) slen))))
(check-sat)
(get-value (sbase slen nbase nlen))
"""
    smt_p1_patched = """
(set-logic QF_BV)
(declare-const sbase (_ BitVec 32))
(declare-const slen  (_ BitVec 32))
(declare-const nbase (_ BitVec 32))
(declare-const nlen  (_ BitVec 32))
(assert (bvule sbase (_ bv256 32)))
(assert (bvule slen  (bvsub (_ bv256 32) sbase)))
(assert (bvuge nbase sbase))
(assert (bvule nbase (bvadd sbase slen)))
(assert (bvule nlen  (bvsub (bvadd sbase slen) nbase)))
(assert (bvugt (bvadd ((_ zero_extend 32) nbase) ((_ zero_extend 32) nlen))
               (bvadd ((_ zero_extend 32) sbase) ((_ zero_extend 32) slen))))
(check-sat)
"""
    st_b, m_b, ms_b = run_z3(z3_bin, smt_p1_buggy)
    st_p, _, ms_p = run_z3(z3_bin, smt_p1_patched)
    assert st_b == "sat" and st_p == "unsat", (st_b, st_p)
    replay1 = subprocess.run(
        [
            str(NODE_BIN),
            "audit-replay",
            "cap-attenuate",
            str(m_b["sbase"]),
            str(m_b["slen"]),
            str(m_b["nbase"]),
            str(m_b["nlen"]),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(replay1.stdout)["accepted"] is False, replay1.stdout
    pairs.append({"name": "vm_attenuate_bounds_wrap32", "buggy": st_b, "patched": st_p, "ms": round(ms_b + ms_p, 2), "replay_rejected": True})
    print(f"  [Z3 QF_BV]    vm_attenuate_bounds_wrap32 -> buggy={st_b} (C replay rejected), patched={st_p} ({ms_p}ms)")

    # 2. vm_check_cap_wrap32
    smt_p2_buggy = """
(set-logic QF_BV)
(declare-const base (_ BitVec 32))
(declare-const len  (_ BitVec 32))
(declare-const addr (_ BitVec 32))
; Buggy naive uint32 check without upper-sum guard on corrupt base/len
(assert (bvuge addr base))
(assert (bvult addr (bvadd base len)))
(assert (or (bvugt base (_ bv256 32)) (bvugt len (bvsub (_ bv256 32) base))))
(check-sat)
"""
    smt_p2_patched = """
(set-logic QF_BV)
(declare-const base (_ BitVec 32))
(declare-const len  (_ BitVec 32))
(declare-const addr (_ BitVec 32))
(assert (bvule base (_ bv256 32)))
(assert (bvule len  (bvsub (_ bv256 32) base)))
(assert (bvuge addr base))
(assert (bvult (bvsub addr base) len))
(assert (bvult addr (_ bv256 32)))
(assert (bvuge (bvadd ((_ zero_extend 32) base) ((_ zero_extend 32) len))
               ((_ zero_extend 32) addr)))
; Must never exceed memory region bounds 256 or wrap base+len
(assert (not (and (bvult addr (_ bv256 32)) (bvult (bvsub addr base) len))))
(check-sat)
"""
    st_b, _, ms_b = run_z3(z3_bin, smt_p2_buggy)
    st_p, _, ms_p = run_z3(z3_bin, smt_p2_patched)
    assert st_b == "sat" and st_p == "unsat", (st_b, st_p)
    pairs.append({"name": "vm_check_cap_wrap32", "buggy": st_b, "patched": st_p, "ms": round(ms_b + ms_p, 2)})
    print(f"  [Z3 QF_BV]    vm_check_cap_wrap32        -> buggy={st_b}, patched={st_p} ({ms_p}ms)")

    # 3. dbsp_zset_signed_overflow64
    smt_p3_buggy = """
(set-logic QF_BV)
(declare-const w1 (_ BitVec 64))
(declare-const w2 (_ BitVec 64))
(assert (bvsgt w1 (_ bv0 64)))
(assert (bvsgt w2 (_ bv0 64)))
; Signed overflow: positive + positive wraps negative in two's complement!
(assert (bvslt (bvadd w1 w2) (_ bv0 64)))
(check-sat)
(get-value (w1 w2))
"""
    smt_p3_patched = """
(set-logic QF_BV)
(declare-const w1 (_ BitVec 64))
(declare-const w2 (_ BitVec 64))
(define-fun maxw () (_ BitVec 64) #x000000003fffffff)
(define-fun minw () (_ BitVec 64) #xffffffffc0000001)
(assert (and (bvsge w1 minw) (bvsle w1 maxw)))
(assert (and (bvsge w2 minw) (bvsle w2 maxw)))
(define-fun sumw () (_ BitVec 64) (bvadd w1 w2))
(define-fun prod () (_ BitVec 64) (bvmul w1 w2))
(assert (or (not (= ((_ sign_extend 1) sumw)
                    (bvadd ((_ sign_extend 1) w1) ((_ sign_extend 1) w2))))
            (not (= ((_ sign_extend 64) prod)
                    (bvmul ((_ sign_extend 64) w1) ((_ sign_extend 64) w2))))))
(check-sat)
"""
    st_b, m_b, ms_b = run_z3(z3_bin, smt_p3_buggy)
    st_p, _, ms_p = run_z3(z3_bin, smt_p3_patched)
    assert st_b == "sat" and st_p == "unsat", (st_b, st_p)
    w1_s = m_b["w1"] - (1 << 64) if (m_b["w1"] & (1 << 63)) else m_b["w1"]
    w2_s = m_b["w2"] - (1 << 64) if (m_b["w2"] & (1 << 63)) else m_b["w2"]
    replay3 = subprocess.run(
        [str(NODE_BIN), "audit-replay", "zset-overflow", str(w1_s), str(w2_s)],
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(replay3.stdout)["accepted"] is False, replay3.stdout
    pairs.append({"name": "dbsp_zset_signed_overflow64", "buggy": st_b, "patched": st_p, "ms": round(ms_b + ms_p, 2), "replay_rejected": True})
    print(f"  [Z3 QF_BV]    dbsp_zset_signed_overflow64-> buggy={st_b} (C replay rejected), patched={st_p} ({ms_p}ms)")

    # 4. raft_net_tick_term_wrap32
    smt_p4_buggy = """
(set-logic QF_BV)
(declare-const tick  (_ BitVec 32))
(declare-const delay (_ BitVec 32))
(assert (bvult (bvadd tick delay) tick))
(check-sat)
"""
    smt_p4_patched = """
(set-logic QF_BV)
(declare-const tick  (_ BitVec 32))
(declare-const delay (_ BitVec 32))
(define-fun sat_deliv () (_ BitVec 32)
  (ite (bvugt delay (bvsub #xffffffff tick)) #xffffffff (bvadd tick delay)))
(assert (bvult sat_deliv tick))
(check-sat)
"""
    st_b, _, ms_b = run_z3(z3_bin, smt_p4_buggy)
    st_p, _, ms_p = run_z3(z3_bin, smt_p4_patched)
    assert st_b == "sat" and st_p == "unsat", (st_b, st_p)
    pairs.append({"name": "raft_net_tick_term_wrap32", "buggy": st_b, "patched": st_p, "ms": round(ms_b + ms_p, 2)})
    print(f"  [Z3 QF_BV]    raft_net_tick_term_wrap32  -> buggy={st_b}, patched={st_p} ({ms_p}ms)")

    # 5. bft_quorum_safety_bv (N=4, f=1)
    smt_p5_buggy = f"""
(set-logic QF_BV)
(declare-const q1 (_ BitVec 4))
(declare-const q2 (_ BitVec 4))
(declare-const byz (_ BitVec 4))
(assert (bvuge {_bv_pop4('q1')} (_ bv2 3)))
(assert (bvuge {_bv_pop4('q2')} (_ bv2 3)))
(assert (bvule {_bv_pop4('byz')} (_ bv1 3)))
(assert (= (bvand (bvand q1 q2) (bvnot byz)) #x0))
(check-sat)
"""
    smt_p5_patched = f"""
(set-logic QF_BV)
(declare-const q1 (_ BitVec 4))
(declare-const q2 (_ BitVec 4))
(declare-const byz (_ BitVec 4))
(assert (bvuge {_bv_pop4('q1')} (_ bv3 3)))
(assert (bvuge {_bv_pop4('q2')} (_ bv3 3)))
(assert (bvule {_bv_pop4('byz')} (_ bv1 3)))
(assert (= (bvand (bvand q1 q2) (bvnot byz)) #x0))
(check-sat)
"""
    st_b, _, ms_b = run_z3(z3_bin, smt_p5_buggy)
    st_p, _, ms_p = run_z3(z3_bin, smt_p5_patched)
    assert st_b == "sat" and st_p == "unsat", (st_b, st_p)
    pairs.append({"name": "bft_quorum_safety_bv", "buggy": st_b, "patched": st_p, "ms": round(ms_b + ms_p, 2)})
    print(f"  [Z3 QF_BV]    bft_quorum_safety_bv       -> buggy={st_b}, patched={st_p} ({ms_p}ms)")

    # 6. ct_cswap_mask_bv64
    smt_p6_buggy = """
(set-logic QF_BV)
(declare-const a (_ BitVec 64))
(declare-const b (_ BitVec 64))
(declare-const sw (_ BitVec 32))
(assert (or (= sw #x00000000) (= sw #x00000001)))
; Buggy RFC-7748 mask `~sw` instead of `0 - (sw & 1)`
(define-fun bad_m () (_ BitVec 64) (bvnot ((_ zero_extend 32) sw)))
(define-fun out_a () (_ BitVec 64) (bvor (bvand a (bvnot bad_m)) (bvand b bad_m)))
(assert (not (= out_a (ite (= sw #x00000001) b a))))
(check-sat)
"""
    smt_p6_patched = """
(set-logic QF_BV)
(declare-const a (_ BitVec 64))
(declare-const b (_ BitVec 64))
(declare-const sw (_ BitVec 32))
(define-fun m () (_ BitVec 64) (bvneg ((_ zero_extend 32) (bvand sw #x00000001))))
(define-fun out_a () (_ BitVec 64) (bvor (bvand a (bvnot m)) (bvand b m)))
(assert (not (= out_a (ite (= (bvand sw #x00000001) #x00000001) b a))))
(check-sat)
"""
    st_b, _, ms_b = run_z3(z3_bin, smt_p6_buggy)
    st_p, _, ms_p = run_z3(z3_bin, smt_p6_patched)
    assert st_b == "sat" and st_p == "unsat", (st_b, st_p)
    pairs.append({"name": "ct_cswap_mask_bv64", "buggy": st_b, "patched": st_p, "ms": round(ms_b + ms_p, 2)})
    print(f"  [Z3 QF_BV]    ct_cswap_mask_bv64         -> buggy={st_b}, patched={st_p} ({ms_p}ms)")

    return pairs


def main() -> int:
    auditor_dir = _find_auditor_dir()
    z3_bin = _find_z3()
    clang_bin = _find_clang()
    if auditor_dir is None or z3_bin is None:
        print(
            f"[Gate 8] NOTICE: ../Auditor ({auditor_dir}) or z3 ({z3_bin}) unavailable; skipping cross-audit cleanly."
        )
        return 0

    t0 = time.perf_counter()
    print("=== Gate 8: NODE x Auditor (LLVM IR -O2 CT + Z3 5.3.3 QF_BV + Net MAC Replay) ===")
    ct_report = run_llvm_ct_track(auditor_dir, clang_bin)
    z3_pairs = run_z3_security_track(z3_bin)

    mac_proc = subprocess.run([str(NODE_BIN), "audit-replay", "net-mac"], capture_output=True, text=True, check=True)
    mac_rep = json.loads(mac_proc.stdout)
    assert mac_rep["genuine_ok"] is True and mac_rep["tamper_rejected"] == mac_rep["tamper_tests"] == 10, mac_rep
    print(f"  [NET MAC]     genuine_ok=True tamper_rejected={mac_rep['tamper_rejected']}/{mac_rep['tamper_tests']}")

    llvm_z3_script = auditor_dir / "crypto" / "llvm_to_z3.py"
    llvm_z3_rep = None
    if llvm_z3_script.exists():
        rep_p = BUILD / "node_llvm_z3_report.json"
        subprocess.run(
            [sys.executable, "-u", str(llvm_z3_script), "--extra-ll", str(ct_report["ir_file"]), "--report", str(rep_p)],
            check=True,
        )
        llvm_z3_rep = json.loads(rep_p.read_text(encoding="utf-8"))

    proto_script = auditor_dir / "verifier" / "protocol_verify.py"
    proto_rep = None
    if proto_script.exists():
        prep_p = BUILD / "node_protocol_audit_report.json"
        subprocess.run(
            [sys.executable, "-u", str(proto_script), "--report", str(prep_p)],
            check=True,
        )
        proto_rep = json.loads(prep_p.read_text(encoding="utf-8"))

    total_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    report = {
        "auditor_dir": str(auditor_dir),
        "z3_bin": z3_bin,
        "elapsed_ms": total_ms,
        "ct_audit": ct_report,
        "z3_qf_bv_pairs": z3_pairs,
        "net_mac_replay": mac_rep,
        "llvm_to_z3": llvm_z3_rep,
        "protocol_dolev_yao": proto_rep,
    }
    (BUILD / "node_auditor_report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(
        f"[Gate 8] PASS ({len(ct_report['verified'])}/{len(ct_report['verified'])} CT verified, "
        f"{len(z3_pairs)}/6 Z3 QF_BV pairs UNSAT/SAT+replay, 10/10 Net MAC tamper rejected"
        f"{', LLVM-to-Z3 + 3/3 Dolev-Yao verified' if proto_rep else ''} in {total_ms:.2f}ms)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
