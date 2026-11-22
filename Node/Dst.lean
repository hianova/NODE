/-
  Node.Dst — Deterministic Simulation Testing (DST) Foundations & Constructive Counterexamples
  =============================================================================================
  Pure Lean 4 kernel proofs (zero Mathlib, zero incomplete proofs, zero TrustCompiler).
-/
import Node.Consensus

namespace Node.Dst

open Node.Consensus

structure DstState where
  tick : Nat
  prng : Nat
  faultsInjected : Nat
  partitions : Nat
  crashes : Nat
  safetyViolation : Bool
  deriving DecidableEq, Repr

def xorshiftStep (x : Nat) : Nat :=
  (x * 6364136223846793005 + 1442695040888963407) % 4294967296

def dstStep (faultBudget : Nat) (injectFn : Nat → Bool) (s : DstState) : DstState :=
  let nxt := xorshiftStep s.prng
  let doFault := (s.faultsInjected < faultBudget) && injectFn nxt
  { tick := s.tick + 1
    prng := nxt
    faultsInjected := s.faultsInjected + if doFault then 1 else 0
    partitions := s.partitions + if doFault && (nxt % 2 = 0) then 1 else 0
    crashes := s.crashes + if doFault && (nxt % 2 = 1) then 1 else 0
    safetyViolation := s.safetyViolation }

def dstRun (faultBudget : Nat) (injectFn : Nat → Bool) : Nat → DstState → DstState
  | 0, s => s
  | k + 1, s => dstRun faultBudget injectFn k (dstStep faultBudget injectFn s)

theorem dst_same_seed_same_trace (faultBudget : Nat) (injectFn : Nat → Bool)
    (steps : Nat) (s1 s2 : DstState) (h : s1 = s2) :
    dstRun faultBudget injectFn steps s1 = dstRun faultBudget injectFn steps s2 := by
  subst h
  rfl

theorem dstStep_tick_inc (faultBudget : Nat) (injectFn : Nat → Bool) (s : DstState) :
    (dstStep faultBudget injectFn s).tick = s.tick + 1 := by
  rfl

theorem dstStep_fault_budget_preserved (faultBudget : Nat) (injectFn : Nat → Bool) (s : DstState)
    (h : s.faultsInjected ≤ faultBudget) :
    (dstStep faultBudget injectFn s).faultsInjected ≤ faultBudget := by
  dsimp [dstStep]
  by_cases hLt : s.faultsInjected < faultBudget
  · cases injectFn (xorshiftStep s.prng) <;> simp [hLt] <;> omega
  · simp [hLt]
    exact h

theorem dstRun_fault_budget_bounded : ∀ (steps faultBudget : Nat)
    (injectFn : Nat → Bool) (s : DstState),
    s.faultsInjected ≤ faultBudget →
    (dstRun faultBudget injectFn steps s).faultsInjected ≤ faultBudget
  | 0, _, _, _, h => h
  | k + 1, fb, fn, s, h =>
      dstRun_fault_budget_bounded k fb fn (dstStep fb fn s)
        (dstStep_fault_budget_preserved fb fn s h)

theorem dst_first_violation_minimal (pred : Nat → Bool) :
    ∀ n : Nat, pred n = true →
      ∃ tStar, tStar ≤ n ∧ pred tStar = true ∧ ∀ t, t < tStar → pred t = false
  | 0, h0 => ⟨0, Nat.le_refl 0, h0, fun t ht => by omega⟩
  | n + 1, hn => by
      by_cases hExists : ∃ k, k ≤ n ∧ pred k = true
      · obtain ⟨k, hkLe, hkPred⟩ := hExists
        obtain ⟨tStar, htLe, htPred, htMin⟩ := dst_first_violation_minimal pred k hkPred
        exact ⟨tStar, Nat.le_trans htLe (Nat.le_trans hkLe (Nat.le_succ n)), htPred, htMin⟩
      · have hAllBelow : ∀ t, t < n + 1 → pred t = false := by
          intro t ht
          cases hp : pred t
          · rfl
          · exfalso
            exact hExists ⟨t, Nat.lt_succ_iff.mp ht, hp⟩
        exact ⟨n + 1, Nat.le_refl (n + 1), hn, hAllBelow⟩

theorem dst_broken_quorum_admits_split_brain :
    ∃ q1 q2 : Nat → Bool,
      countPred 4 q1 ≥ 2 ∧
      countPred 4 q2 ≥ 2 ∧
      countPred 4 (fun i => q1 i && q2 i) = 0 := by
  refine ⟨(fun i => decide (i < 2)), (fun i => decide (2 ≤ i)), ?_⟩
  decide

theorem dst_bft_broken_quorum_admits_equivocation :
    ∃ q1 q2 byz : Nat → Bool,
      countPred 4 q1 ≥ 2 ∧
      countPred 4 q2 ≥ 2 ∧
      countPred 4 byz ≤ 1 ∧
      (∀ i, i < 4 → q1 i = true → q2 i = true → byz i = true) := by
  let q1 : Nat → Bool := fun i => decide (i = 0 ∨ i = 3)
  let q2 : Nat → Bool := fun i => decide (i = 1 ∨ i = 3)
  let byz : Nat → Bool := fun i => decide (i = 3)
  refine ⟨q1, q2, byz, by decide, by decide, by decide, ?_⟩
  intro i hi h1 h2
  dsimp [q1, q2, byz] at h1 h2 ⊢
  simp at h1 h2 ⊢
  omega

theorem dst_bft_valid_quorum_nogo_witness :
    ∀ q1 q2 byz : Nat → Bool,
      countPred 4 q1 ≥ 3 →
      countPred 4 q2 ≥ 3 →
      countPred 4 byz ≤ 1 →
      ∃ i, i < 4 ∧ q1 i = true ∧ q2 i = true ∧ byz i = false := by
  intro q1 q2 byz hq1 hq2 hbyz
  exact bft_honest_witness 4 1 q1 q2 byz (by omega) hq1 hq2 hbyz

end Node.Dst
