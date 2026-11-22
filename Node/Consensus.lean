/-
  Node.Consensus — Layer 3: CALM Semilattices, BFT 3f+1 Safety, Raft Majority & Two-Generals No-Go
  ==================================================================================================
  Pure Lean 4 kernel proofs (zero Mathlib, zero incomplete proofs, zero TrustCompiler).
-/

namespace Node.Consensus

/-! ## Join-Semilattice CRDTs & CALM Theorem Core -/

structure JoinSemilattice (α : Type) where
  join : α → α → α
  assoc : ∀ a b c, join (join a b) c = join a (join b c)
  comm : ∀ a b, join a b = join b a
  idem : ∀ a, join a a = a

def semilatticeLe {α : Type} (L : JoinSemilattice α) (a b : α) : Prop :=
  L.join a b = b

theorem semilattice_le_refl {α : Type} (L : JoinSemilattice α) (a : α) :
    semilatticeLe L a a :=
  L.idem a

theorem semilattice_le_antisymm {α : Type} (L : JoinSemilattice α) {a b : α}
    (hab : semilatticeLe L a b) (hba : semilatticeLe L b a) : a = b := by
  unfold semilatticeLe at hab hba
  rw [L.comm] at hba
  exact hba.symm.trans hab

theorem semilattice_le_trans {α : Type} (L : JoinSemilattice α) {a b c : α}
    (hab : semilatticeLe L a b) (hbc : semilatticeLe L b c) : semilatticeLe L a c := by
  unfold semilatticeLe at hab hbc ⊢
  calc
    L.join a c = L.join a (L.join b c) := by rw [hbc]
    _ = L.join (L.join a b) c := by rw [L.assoc]
    _ = L.join b c := by rw [hab]
    _ = c := hbc

theorem semilattice_fold_dup {α : Type} (L : JoinSemilattice α) (acc x : α) :
    L.join (L.join acc x) x = L.join acc x := by
  rw [L.assoc, L.idem]

theorem semilattice_fold_swap {α : Type} (L : JoinSemilattice α) (acc x y : α) :
    L.join (L.join acc x) y = L.join (L.join acc y) x := by
  rw [L.assoc, L.comm x y, ← L.assoc]

theorem calm_monotone_persistence {α : Type} (L : JoinSemilattice α) (P : α → Prop)
    (hMono : ∀ a b, semilatticeLe L a b → P a → P b)
    (localState remoteState : α) (hHold : P localState) :
    P (L.join localState remoteState) := by
  apply hMono localState (L.join localState remoteState) _ hHold
  unfold semilatticeLe
  rw [← L.assoc, L.idem]

/-! ## Concrete Verified CRDT Instances: G-Counter, PN-Counter, LWW-Register -/

def natMax (a b : Nat) : Nat :=
  if a ≤ b then b else a

theorem natMax_assoc (a b c : Nat) : natMax (natMax a b) c = natMax a (natMax b c) := by
  unfold natMax
  by_cases h1 : a ≤ b <;> by_cases h2 : b ≤ c <;> by_cases h3 : a ≤ c <;>
  simp [h1, h2, h3] <;> omega

theorem natMax_comm (a b : Nat) : natMax a b = natMax b a := by
  unfold natMax
  by_cases h1 : a ≤ b <;> by_cases h2 : b ≤ a <;> simp [h1, h2] <;> omega

theorem natMax_idem (a : Nat) : natMax a a = a := by
  unfold natMax
  simp

def GCounter (n : Nat) : Type := Fin n → Nat

def gcounterJoin {n : Nat} (a b : GCounter n) : GCounter n :=
  fun i => natMax (a i) (b i)

theorem gcounter_assoc {n : Nat} (a b c : GCounter n) :
    gcounterJoin (gcounterJoin a b) c = gcounterJoin a (gcounterJoin b c) := by
  funext i
  exact natMax_assoc (a i) (b i) (c i)

theorem gcounter_comm {n : Nat} (a b : GCounter n) :
    gcounterJoin a b = gcounterJoin b a := by
  funext i
  exact natMax_comm (a i) (b i)

theorem gcounter_idem {n : Nat} (a : GCounter n) :
    gcounterJoin a a = a := by
  funext i
  exact natMax_idem (a i)

def gcounterSemilattice (n : Nat) : JoinSemilattice (GCounter n) where
  join := gcounterJoin
  assoc := gcounter_assoc
  comm := gcounter_comm
  idem := gcounter_idem

structure PNCounter (n : Nat) where
  pos : GCounter n
  neg : GCounter n

def pncounterJoin {n : Nat} (a b : PNCounter n) : PNCounter n :=
  { pos := gcounterJoin a.pos b.pos, neg := gcounterJoin a.neg b.neg }

theorem pncounter_assoc {n : Nat} (a b c : PNCounter n) :
    pncounterJoin (pncounterJoin a b) c = pncounterJoin a (pncounterJoin b c) := by
  unfold pncounterJoin
  simp [gcounter_assoc]

theorem pncounter_comm {n : Nat} (a b : PNCounter n) :
    pncounterJoin a b = pncounterJoin b a := by
  unfold pncounterJoin
  simp [gcounter_comm]

theorem pncounter_idem {n : Nat} (a : PNCounter n) :
    pncounterJoin a a = a := by
  cases a with | mk p neg =>
  unfold pncounterJoin
  simp [gcounter_idem]

structure LwwReg where
  ts : Nat
  nodeId : Nat
  val : Nat
  deriving DecidableEq, Repr

def lwwLtProp (a b : LwwReg) : Prop :=
  a.ts < b.ts ∨ (a.ts = b.ts ∧ (a.nodeId < b.nodeId ∨ (a.nodeId = b.nodeId ∧ a.val < b.val)))

def lwwLt (a b : LwwReg) : Bool :=
  decide (a.ts < b.ts) ||
    (decide (a.ts = b.ts) && (decide (a.nodeId < b.nodeId) ||
      (decide (a.nodeId = b.nodeId) && decide (a.val < b.val))))

private theorem lwwLt_eq_decide (a b : LwwReg) :
    lwwLt a b = true ↔ lwwLtProp a b := by
  unfold lwwLt lwwLtProp
  by_cases h1 : a.ts < b.ts <;> by_cases h2 : a.ts = b.ts <;>
  by_cases h3 : a.nodeId < b.nodeId <;> by_cases h4 : a.nodeId = b.nodeId <;>
  by_cases h5 : a.val < b.val <;>
  simp [h1, h2, h3, h4, h5]

private theorem lwwLtProp_irrefl (a b : LwwReg) (h1 : lwwLtProp a b) (h2 : lwwLtProp b a) :
    False := by
  unfold lwwLtProp at h1 h2
  omega

private theorem lwwLtProp_eq_of_not (a b : LwwReg) (h1 : ¬lwwLtProp a b) (h2 : ¬lwwLtProp b a) :
    a = b := by
  cases a with | mk ta na va =>
  cases b with | mk tb nb vb =>
  dsimp [lwwLtProp] at h1 h2
  have hts : ta = tb := by omega
  have hna : na = nb := by omega
  have hva : va = vb := by omega
  subst hts hna hva
  rfl

private theorem lwwLtProp_trans {a b c : LwwReg}
    (hab : lwwLtProp a b) (hbc : lwwLtProp b c) : lwwLtProp a c := by
  unfold lwwLtProp at hab hbc ⊢
  omega

private theorem lwwLtProp_le_trans {a b c : LwwReg}
    (hba : ¬lwwLtProp a b) (hcb : ¬lwwLtProp b c) : ¬lwwLtProp a c := by
  unfold lwwLtProp at hba hcb ⊢
  omega

def lwwJoin (a b : LwwReg) : LwwReg :=
  if lwwLt a b then b else a

theorem lww_comm (a b : LwwReg) : lwwJoin a b = lwwJoin b a := by
  unfold lwwJoin
  by_cases h1 : lwwLt a b = true <;> by_cases h2 : lwwLt b a = true
  · exfalso
    exact lwwLtProp_irrefl a b ((lwwLt_eq_decide a b).mp h1) ((lwwLt_eq_decide b a).mp h2)
  · simp [h1, h2]
  · simp [h1, h2]
  · have hEq : a = b :=
      lwwLtProp_eq_of_not a b
        (fun h => h1 ((lwwLt_eq_decide a b).mpr h))
        (fun h => h2 ((lwwLt_eq_decide b a).mpr h))
    subst hEq
    simp [h1]

theorem lww_idem (a : LwwReg) : lwwJoin a a = a := by
  unfold lwwJoin
  by_cases h : lwwLt a a = true
  · exfalso
    have hp := (lwwLt_eq_decide a a).mp h
    exact lwwLtProp_irrefl a a hp hp
  · simp [h]

theorem lww_assoc (a b c : LwwReg) :
    lwwJoin (lwwJoin a b) c = lwwJoin a (lwwJoin b c) := by
  unfold lwwJoin
  by_cases hab : lwwLt a b = true <;>
  by_cases hbc : lwwLt b c = true <;>
  by_cases hac : lwwLt a c = true
  · simp [hab, hbc, hac]
  · exfalso
    have hp := lwwLtProp_trans ((lwwLt_eq_decide a b).mp hab) ((lwwLt_eq_decide b c).mp hbc)
    exact hac ((lwwLt_eq_decide a c).mpr hp)
  · simp [hab, hbc]
  · simp [hab, hbc]
  · simp [hab, hbc, hac]
  · simp [hab, hbc, hac]
  · exfalso
    have hn1 : ¬lwwLtProp a b := fun h => hab ((lwwLt_eq_decide a b).mpr h)
    have hn2 : ¬lwwLtProp b c := fun h => hbc ((lwwLt_eq_decide b c).mpr h)
    exact lwwLtProp_le_trans hn1 hn2 ((lwwLt_eq_decide a c).mp hac)
  · simp [hbc, hab, hac]

/-! ## Finite Quorum Counting, BFT 3f+1 Safety & Raft Majority Safety -/

def countPred : (n : Nat) → (Nat → Bool) → Nat
  | 0, _ => 0
  | n + 1, p => countPred n p + if p n then 1 else 0

theorem countPred_le : ∀ (n : Nat) (p : Nat → Bool), countPred n p ≤ n
  | 0, _ => by simp [countPred]
  | n + 1, p => by
      have ih := countPred_le n p
      dsimp [countPred]
      by_cases hp : p n = true <;> simp [hp] <;> omega

theorem quorum_intersection_count : ∀ (n : Nat) (q1 q2 : Nat → Bool),
    countPred n q1 + countPred n q2 ≤ n + countPred n (fun i => q1 i && q2 i)
  | 0, _, _ => by simp [countPred]
  | n + 1, q1, q2 => by
      have ih := quorum_intersection_count n q1 q2
      dsimp [countPred]
      by_cases h1 : q1 n = true <;> by_cases h2 : q2 n = true <;> simp [h1, h2] <;> omega

theorem countPred_diff_le : ∀ (n : Nat) (a b : Nat → Bool),
    countPred n a ≤ countPred n (fun i => a i && !(b i)) + countPred n b
  | 0, _, _ => by simp [countPred]
  | n + 1, a, b => by
      have ih := countPred_diff_le n a b
      dsimp [countPred]
      by_cases ha : a n = true <;> by_cases hb : b n = true <;> simp [ha, hb] <;> omega

theorem countPred_pos_exists : ∀ (n : Nat) (p : Nat → Bool),
    0 < countPred n p → ∃ i, i < n ∧ p i = true
  | 0, _, h => by simp [countPred] at h
  | n + 1, p, h => by
      dsimp [countPred] at h
      cases hp : p n
      · simp [hp] at h
        obtain ⟨i, hiLt, hiP⟩ := countPred_pos_exists n p h
        exact ⟨i, by omega, hiP⟩
      · exact ⟨n, Nat.lt_succ_self n, hp⟩

theorem bft_quorum_intersection (n f : Nat) (q1 q2 : Nat → Bool)
    (hn : n ≤ 3 * f + 1)
    (hq1 : 2 * f + 1 ≤ countPred n q1)
    (hq2 : 2 * f + 1 ≤ countPred n q2) :
    f + 1 ≤ countPred n (fun i => q1 i && q2 i) := by
  have hInt := quorum_intersection_count n q1 q2
  omega

theorem bft_honest_witness (n f : Nat) (q1 q2 byz : Nat → Bool)
    (hn : n ≤ 3 * f + 1)
    (hq1 : 2 * f + 1 ≤ countPred n q1)
    (hq2 : 2 * f + 1 ≤ countPred n q2)
    (hbyz : countPred n byz ≤ f) :
    ∃ i, i < n ∧ q1 i = true ∧ q2 i = true ∧ byz i = false := by
  have hInt := bft_quorum_intersection n f q1 q2 hn hq1 hq2
  have hDiff := countPred_diff_le n (fun i => q1 i && q2 i) byz
  have hPos : 0 < countPred n (fun i => (q1 i && q2 i) && !(byz i)) := by omega
  obtain ⟨i, hiLt, hiTrue⟩ := countPred_pos_exists n (fun i => (q1 i && q2 i) && !(byz i)) hPos
  have hAnd : q1 i = true ∧ q2 i = true ∧ byz i = false := by
    cases h1 : q1 i <;> cases h2 : q2 i <;> cases hb : byz i <;> simp [h1, h2, hb] at hiTrue
    exact ⟨rfl, rfl, rfl⟩
  exact ⟨i, hiLt, hAnd⟩

theorem bft_no_conflicting_commits (n f v1 v2 : Nat) (vote1 vote2 byz : Nat → Bool)
    (hn : n ≤ 3 * f + 1)
    (hv1 : 2 * f + 1 ≤ countPred n vote1)
    (hv2 : 2 * f + 1 ≤ countPred n vote2)
    (hbyz : countPred n byz ≤ f)
    (hHonestSingleVote : ∀ i, i < n → byz i = false → vote1 i = true → vote2 i = true → v1 = v2) :
    v1 = v2 := by
  obtain ⟨i, hiLt, h1, h2, hnb⟩ := bft_honest_witness n f vote1 vote2 byz hn hv1 hv2 hbyz
  exact hHonestSingleVote i hiLt hnb h1 h2

theorem raft_majority_intersection (n : Nat) (q1 q2 : Nat → Bool)
    (hq1 : n < 2 * countPred n q1)
    (hq2 : n < 2 * countPred n q2) :
    ∃ i, i < n ∧ q1 i = true ∧ q2 i = true := by
  have hInt := quorum_intersection_count n q1 q2
  have hPos : 0 < countPred n (fun i => q1 i && q2 i) := by omega
  obtain ⟨i, hiLt, hiTrue⟩ := countPred_pos_exists n (fun i => q1 i && q2 i) hPos
  have hBoth : q1 i = true ∧ q2 i = true := by
    cases h1 : q1 i <;> cases h2 : q2 i <;> simp [h1, h2] at hiTrue
    exact ⟨rfl, rfl⟩
  exact ⟨i, hiLt, hBoth⟩

theorem raft_election_safety (n c1 c2 : Nat) (v1 v2 : Nat → Bool)
    (hv1 : n < 2 * countPred n v1)
    (hv2 : n < 2 * countPred n v2)
    (hSingleVote : ∀ i, i < n → v1 i = true → v2 i = true → c1 = c2) :
    c1 = c2 := by
  obtain ⟨i, hiLt, h1, h2⟩ := raft_majority_intersection n v1 v2 hv1 hv2
  exact hSingleVote i hiLt h1 h2

/-! ## Two-Generals Coordinated-Attack Impossibility (Finite Lossy Rounds) -/

theorem two_generals_no_finite_protocol (k : Nat)
    (attackA attackB : Nat → Bool)
    (hSafetySym : ∀ m, m ≤ k → attackB m = true → attackA m = true)
    (hDropLastA : ∀ m, m < k → attackA (m + 1) = true → attackA m = true)
    (hDropLastB : ∀ m, m < k → attackB (m + 1) = true → attackB m = true)
    (hInitFalse : attackA 0 = false) :
    attackA k = false ∧ attackB k = false := by
  have hZero : attackA 0 = false ∧ attackB 0 = false := by
    refine ⟨hInitFalse, ?_⟩
    cases hb0 : attackB 0
    · rfl
    · have ha0 := hSafetySym 0 (Nat.zero_le k) hb0
      simp [hInitFalse] at ha0
  have hAll : ∀ m, m ≤ k → attackA m = false ∧ attackB m = false := by
    intro m hm
    induction m with
    | zero => exact hZero
    | succ m ih =>
        have ihM := ih (Nat.le_of_succ_le hm)
        have hmLt : m < k := hm
        have ha : attackA (m + 1) = false := by
          cases haS : attackA (m + 1)
          · rfl
          · have hPrev := hDropLastA m hmLt haS
            simp [ihM.1] at hPrev
        have hb : attackB (m + 1) = false := by
          cases hbS : attackB (m + 1)
          · rfl
          · have hPrev := hDropLastB m hmLt hbS
            simp [ihM.2] at hPrev
        exact ⟨ha, hb⟩
  exact hAll k (Nat.le_refl k)

/-! ## Anti-Replay 64-Slot Sliding Window Verification -/

structure ReplayWin where
  maxSeq : Nat
  seen : Nat → Bool
  initialized : Bool

def replayAccept (w : ReplayWin) (seq : Nat) : Bool :=
  if !w.initialized then true
  else if w.maxSeq < seq then true
  else if w.maxSeq - seq < 64 then !(w.seen seq)
  else false

def replayUpdate (w : ReplayWin) (seq : Nat) : ReplayWin :=
  if !w.initialized then
    { maxSeq := seq, seen := fun s => s == seq, initialized := true }
  else if w.maxSeq < seq then
    { maxSeq := seq
    , seen := fun s => (s == seq) || (w.seen s)
    , initialized := true }
  else
    { w with seen := fun s => (s == seq) || (w.seen s) }

theorem replay_window_rejects_old (w : ReplayWin) (seq : Nat)
    (hInit : w.initialized = true) (hOld : seq + 64 ≤ w.maxSeq) :
    replayAccept w seq = false := by
  unfold replayAccept
  simp [hInit]
  omega

theorem replay_window_accepts_advance (w : ReplayWin) (seq : Nat)
    (hInit : w.initialized = true) (hAdv : w.maxSeq < seq) :
    replayAccept w seq = true := by
  unfold replayAccept
  simp [hInit, hAdv]

theorem replay_window_marks_seen (w : ReplayWin) (seq : Nat) :
    (replayUpdate w seq).seen seq = true := by
  unfold replayUpdate
  split
  · simp
  · split <;> simp

theorem replay_window_no_duplicate (w : ReplayWin) (seq : Nat)
    (hInit : w.initialized = true) (hLe : seq ≤ w.maxSeq) (hSeen : w.seen seq = true) :
    replayAccept w seq = false := by
  unfold replayAccept
  simp [hInit, hLe, hSeen]

end Node.Consensus
