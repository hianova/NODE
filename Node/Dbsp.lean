/-
  Node.Dbsp — Layer 2: DBSP Z-Set Algebra, WCOJ Triangle Query & Merkle Crash-Safe WAL
  ======================================================================================
  Pure Lean 4 kernel proofs (zero Mathlib, zero incomplete proofs, zero TrustCompiler).
-/

namespace Node.Dbsp

def ZSet (α : Type) : Type := α → Int

def Stream (α : Type) : Type := Nat → α

def zZero {α : Type} : ZSet α := fun _ => 0

def zAdd {α : Type} (a b : ZSet α) : ZSet α := fun k => a k + b k

def zNeg {α : Type} (a : ZSet α) : ZSet α := fun k => - (a k)

def zSub {α : Type} (a b : ZSet α) : ZSet α := fun k => a k - b k

def zJoin {α : Type} (a b : ZSet α) : ZSet α := fun k => a k * b k

def delay {α : Type} (z0 : α) (s : Stream α) : Stream α
  | 0 => z0
  | t + 1 => s t

def diff {α : Type} (s : Stream (ZSet α)) : Stream (ZSet α)
  | 0 => s 0
  | t + 1 => zSub (s (t + 1)) (s t)

def integ {α : Type} (s : Stream (ZSet α)) : Stream (ZSet α)
  | 0 => s 0
  | t + 1 => zAdd (integ s t) (s (t + 1))

theorem zAdd_comm {α : Type} (a b : ZSet α) (k : α) :
    zAdd a b k = zAdd b a k := by
  dsimp [zAdd]
  omega

theorem zAdd_assoc {α : Type} (a b c : ZSet α) (k : α) :
    zAdd (zAdd a b) c k = zAdd a (zAdd b c) k := by
  dsimp [zAdd]
  omega

theorem zAdd_zero {α : Type} (a : ZSet α) (k : α) :
    zAdd a zZero k = a k := by
  dsimp [zAdd, zZero]
  omega

theorem zAdd_neg {α : Type} (a : ZSet α) (k : α) :
    zAdd a (zNeg a) k = zZero k := by
  dsimp [zAdd, zNeg, zZero]
  omega

theorem dbsp_integ_diff {α : Type} (s : Stream (ZSet α)) :
    ∀ t k, integ (diff s) t k = s t k
  | 0, _ => rfl
  | t + 1, k => by
      dsimp [integ, diff, zAdd, zSub]
      have ih := dbsp_integ_diff s t k
      rw [ih]
      omega

theorem dbsp_diff_integ {α : Type} (s : Stream (ZSet α)) :
    ∀ t k, diff (integ s) t k = s t k
  | 0, _ => rfl
  | t + 1, k => by
      dsimp [diff, integ, zSub, zAdd]
      omega

theorem dbsp_linear_incremental {α β : Type} (L : ZSet α → ZSet β)
    (hLin : ∀ a b k, L (zSub a b) k = zSub (L a) (L b) k)
    (s : Stream (ZSet α)) :
    ∀ t k, diff (fun n => L (s n)) t k = L (diff s t) k
  | 0, _ => rfl
  | t + 1, k => by
      dsimp [diff]
      exact (hLin (s (t + 1)) (s t) k).symm

private theorem int_bilinear_delta (a0 a1 b0 b1 : Int) :
    a1 * b1 - a0 * b0 = (a1 - a0) * b0 + a0 * (b1 - b0) + (a1 - a0) * (b1 - b0) := by
  have h1 : (a1 - a0) * (b1 - b0) = (a1 - a0) * b1 - (a1 - a0) * b0 := by
    exact Int.mul_sub (a1 - a0) b1 b0
  have h2 : (a1 - a0) * b1 = a1 * b1 - a0 * b1 := by
    exact Int.sub_mul a1 a0 b1
  have h3 : a0 * (b1 - b0) = a0 * b1 - a0 * b0 := by
    exact Int.mul_sub a0 b1 b0
  omega

theorem dbsp_bilinear_join_delta {α : Type} (a b : Stream (ZSet α)) :
    ∀ t k,
      diff (fun n => zJoin (a n) (b n)) (t + 1) k =
        zJoin (diff a (t + 1)) (delay zZero b (t + 1)) k +
        zJoin (delay zZero a (t + 1)) (diff b (t + 1)) k +
        zJoin (diff a (t + 1)) (diff b (t + 1)) k := by
  intro t k
  dsimp [diff, delay, zJoin, zSub]
  exact int_bilinear_delta (a t k) (a (t + 1) k) (b t k) (b (t + 1) k)

theorem dbsp_bilinear_join_delta_all {α : Type} (a b : Stream (ZSet α)) :
    ∀ t k,
      diff (fun n => zJoin (a n) (b n)) t k =
        zJoin (diff a t) (delay zZero b t) k +
        zJoin (delay zZero a t) (diff b t) k +
        zJoin (diff a t) (diff b t) k
  | 0, k => by
      dsimp [diff, delay, zJoin, zZero]
      rw [Int.mul_zero, Int.zero_mul]
      omega
  | t + 1, k => dbsp_bilinear_join_delta a b t k

def dbspBilinearJoinStep {α : Type} (a b : Stream (ZSet α)) : Stream (ZSet α) :=
  fun t k =>
    zJoin (diff a t) (delay zZero b t) k +
    zJoin (delay zZero a t) (diff b t) k +
    zJoin (diff a t) (diff b t) k

theorem dbsp_incremental_join_matches_full {α : Type} (a b : Stream (ZSet α)) :
    ∀ t k, integ (dbspBilinearJoinStep a b) t k = zJoin (a t) (b t) k := by
  intro t k
  have hStepEq : ∀ n, dbspBilinearJoinStep a b n k = diff (fun m => zJoin (a m) (b m)) n k := by
    intro n
    exact (dbsp_bilinear_join_delta_all a b n k).symm
  have hInteg : integ (dbspBilinearJoinStep a b) t k =
      integ (diff (fun m => zJoin (a m) (b m))) t k := by
    induction t with
    | zero => exact hStepEq 0
    | succ t ih =>
        dsimp [integ, zAdd]
        rw [ih, hStepEq (t + 1)]
  rw [hInteg]
  exact dbsp_integ_diff (fun m => zJoin (a m) (b m)) t k

/-! ## WCOJ Triangle Intersection & Degree-Split Bound -/

def wcojIntersect (nx ny : List Nat) : List Nat :=
  nx.filter (fun z => ny.elem z)

theorem wcoj_triangle_sound_complete (nx ny : List Nat) (z : Nat) :
    z ∈ wcojIntersect nx ny ↔ z ∈ nx ∧ z ∈ ny := by
  unfold wcojIntersect
  simp [List.mem_filter]

theorem wcoj_intersection_len_le_min (nx ny : List Nat) :
    (wcojIntersect nx ny).length ≤ nx.length := by
  unfold wcojIntersect
  exact List.length_filter_le _ _

theorem wcoj_degree_split_bound (T lightTris heavyTris heavyCnt m d : Nat)
    (hd : 0 < d)
    (hSplit : T ≤ lightTris + heavyTris)
    (hLight : lightTris ≤ m * d)
    (hHeavy : heavyTris ≤ heavyCnt * m)
    (hHeavyCnt : heavyCnt * d ≤ m) :
    T * d ≤ m * d * d + m * m := by
  have hTd : T * d ≤ (lightTris + heavyTris) * d := Nat.mul_le_mul_right d hSplit
  have hDist : (lightTris + heavyTris) * d = lightTris * d + heavyTris * d :=
    Nat.add_mul lightTris heavyTris d
  have hL : lightTris * d ≤ m * d * d := Nat.mul_le_mul_right d hLight
  have hH1 : heavyTris * d ≤ (heavyCnt * m) * d := Nat.mul_le_mul_right d hHeavy
  have hAssoc : (heavyCnt * m) * d = (heavyCnt * d) * m := by
    rw [Nat.mul_assoc, Nat.mul_comm m d, Nat.mul_assoc]
  have hH2 : (heavyCnt * d) * m ≤ m * m := Nat.mul_le_mul_right m hHeavyCnt
  have _ := hd
  omega

/-! ## Merkle Crash-Safe Write-Ahead Log -/

structure WalRec where
  txId : Nat
  key : Nat
  val : Nat
  isCommit : Bool
  crcOk : Bool
  deriving DecidableEq, Repr

def validPrefix : List WalRec → List WalRec
  | [] => []
  | r :: rs => if r.crcOk then r :: validPrefix rs else []

def commitList : List WalRec → List Nat
  | [] => []
  | r :: rs => if r.crcOk && r.isCommit then r.txId :: commitList rs else commitList rs

def committedOfPrefix (rs : List WalRec) : List Nat :=
  commitList (validPrefix rs)

def applyWalWrites (writes : List (Nat × Nat)) (mem : Nat → Nat) : Nat → Nat :=
  writes.foldl (fun m (kv : Nat × Nat) => fun k => if k = kv.1 then kv.2 else m k) mem

theorem validPrefix_stops_at_corrupt : ∀ (a b : List WalRec) (r : WalRec),
    r.crcOk = false → (∀ x ∈ a, x.crcOk = true) → validPrefix (a ++ r :: b) = a
  | [], b, r, hBad, _ => by
      dsimp [validPrefix]
      simp [hBad]
  | x :: xs, b, r, hBad, hGood => by
      have hx : x.crcOk = true := hGood x (List.Mem.head _)
      have hxs : ∀ y ∈ xs, y.crcOk = true := fun y hy => hGood y (List.Mem.tail _ hy)
      have ih := validPrefix_stops_at_corrupt xs b r hBad hxs
      rw [List.cons_append]
      dsimp [validPrefix]
      simp [hx, ih]

theorem wal_torn_tail_ignored (prefixGood : List WalRec) (r : WalRec) (tail : List WalRec)
    (hBad : r.crcOk = false) (hGood : ∀ x ∈ prefixGood, x.crcOk = true) :
    committedOfPrefix (prefixGood ++ r :: tail) = commitList prefixGood := by
  unfold committedOfPrefix
  rw [validPrefix_stops_at_corrupt prefixGood tail r hBad hGood]

theorem wal_uncommitted_tail_ignored (prefixGood : List WalRec) (uncommitted : List WalRec)
    (hGood : ∀ x ∈ prefixGood, x.crcOk = true)
    (hNoCommit : ∀ x ∈ uncommitted, x.isCommit = false) :
    commitList (prefixGood ++ uncommitted) = commitList prefixGood := by
  induction prefixGood with
  | nil =>
      simp
      induction uncommitted with
      | nil => rfl
      | cons u us ihu =>
          have hu : u.isCommit = false := hNoCommit u (List.Mem.head _)
          have hus : ∀ y ∈ us, y.isCommit = false := fun y hy => hNoCommit y (List.Mem.tail _ hy)
          dsimp [commitList]
          simp [hu]
          exact ihu hus
  | cons x xs ih =>
      have hx : x.crcOk = true := hGood x (List.Mem.head _)
      have hxs : ∀ y ∈ xs, y.crcOk = true := fun y hy => hGood y (List.Mem.tail _ hy)
      dsimp [commitList]
      cases hc : x.isCommit
      · simp [hx]
        exact ih hxs
      · simp [hx]
        exact ih hxs

theorem wal_recovery_idempotent (rs : List WalRec) :
    validPrefix (validPrefix rs) = validPrefix rs := by
  induction rs with
  | nil => rfl
  | cons r rs ih =>
      dsimp [validPrefix]
      cases hc : r.crcOk
      · rfl
      · dsimp [validPrefix]
        simp [hc, ih]

theorem wal_commitList_idempotent (rs : List WalRec) :
    committedOfPrefix (validPrefix rs) = committedOfPrefix rs := by
  unfold committedOfPrefix
  rw [wal_recovery_idempotent]

theorem merkle_pair_tamper_detection (hPair : Nat → Nat → Nat)
    (hInj : ∀ a1 b1 a2 b2, hPair a1 b1 = hPair a2 b2 → a1 = a2 ∧ b1 = b2)
    {l1 l2 r1 r2 : Nat} (hNe : l1 ≠ l2 ∨ r1 ≠ r2) :
    hPair l1 r1 ≠ hPair l2 r2 := by
  intro hEq
  have ⟨hl, hr⟩ := hInj l1 r1 l2 r2 hEq
  cases hNe with
  | inl h => exact h hl
  | inr h => exact h hr

end Node.Dbsp
