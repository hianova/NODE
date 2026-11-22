/-
  Node.Sandbox — Layer 1: Capability Isolation, Attenuation, WCET Fuel & Deterministic Replay
  ============================================================================================
  Pure Lean 4 kernel proofs (zero Mathlib, zero incomplete proofs, zero TrustCompiler).
-/

namespace Node.Sandbox

structure Rights where
  r : Bool
  w : Bool
  x : Bool
  g : Bool
  deriving DecidableEq, Repr

def subRightsBool (a b : Rights) : Bool :=
  (!a.r || b.r) && (!a.w || b.w) && (!a.x || b.x) && (!a.g || b.g)

def subRights (a b : Rights) : Prop :=
  subRightsBool a b = true

theorem subRights_refl (a : Rights) : subRights a a := by
  cases a with | mk r w x g =>
  cases r <;> cases w <;> cases x <;> cases g <;> rfl

theorem subRights_trans {a b c : Rights} :
    subRights a b → subRights b c → subRights a c := by
  cases a with | mk ar aw ax ag =>
  cases b with | mk br bw bx bg =>
  cases c with | mk cr cw cx cg =>
  cases ar <;> cases br <;> cases cr <;>
  cases aw <;> cases bw <;> cases cw <;>
  cases ax <;> cases bx <;> cases cx <;>
  cases ag <;> cases bg <;> cases cg <;>
  simp [subRights, subRightsBool]

structure Cap where
  regionId : Nat
  base : Nat
  len : Nat
  rights : Rights
  deriving DecidableEq, Repr

def attenuateCap (c : Cap) (nb nl : Nat) (nr : Rights) : Option Cap :=
  if c.rights.g && subRightsBool nr c.rights &&
     decide (c.base ≤ nb) && decide (nb + nl ≤ c.base + c.len) then
    some { regionId := c.regionId, base := nb, len := nl, rights := nr }
  else
    none

theorem attenuate_some_grant {c c' : Cap} {nb nl : Nat} {nr : Rights}
    (h : attenuateCap c nb nl nr = some c') : c.rights.g = true := by
  unfold attenuateCap at h
  cases hg : c.rights.g <;> simp [hg] at h
  rfl

theorem attenuate_subset_rights {c c' : Cap} {nb nl : Nat} {nr : Rights}
    (h : attenuateCap c nb nl nr = some c') : subRights c'.rights c.rights := by
  unfold attenuateCap at h
  by_cases hg : c.rights.g = true
  · by_cases hs : subRightsBool nr c.rights = true
    · by_cases hb1 : c.base ≤ nb
      · by_cases hb2 : nb + nl ≤ c.base + c.len
        · simp [hg, hs, hb1, hb2] at h
          subst h
          exact hs
        · simp [hg, hs, hb1, hb2] at h
      · simp [hg, hs, hb1] at h
    · simp [hg, hs] at h
  · simp [hg] at h

theorem attenuate_subset_bounds {c c' : Cap} {nb nl : Nat} {nr : Rights}
    (h : attenuateCap c nb nl nr = some c') :
    c.base ≤ c'.base ∧ c'.base + c'.len ≤ c.base + c.len := by
  unfold attenuateCap at h
  by_cases hg : c.rights.g = true
  · by_cases hs : subRightsBool nr c.rights = true
    · by_cases hb1 : c.base ≤ nb
      · by_cases hb2 : nb + nl ≤ c.base + c.len
        · simp [hg, hs, hb1, hb2] at h
          subst h
          exact ⟨hb1, hb2⟩
        · simp [hg, hs, hb1, hb2] at h
      · simp [hg, hs, hb1] at h
    · simp [hg, hs] at h
  · simp [hg] at h

theorem attenuate_preserves_region {c c' : Cap} {nb nl : Nat} {nr : Rights}
    (h : attenuateCap c nb nl nr = some c') : c'.regionId = c.regionId := by
  unfold attenuateCap at h
  by_cases hg : c.rights.g = true
  · by_cases hs : subRightsBool nr c.rights = true
    · by_cases hb1 : c.base ≤ nb
      · by_cases hb2 : nb + nl ≤ c.base + c.len
        · simp [hg, hs, hb1, hb2] at h
          subst h
          rfl
        · simp [hg, hs, hb1, hb2] at h
      · simp [hg, hs, hb1] at h
    · simp [hg, hs] at h
  · simp [hg] at h

theorem attenuate_trans {c1 c2 c3 : Cap} {b2 l2 b3 l3 : Nat} {r2 r3 : Rights}
    (h12 : attenuateCap c1 b2 l2 r2 = some c2)
    (h23 : attenuateCap c2 b3 l3 r3 = some c3) :
    c3.regionId = c1.regionId ∧
    subRights c3.rights c1.rights ∧
    c1.base ≤ c3.base ∧
    c3.base + c3.len ≤ c1.base + c1.len := by
  have hr12 := attenuate_preserves_region h12
  have hr23 := attenuate_preserves_region h23
  have hs12 := attenuate_subset_rights h12
  have hs23 := attenuate_subset_rights h23
  have hb12 := attenuate_subset_bounds h12
  have hb23 := attenuate_subset_bounds h23
  refine ⟨hr23.trans hr12, subRights_trans hs23 hs12, ?_, ?_⟩
  · omega
  · omega

inductive VmInsn where
  | halt
  | movi (dst imm : Nat)
  | add (dst s1 s2 : Nat)
  | storeCap (capIdx off src : Nat)
  deriving DecidableEq, Repr

structure VmState where
  pc : Nat
  fuel : Nat
  halted : Bool
  fault : Nat
  regs : Fin 8 → Nat
  mem : Nat → Nat → Nat
  caps : List Cap
  log : List Nat

def noWriteCapForRegion (caps : List Cap) (targetRegion : Nat) : Prop :=
  ∀ c ∈ caps, c.regionId ≠ targetRegion ∨ c.rights.w = false

private theorem list_getElem_mem : ∀ (xs : List Cap) (i : Nat) (c : Cap),
    xs[i]? = some c → c ∈ xs
  | [], _, _, h => by simp at h
  | _ :: _, 0, c, h => by
      simp at h
      subst h
      exact List.Mem.head _
  | _ :: xs, i + 1, c, h => by
      simp at h
      exact List.Mem.tail _ (list_getElem_mem xs i c h)

def vmExecInsn (s1 : VmState) (insn : VmInsn) : VmState :=
  match insn with
  | .halt => { s1 with halted := true }
  | .movi dst imm =>
      { s1 with
        pc := s1.pc + 1
        regs := fun r => if r.val = dst then imm else s1.regs r }
  | .add dst a b =>
      let av := if ha : a < 8 then s1.regs ⟨a, ha⟩ else 0
      let bv := if hb : b < 8 then s1.regs ⟨b, hb⟩ else 0
      { s1 with
        pc := s1.pc + 1
        regs := fun r => if r.val = dst then av + bv else s1.regs r }
  | .storeCap capIdx off src =>
      match s1.caps[capIdx]? with
      | none => { s1 with halted := true, fault := 2 }
      | some c =>
          if c.rights.w && decide (c.base ≤ off) && decide (off < c.base + c.len) then
            let sv := if hs : src < 8 then s1.regs ⟨src, hs⟩ else 0
            let newMem := fun rid addr =>
              if rid = c.regionId && addr = off then sv else s1.mem rid addr
            { s1 with
              pc := s1.pc + 1
              mem := newMem
              log := s1.log ++ [sv] }
          else
            { s1 with halted := true, fault := 2 }

def vmStep (prog : List VmInsn) (s : VmState) : VmState :=
  if s.halted then
    s
  else if s.fuel = 0 then
    { s with halted := true, fault := 1 }
  else
    let s1 : VmState := { s with fuel := s.fuel - 1 }
    match prog[s.pc]? with
    | none => { s1 with halted := true }
    | some insn => vmExecInsn s1 insn

def vmRun (prog : List VmInsn) : Nat → VmState → VmState
  | 0, s => s
  | k + 1, s => vmRun prog k (vmStep prog s)

theorem vmExecInsn_preserves_caps (s1 : VmState) (insn : VmInsn) :
    (vmExecInsn s1 insn).caps = s1.caps := by
  cases insn with
  | halt => rfl
  | movi _ _ => rfl
  | add _ _ _ => rfl
  | storeCap capIdx off src =>
      dsimp [vmExecInsn]
      cases hc : s1.caps[capIdx]? with
      | none => rfl
      | some c =>
          by_cases hCond : (c.rights.w && decide (c.base ≤ off) && decide (off < c.base + c.len)) = true
          · simp [hCond]
          · simp [hCond]

theorem vmStep_preserves_caps (prog : List VmInsn) (s : VmState) :
    (vmStep prog s).caps = s.caps := by
  unfold vmStep
  by_cases hh : s.halted = true
  · simp [hh]
  · by_cases hf : s.fuel = 0
    · simp [hh, hf]
    · simp only [hh, Bool.false_eq_true, ↓reduceIte, hf]
      cases hp : prog[s.pc]? with
      | none => rfl
      | some insn =>
          exact vmExecInsn_preserves_caps { s with fuel := s.fuel - 1, halted := false } insn

theorem cap_non_interference_exec (s1 : VmState) (insn : VmInsn) (targetRegion : Nat)
    (hNoCap : noWriteCapForRegion s1.caps targetRegion) :
    ∀ addr, (vmExecInsn s1 insn).mem targetRegion addr = s1.mem targetRegion addr := by
  intro addr
  cases insn with
  | halt => rfl
  | movi _ _ => rfl
  | add _ _ _ => rfl
  | storeCap capIdx off src =>
      dsimp [vmExecInsn]
      cases hc : s1.caps[capIdx]? with
      | none => rfl
      | some c =>
          by_cases hCond : (c.rights.w && decide (c.base ≤ off) && decide (off < c.base + c.len)) = true
          · simp only [hCond, ↓reduceIte]
            have hMem := list_getElem_mem s1.caps capIdx c hc
            have hNo := hNoCap c hMem
            have hW : c.rights.w = true := by
              cases hw : c.rights.w
              · simp [hw] at hCond
              · rfl
            have hNeq : c.regionId ≠ targetRegion := by
              cases hNo with
              | inl hl => exact hl
              | inr hr => simp [hW] at hr
            have hFalse : (targetRegion = c.regionId) = False :=
              propext ⟨fun hEq => hNeq hEq.symm, False.elim⟩
            simp [hFalse]
          · simp [hCond]

theorem cap_non_interference_step (prog : List VmInsn) (s : VmState) (targetRegion : Nat)
    (hNoCap : noWriteCapForRegion s.caps targetRegion) :
    ∀ addr, (vmStep prog s).mem targetRegion addr = s.mem targetRegion addr := by
  intro addr
  unfold vmStep
  by_cases hh : s.halted = true
  · simp [hh]
  · by_cases hf : s.fuel = 0
    · simp [hh, hf]
    · simp only [hh, Bool.false_eq_true, ↓reduceIte, hf]
      cases hp : prog[s.pc]? with
      | none => rfl
      | some insn =>
          exact cap_non_interference_exec { s with fuel := s.fuel - 1, halted := false } insn targetRegion hNoCap addr

theorem cap_non_interference_run : ∀ (k : Nat) (prog : List VmInsn) (s : VmState)
    (targetRegion : Nat),
    noWriteCapForRegion s.caps targetRegion →
    ∀ addr, (vmRun prog k s).mem targetRegion addr = s.mem targetRegion addr
  | 0, _, _, _, _, _ => rfl
  | k + 1, prog, s, targetRegion, hNoCap, addr => by
      dsimp [vmRun]
      have hStep := cap_non_interference_step prog s targetRegion hNoCap addr
      have hCaps : noWriteCapForRegion (vmStep prog s).caps targetRegion := by
        rw [vmStep_preserves_caps]
        exact hNoCap
      exact (cap_non_interference_run k prog (vmStep prog s) targetRegion hCaps addr).trans hStep

theorem vmExecInsn_preserves_fuel (s1 : VmState) (insn : VmInsn) :
    (vmExecInsn s1 insn).fuel = s1.fuel := by
  cases insn with
  | halt => rfl
  | movi _ _ => rfl
  | add _ _ _ => rfl
  | storeCap capIdx off src =>
      dsimp [vmExecInsn]
      cases hc : s1.caps[capIdx]? with
      | none => rfl
      | some c =>
          by_cases hCond : (c.rights.w && decide (c.base ≤ off) && decide (off < c.base + c.len)) = true
          · simp [hCond]
          · simp [hCond]

theorem vmStep_fuel_decreases (prog : List VmInsn) (s : VmState)
    (hNotHalted : s.halted = false) (hFuel : 0 < s.fuel) :
    (vmStep prog s).fuel = s.fuel - 1 := by
  unfold vmStep
  have hNe : s.fuel ≠ 0 := Nat.ne_of_gt hFuel
  simp only [hNotHalted, Bool.false_eq_true, ↓reduceIte, hNe]
  cases hp : prog[s.pc]? with
  | none => rfl
  | some insn =>
      exact vmExecInsn_preserves_fuel { s with fuel := s.fuel - 1, halted := false } insn

theorem vmStep_fuel_le (prog : List VmInsn) (s : VmState) :
    (vmStep prog s).fuel ≤ s.fuel := by
  by_cases hh : s.halted = true
  · unfold vmStep
    simp [hh]
  · have hNotHalted : s.halted = false := by
      cases hx : s.halted <;> simp_all
    by_cases hf : s.fuel = 0
    · unfold vmStep
      simp [hNotHalted, hf]
    · have hPos : 0 < s.fuel := Nat.pos_of_ne_zero hf
      rw [vmStep_fuel_decreases prog s hNotHalted hPos]
      omega

theorem vmStep_halted_absorb (prog : List VmInsn) (s : VmState) (h : s.halted = true) :
    vmStep prog s = s := by
  unfold vmStep
  simp [h]

theorem vmRun_halted_absorb : ∀ (k : Nat) (prog : List VmInsn) (s : VmState),
    s.halted = true → vmRun prog k s = s
  | 0, _, _, _ => rfl
  | k + 1, prog, s, h => by
      dsimp [vmRun]
      rw [vmStep_halted_absorb prog s h]
      exact vmRun_halted_absorb k prog s h

theorem vmRun_halts_within_fuel : ∀ (k : Nat) (prog : List VmInsn) (s : VmState),
    s.fuel < k → (vmRun prog k s).halted = true
  | 0, _, s, h => by omega
  | k + 1, prog, s, h => by
      dsimp [vmRun]
      by_cases hh : s.halted = true
      · rw [vmStep_halted_absorb prog s hh, vmRun_halted_absorb k prog s hh]
        exact hh
      · have hNotHalted : s.halted = false := by
          cases hx : s.halted <;> simp_all
        by_cases hf : s.fuel = 0
        · have hStepHalted : (vmStep prog s).halted = true := by
            unfold vmStep
            simp [hNotHalted, hf]
          rw [vmRun_halted_absorb k prog (vmStep prog s) hStepHalted]
          exact hStepHalted
        · have hPos : 0 < s.fuel := Nat.pos_of_ne_zero hf
          have hDec := vmStep_fuel_decreases prog s hNotHalted hPos
          apply vmRun_halts_within_fuel k prog (vmStep prog s)
          omega

theorem vmRun_add : ∀ (a b : Nat) (prog : List VmInsn) (s : VmState),
    vmRun prog (a + b) s = vmRun prog b (vmRun prog a s)
  | 0, _, prog, s => by
      simp [vmRun]
  | a + 1, b, prog, s => by
      have hEq : a + 1 + b = (a + b) + 1 := by omega
      rw [hEq]
      dsimp [vmRun]
      exact vmRun_add a b prog (vmStep prog s)

theorem vmRun_deterministic (prog : List VmInsn) (k : Nat) (s1 s2 : VmState)
    (hEq : s1 = s2) : vmRun prog k s1 = vmRun prog k s2 := by
  subst hEq
  rfl

theorem replay_from_checkpoint_exact (prog : List VmInsn) (tPre tPost : Nat) (s0 : VmState) :
    let snap := vmRun prog tPre s0
    vmRun prog tPost snap = vmRun prog (tPre + tPost) s0 := by
  exact (vmRun_add tPre tPost prog s0).symm

end Node.Sandbox
