/-
Lean 4 model of the pure verdict logic in crates/dos-core/src/verdict.rs (spec/verdict.md).
The definitions copy the Rust code one to one (rank, meet by `>=`, fold from the authority
verdict), so the theorems are about the same function, not a paraphrase.

Proved: meet is commutative, associative, idempotent; DENY absorbs; ALLOW is the identity;
the result is one of the operands and at least as restrictive as both; meet is permitting
only if both operands are (no amplification); composeWith is permitting only if the
authority verdict and every evaluator verdict are (fail closed on any non-permitting input);
composeWith is at least as restrictive as each input; parse maps every non-canonical wire
string to DENY.
-/

namespace Verdicts

inductive Verdict
  | allow | limit | contain | defer | deny
  deriving DecidableEq, Repr

open Verdict

def rank : Verdict → Nat
  | allow => 0 | limit => 1 | contain => 2 | defer => 3 | deny => 4

def permitting : Verdict → Bool
  | allow | limit | contain => true
  | defer | deny => false

/-- Rust: `if a.rank() >= b.rank() { a } else { b }`. -/
def meet (a b : Verdict) : Verdict := if rank b ≤ rank a then a else b

/-- Rust: `evaluators.into_iter().fold(authority, meet)`. -/
def composeWith (authority : Verdict) (evs : List Verdict) : Verdict :=
  evs.foldl meet authority

def parse (s : String) : Verdict :=
  if s = "ALLOW" then allow
  else if s = "LIMIT" then limit
  else if s = "CONTAIN" then contain
  else if s = "DEFER" then defer
  else deny

theorem meet_comm (a b : Verdict) : meet a b = meet b a := by
  cases a <;> cases b <;> decide

theorem meet_assoc (a b c : Verdict) : meet (meet a b) c = meet a (meet b c) := by
  cases a <;> cases b <;> cases c <;> decide

theorem meet_idem (a : Verdict) : meet a a = a := by cases a <;> decide

theorem deny_absorbs (a : Verdict) : meet deny a = deny ∧ meet a deny = deny := by
  cases a <;> decide

theorem allow_identity (a : Verdict) : meet allow a = a ∧ meet a allow = a := by
  cases a <;> decide

theorem meet_is_operand (a b : Verdict) : meet a b = a ∨ meet a b = b := by
  cases a <;> cases b <;> decide

theorem meet_rank_ge (a b : Verdict) :
    rank a ≤ rank (meet a b) ∧ rank b ≤ rank (meet a b) := by
  cases a <;> cases b <;> decide

/-- AE-2: the meet permits only if both operands permit. -/
theorem meet_permitting (a b : Verdict) :
    permitting (meet a b) = (permitting a && permitting b) := by
  cases a <;> cases b <;> decide

/-- Only a permitting verdict may lead to a token: the fold over the authority verdict and
    every evaluator verdict permits only if each of them does. -/
theorem composeWith_permitting (auth : Verdict) (evs : List Verdict) :
    permitting (composeWith auth evs) = true →
      permitting auth = true ∧ ∀ e ∈ evs, permitting e = true := by
  induction evs generalizing auth with
  | nil => intro h; exact ⟨h, by simp⟩
  | cons e es ih =>
    intro h
    have h' := ih (meet auth e) h
    have hm := meet_permitting auth e
    rw [h'.1] at hm
    have hp : (permitting auth && permitting e) = true := hm.symm
    simp at hp
    refine ⟨hp.1, ?_⟩
    intro x hx
    cases List.mem_cons.mp hx with
    | inl hxe => rw [hxe]; exact hp.2
    | inr hxs => exact h'.2 x hxs

/-- The fold is at least as restrictive as the authority verdict and as every evaluator. -/
theorem composeWith_rank (auth : Verdict) (evs : List Verdict) :
    rank auth ≤ rank (composeWith auth evs) ∧
      ∀ e ∈ evs, rank e ≤ rank (composeWith auth evs) := by
  induction evs generalizing auth with
  | nil => exact ⟨Nat.le_refl _, by simp⟩
  | cons e es ih =>
    have h := ih (meet auth e)
    have hm := meet_rank_ge auth e
    refine ⟨Nat.le_trans hm.1 h.1, ?_⟩
    intro x hx
    cases List.mem_cons.mp hx with
    | inl hxe => rw [hxe]; exact Nat.le_trans hm.2 h.1
    | inr hxs => exact h.2 x hxs

/-- A DENY anywhere makes the result DENY. -/
theorem composeWith_deny (auth : Verdict) (evs : List Verdict) (hd : deny ∈ evs ∨ auth = deny) :
    composeWith auth evs = deny := by
  have h := composeWith_rank auth evs
  have hle : rank (composeWith auth evs) ≤ 4 := by
    generalize composeWith auth evs = v; cases v <;> decide
  cases hd with
  | inl hmem =>
    have := h.2 deny hmem
    have : rank (composeWith auth evs) = 4 := Nat.le_antisymm hle this
    generalize composeWith auth evs = v at this; cases v <;> simp_all [rank]
  | inr ha =>
    have h4 : rank auth = 4 := by rw [ha]; rfl
    have h5 : 4 ≤ rank (composeWith auth evs) := h4 ▸ h.1
    have : rank (composeWith auth evs) = 4 := Nat.le_antisymm hle h5
    generalize composeWith auth evs = v at this; cases v <;> simp_all [rank]

/-- Fail closed: every string other than the four exact names parses to DENY. -/
theorem parse_other_is_deny (s : String)
    (h1 : s ≠ "ALLOW") (h2 : s ≠ "LIMIT") (h3 : s ≠ "CONTAIN") (h4 : s ≠ "DEFER") :
    parse s = deny := by
  simp [parse, h1, h2, h3, h4]

end Verdicts
