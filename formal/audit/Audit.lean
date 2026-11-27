/-
Lean 4 model of the audit chain (crates/dos-audit, design/audit.md, spec U-CHAIN-LOG).

Core Lean only, no Mathlib. What is modelled: entry `n` carries its position, the hash of
the previous entry and a body; its hash is a function of exactly those three. A log is valid
if it can be built from the empty log by appending entries that follow that rule.

Axiomatized (like Ed25519 in the other formal artifacts): collision resistance of the entry
hash, as injectivity of `Model.h`. Signatures are not modelled here: they give authenticity
(who wrote it), the chain gives integrity (what and in which order).

Proved:
  append_valid       appending a correctly built entry keeps a log valid
  seq_eq_index       in a valid log every entry's seq is its index
  fork_free          two valid logs of the same length with the same head hash are equal
  valid_prefix       every prefix of a valid log is valid
  anchor_binds       an anchor (n, h) pins the first n entries: two valid logs whose n-th
                     entry hash is h agree on those n entries (no edit, insert, delete or
                     reorder before the anchor goes undetected)
  truncation_visible a valid log shorter than the anchor cannot match it
-/

namespace Audit

structure Entry (Body Hash : Type) where
  seq  : Nat
  prev : Hash
  body : Body
  hash : Hash

structure Model (Body Hash : Type) where
  genesis : Hash
  /-- entry hash: a function of position, previous hash and body only. -/
  h : Nat → Hash → Body → Hash
  /-- collision resistance (SHA-256 over the JCS bytes), axiomatized. -/
  inj : ∀ s p b s' p' b', h s p b = h s' p' b' → s = s' ∧ p = p' ∧ b = b'

variable {Body Hash : Type} (M : Model Body Hash)

/-- Head hash of a log: the last entry's hash, or genesis for the empty log. -/
def head (l : List (Entry Body Hash)) : Hash :=
  match l.getLast? with
  | none => M.genesis
  | some e => e.hash

inductive Valid : List (Entry Body Hash) → Prop
  | nil : Valid []
  | snoc (l : List (Entry Body Hash)) (e : Entry Body Hash) :
      Valid l → e.seq = l.length → e.prev = head M l →
      e.hash = M.h e.seq e.prev e.body → Valid (l ++ [e])

/-- The entry the sink appends for `body`. -/
def mk (l : List (Entry Body Hash)) (body : Body) : Entry Body Hash :=
  { seq := l.length, prev := head M l, body := body,
    hash := M.h l.length (head M l) body }

theorem head_snoc (l : List (Entry Body Hash)) (e : Entry Body Hash) :
    head M (l ++ [e]) = e.hash := by
  simp [head, List.getLast?_append]

theorem append_valid {l : List (Entry Body Hash)} (hl : Valid M l) (b : Body) :
    Valid M (l ++ [mk M l b]) :=
  Valid.snoc l (mk M l b) hl rfl rfl rfl

theorem seq_eq_index {l : List (Entry Body Hash)} (hl : Valid M l) :
    ∀ i (hi : i < l.length), (l.get ⟨i, hi⟩).seq = i := by
  induction hl with
  | nil => intro i hi; simp at hi
  | snoc l e _ hs _ _ ih =>
    intro i hi
    by_cases h : i < l.length
    · have := ih i h
      simpa [List.getElem_append_left h] using this
    · have hlen : i = l.length := by
        have : (l ++ [e]).length = l.length + 1 := by simp
        omega
      subst hlen
      simpa using hs

theorem fork_free {l1 l2 : List (Entry Body Hash)} (h1 : Valid M l1) :
    Valid M l2 → l1.length = l2.length → head M l1 = head M l2 → l1 = l2 := by
  induction h1 generalizing l2 with
  | nil =>
    intro _ hlen _
    exact (List.length_eq_zero_iff.mp hlen.symm).symm
  | snoc l e _ hs hp hh ih =>
    intro h2 hlen hhead
    cases h2 with
    | nil => simp at hlen
    | snoc l' e' v' hs' hp' hh' =>
      rw [head_snoc, head_snoc] at hhead
      have hl : l.length = l'.length := by simpa using hlen
      rw [hhead] at hh
      have hi := M.inj _ _ _ _ _ _ (hh.symm.trans hh')
      have hseq : e.seq = e'.seq := hi.1
      have hprev : e.prev = e'.prev := hi.2.1
      have hbody : e.body = e'.body := hi.2.2
      have hheads : head M l = head M l' := by rw [← hp, ← hp', hprev]
      have := ih v' hl hheads
      subst this
      have : e = e' := by
        cases e; cases e'
        simp_all
      subst this
      rfl

theorem valid_prefix {l : List (Entry Body Hash)} (hl : Valid M l) :
    ∀ p s, p ++ s = l → Valid M p := by
  induction hl with
  | nil =>
    intro p s h
    have hp : p = [] := (List.append_eq_nil_iff.mp h).1
    subst hp; exact Valid.nil
  | snoc l e hv hs hp hh ih =>
    intro p s h
    cases List.eq_nil_or_concat s with
    | inl h0 =>
      subst h0
      simp at h
      subst h
      exact Valid.snoc l e hv hs hp hh
    | inr h1 =>
      obtain ⟨s2, x, h2⟩ := h1
      subst h2
      have h3 : (p ++ s2) ++ [x] = l ++ [e] := by simpa [List.append_assoc] using h
      exact ih p s2 (List.append_inj_left' h3 rfl)

/-- The first `n` entries of a log. -/
def firstN (n : Nat) (l : List (Entry Body Hash)) := l.take n

theorem valid_take {l : List (Entry Body Hash)} (hl : Valid M l) (n : Nat) :
    Valid M (l.take n) :=
  valid_prefix M hl (l.take n) (l.drop n) (List.take_append_drop n l)

/-- An anchor `(n, h)`: the log has `n` entries and the n-th has hash `h`. A log matches it
    if its first `n` entries have length `n` and head `h`. -/
def Matches (n : Nat) (a : Hash) (l : List (Entry Body Hash)) : Prop :=
  (l.take n).length = n ∧ head M (l.take n) = a

theorem anchor_binds {l1 l2 : List (Entry Body Hash)} (h1 : Valid M l1) (h2 : Valid M l2)
    {n : Nat} {a : Hash} (m1 : Matches M n a l1) (m2 : Matches M n a l2) :
    l1.take n = l2.take n :=
  fork_free M (valid_take M h1 n) (valid_take M h2 n) (m1.1.trans m2.1.symm)
    (m1.2.trans m2.2.symm)

theorem truncation_visible {l : List (Entry Body Hash)} {n : Nat} {a : Hash}
    (hshort : l.length < n) : ¬ Matches M n a l := by
  intro m
  have := m.1
  simp [List.length_take] at this
  omega

end Audit
