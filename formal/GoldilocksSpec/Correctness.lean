import GoldilocksSpec.Model

/-!
# Tier-1 correctness of the optimized Goldilocks arithmetic

For every operation `op` in `src/goldilocks.rs` (modeled in
`GoldilocksSpec.Model`) we prove, assuming only that the inputs are machine
words (`< 2^64` — canonicality is NOT assumed, since the crate's
representation is non-canonical by design):

  * **congruence**: the result equals the mathematical field operation mod P,
    stated as a `Nat` congruence, e.g. `rustAdd a b % P = (a + b) % P`;
  * **closure**: the result is again a machine word (`< 2^64`);
  * **no silent wrap**: every `+=` / `-=` / `wrapping_*` the Rust annotates
    with "Cannot overflow" / "Cannot underflow" really cannot, and each
    `assume(..)` UB-hint is implied by its branch condition (so the
    `unreachable_unchecked` inside `assume` is never reached).

On the `ZMod P` reading: casting `Nat → ZMod P` identifies `x` with `x % P`,
so e.g. `rustAdd a b % P = (a + b) % P` is precisely
`(↑(rustAdd a b) : ZMod P) = ↑a + ↑b`. We state the `Nat` form to keep the
package dependency-free (no mathlib), mirroring qp-zk-circuits/formal.

The capstone `goldilocks_tier1` bundles every theorem; CI asserts its axiom
footprint is exactly the standard Lean axioms.
-/

namespace GoldilocksSpec

/-! ### Numeric literals for `omega` -/

theorem two_pow_32 : (2 : Nat) ^ 32 = 4294967296 := by decide
theorem two_pow_64 : (2 : Nat) ^ 64 = 18446744073709551616 := by decide
theorem two_pow_96 : (2 : Nat) ^ 96 = 79228162514264337593543950336 := by decide
theorem two_pow_128 : (2 : Nat) ^ 128 = 340282366920938463463374607431768211456 := by decide

/-! ### `as_canonical_u64`, `is_zero`, `eq` -/

/-- One conditional subtraction fully canonicalizes, because `2 * P` does not
fit in a `u64` (justifying the comment at `goldilocks.rs:92`). -/
theorem rustCanonical_eq_mod {a : Nat} (ha : a < 2 ^ 64) :
    rustCanonical a = a % P := by
  simp only [rustCanonical, P, two_pow_64] at *
  split <;> omega

theorem rustCanonical_lt_P {a : Nat} (ha : a < 2 ^ 64) : rustCanonical a < P := by
  simp only [rustCanonical, P, two_pow_64] at *
  split <;> omega

/-- `is_zero` recognizes exactly the two representatives of `0`. -/
theorem rustIsZero_iff {a : Nat} (ha : a < 2 ^ 64) : rustIsZero a ↔ a % P = 0 := by
  simp only [rustIsZero, P, two_pow_64] at *
  omega

/-- `==` on `Goldilocks` decides equality of residues mod P. -/
theorem rustEq_iff {a b : Nat} (ha : a < 2 ^ 64) (hb : b < 2 ^ 64) :
    rustEq a b ↔ a % P = b % P := by
  simp only [rustEq, rustCanonical, P, two_pow_64] at *
  split <;> split <;> omega

/-! ### Addition -/

theorem rustAdd_lt (a b : Nat) : rustAdd a b < 2 ^ 64 := by
  simp only [rustAdd]
  exact Nat.mod_lt _ (by decide)

theorem rustAdd_mod {a b : Nat} (ha : a < 2 ^ 64) (hb : b < 2 ^ 64) :
    rustAdd a b % P = (a + b) % P := by
  simp only [rustAdd, P, NEG_ORDER, two_pow_64] at *
  split <;> split <;> omega

/-- The `assume(self.value > P && rhs.value > P)` at `goldilocks.rs:203` is
sound: whenever the double-overflow branch is taken (first `overflowing_add`
carried — `h1` — and the `NEG_ORDER` correction carried again — `h2`), both
inputs necessarily exceed P, so `assume`'s `unreachable_unchecked` is dead. -/
theorem rustAdd_assume_sound {a b : Nat} (ha : a < 2 ^ 64) (hb : b < 2 ^ 64)
    (h1 : 2 ^ 64 ≤ a + b) (h2 : 2 ^ 64 ≤ (a + b) % 2 ^ 64 + NEG_ORDER) :
    P < a ∧ P < b := by
  simp only [P, NEG_ORDER, two_pow_64] at *
  omega

/-- The `sum += NEG_ORDER; // Cannot overflow.` at `goldilocks.rs:205` indeed
cannot: in the double-overflow branch (`_h1`, `h2` as in
`rustAdd_assume_sound`) the wrapped sum plus `NEG_ORDER` still fits. -/
theorem rustAdd_fixup_no_overflow {a b : Nat} (_h1 : 2 ^ 64 ≤ a + b)
    (h2 : 2 ^ 64 ≤ (a + b) % 2 ^ 64 + NEG_ORDER) :
    ((a + b) % 2 ^ 64 + NEG_ORDER) % 2 ^ 64 + NEG_ORDER < 2 ^ 64 := by
  simp only [NEG_ORDER, two_pow_64] at *
  omega

/-! ### Subtraction -/

theorem rustSub_lt (a b : Nat) : rustSub a b < 2 ^ 64 := by
  simp only [rustSub]
  exact Nat.mod_lt _ (by decide)

/-- `sub` computes `a - b` in the field: adding `b` back recovers `a` mod P. -/
theorem rustSub_mod {a b : Nat} (ha : a < 2 ^ 64) (hb : b < 2 ^ 64) :
    (rustSub a b + b) % P = a % P := by
  simp only [rustSub, P, NEG_ORDER, two_pow_64] at *
  split <;> split <;> omega

/-- The `assume(self.value < NEG_ORDER - 1 && rhs.value > P)` at
`goldilocks.rs:232` is sound: `h1` is the first borrow, `h2` the second
(`(a + 2^64 - b) % 2^64` is the wrapped first difference). -/
theorem rustSub_assume_sound {a b : Nat} (ha : a < 2 ^ 64) (hb : b < 2 ^ 64)
    (h1 : a < b) (h2 : (a + 2 ^ 64 - b) % 2 ^ 64 < NEG_ORDER) :
    a < NEG_ORDER - 1 ∧ P < b := by
  simp only [P, NEG_ORDER, two_pow_64] at *
  omega

/-- The `diff -= NEG_ORDER; // Cannot underflow.` at `goldilocks.rs:234`
indeed cannot: after the double-borrow wrap, the intermediate difference is at
least `NEG_ORDER`. -/
theorem rustSub_fixup_no_underflow {a b : Nat} (_h1 : a < b)
    (h2 : (a + 2 ^ 64 - b) % 2 ^ 64 < NEG_ORDER) :
    NEG_ORDER ≤ ((a + 2 ^ 64 - b) % 2 ^ 64 + 2 ^ 64 - NEG_ORDER) % 2 ^ 64 := by
  simp only [NEG_ORDER, two_pow_64] at *
  omega

/-! ### Negation -/

theorem rustNeg_lt (a : Nat) : rustNeg a < 2 ^ 64 := by
  simp only [rustNeg, P, two_pow_64]
  omega

theorem rustNeg_mod {a : Nat} (ha : a < 2 ^ 64) : (rustNeg a + a) % P = 0 := by
  simp only [rustNeg, rustCanonical, P, two_pow_64] at *
  split <;> omega

/-! ### Halving -/

theorem rustHalve_lt (a : Nat) : rustHalve a < 2 ^ 64 := by
  simp only [rustHalve]
  exact Nat.mod_lt _ (by decide)

/-- The `wrapping_add` in `halve` (`goldilocks.rs:114`) never wraps. -/
theorem rustHalve_no_wrap {a : Nat} (ha : a < 2 ^ 64) :
    a / 2 + a % 2 * HALF_P_PLUS_1 < 2 ^ 64 := by
  simp only [HALF_P_PLUS_1, two_pow_64] at *
  omega

/-- `halve` inverts doubling: `2 * halve(a) ≡ a (mod P)`. -/
theorem rustHalve_mod {a : Nat} (ha : a < 2 ^ 64) :
    2 * rustHalve a % P = a % P := by
  simp only [rustHalve]
  rw [Nat.mod_eq_of_lt (rustHalve_no_wrap ha)]
  simp only [P, HALF_P_PLUS_1, two_pow_64] at *
  omega

/-! ### 128-bit reduction (used by `mul`)

`reduce128` is decomposed as `reducePieces (x % 2^64) (x / 2^96) (bits 64..96)`
in the model; we prove the straight-line body correct first, then reassemble.
Throughout, `lo` is `x_lo`, `hh` is `x_hi_hi`, `hl` is `x_hi_lo`. -/

theorem addNoCanonicalize_lt (x y : Nat) : addNoCanonicalize x y < 2 ^ 64 := by
  simp only [addNoCanonicalize]
  exact Nat.mod_lt _ (by decide)

/-- The safety contract of `add_no_canonicalize_trashing_input`
(`goldilocks.rs:312`, "Only correct if x + y < 2^64 + P"): under it, the
result is a correct non-canonical mod-P sum. We use it with `y < P`. -/
theorem addNoCanonicalize_mod {x y : Nat} (hx : x < 2 ^ 64) (hy : y < P) :
    addNoCanonicalize x y % P = (x + y) % P := by
  simp only [addNoCanonicalize, P, NEG_ORDER, two_pow_64] at *
  split <;> omega

/-- Under the same contract, the trailing plain `+` of the portable fallback
(`goldilocks.rs:338`) never overflows. -/
theorem addNoCanonicalize_fixup_no_overflow {x y : Nat} (hx : x < 2 ^ 64)
    (hy : y < P) (h : 2 ^ 64 ≤ x + y) :
    (x + y) % 2 ^ 64 + NEG_ORDER < 2 ^ 64 := by
  simp only [P, NEG_ORDER, two_pow_64] at *
  omega

/-- The `u64` product `t1 = x_hi_lo * NEG_ORDER` at `goldilocks.rs:298` never
wraps — in fact it stays below P, which feeds the safety contract above. -/
theorem reduce_t1_lt_P {hl : Nat} (hhl : hl < 2 ^ 32) : hl * NEG_ORDER < P := by
  simp only [P, NEG_ORDER, two_pow_32] at *
  omega

/-- The `t0 -= NEG_ORDER; // Cannot underflow` at `goldilocks.rs:296` indeed
cannot: when the borrow fires (`h`), the wrapped difference exceeds
`NEG_ORDER`. -/
theorem reduce_borrow_fixup_no_underflow {lo hh : Nat} (hlo : lo < 2 ^ 64)
    (hhh : hh < 2 ^ 32) (h : lo < hh) :
    NEG_ORDER ≤ (lo + 2 ^ 64 - hh) % 2 ^ 64 := by
  simp only [NEG_ORDER, two_pow_32, two_pow_64] at *
  omega

/-- The borrow-corrected `t0` (`goldilocks.rs:293–297`) equals `lo - hh`
shifted into `[0, 2^64)` by at most one multiple of P: `t0 + hh` is `lo` or
`lo + P`. -/
theorem reduce_t0_spec {lo hh : Nat} (hlo : lo < 2 ^ 64) (hhh : hh < 2 ^ 32) :
    ((lo + 2 ^ 64 - hh) % 2 ^ 64 + 2 ^ 64
        - (if lo < hh then 1 else 0) * NEG_ORDER) % 2 ^ 64 < 2 ^ 64 ∧
    (((lo + 2 ^ 64 - hh) % 2 ^ 64 + 2 ^ 64
        - (if lo < hh then 1 else 0) * NEG_ORDER) % 2 ^ 64 + hh = lo ∨
     ((lo + 2 ^ 64 - hh) % 2 ^ 64 + 2 ^ 64
        - (if lo < hh then 1 else 0) * NEG_ORDER) % 2 ^ 64 + hh = lo + P) := by
  simp only [P, NEG_ORDER, two_pow_32, two_pow_64] at *
  split <;> omega

/-- Combining step, with `t0` abstract so the arithmetic stays small: if
`t0 ≡ lo - hh (mod P)` then `add_no_canonicalize(t0, hl * NEG_ORDER)` is
`lo - hh + 2^64·hl (mod P)`, which matches `2^96·hh + 2^64·hl + lo` because
`P ∣ 2^96 + 1` (Goldilocks: `2^96 ≡ -1`). -/
theorem reduce_combine {t0 lo hh hl : Nat} (ht0lt : t0 < 2 ^ 64)
    (ht0 : t0 + hh = lo ∨ t0 + hh = lo + P) (hhl : hl < 2 ^ 32) :
    addNoCanonicalize t0 (hl * NEG_ORDER % 2 ^ 64) % P
      = (lo + 2 ^ 96 * hh + 2 ^ 64 * hl) % P := by
  have ht1P : hl * NEG_ORDER < P := reduce_t1_lt_P hhl
  have ht1 : hl * NEG_ORDER % 2 ^ 64 = hl * NEG_ORDER :=
    Nat.mod_eq_of_lt (Nat.lt_trans ht1P (by decide))
  rw [ht1, addNoCanonicalize_mod ht0lt ht1P]
  simp only [P, NEG_ORDER, two_pow_32, two_pow_64, two_pow_96] at *
  rcases ht0 with h | h <;> omega

/-- The straight-line body of `reduce128` is a correct mod-P reduction of
`lo + 2^96·hh + 2^64·hl`. -/
theorem reducePieces_mod {lo hh hl : Nat} (hlo : lo < 2 ^ 64)
    (hhh : hh < 2 ^ 32) (hhl : hl < 2 ^ 32) :
    reducePieces lo hh hl % P = (lo + 2 ^ 96 * hh + 2 ^ 64 * hl) % P := by
  obtain ⟨ht0lt, ht0⟩ := reduce_t0_spec hlo hhh
  simp only [reducePieces]
  exact reduce_combine ht0lt ht0 hhl

theorem reducePieces_lt (lo hh hl : Nat) : reducePieces lo hh hl < 2 ^ 64 := by
  simp only [reducePieces]
  exact addNoCanonicalize_lt _ _

theorem reduce128_lt (x : Nat) : reduce128 x < 2 ^ 64 :=
  reducePieces_lt _ _ _

/-- `reduce128` is a correct mod-P reduction on the FULL `u128` range — no
bound tighter than `x < 2^128` is needed. (The three pieces recompose exactly:
`x = lo + 2^96·hh + 2^64·hl`, so this is `reducePieces_mod` plus an identity.) -/
theorem reduce128_mod {x : Nat} (hx : x < 2 ^ 128) : reduce128 x % P = x % P := by
  have hlo : x % 2 ^ 64 < 2 ^ 64 := Nat.mod_lt _ (by decide)
  have hhh : x / 2 ^ 64 / 2 ^ 32 < 2 ^ 32 := by
    simp only [two_pow_32, two_pow_64, two_pow_128] at *
    omega
  have hhl : x / 2 ^ 64 % 2 ^ 32 < 2 ^ 32 := Nat.mod_lt _ (by decide)
  have hsplit : x % 2 ^ 64 + 2 ^ 96 * (x / 2 ^ 64 / 2 ^ 32)
      + 2 ^ 64 * (x / 2 ^ 64 % 2 ^ 32) = x := by
    simp only [two_pow_32, two_pow_64, two_pow_96]
    omega
  simp only [reduce128]
  rw [reducePieces_mod hlo hhh hhl, hsplit]

/-! ### Multiplication, squaring, doubling, the x^7 S-box -/

theorem rustMul_lt (a b : Nat) : rustMul a b < 2 ^ 64 :=
  reduce128_lt _

theorem rustMul_mod {a b : Nat} (ha : a < 2 ^ 64) (hb : b < 2 ^ 64) :
    rustMul a b % P = a * b % P := by
  have hab : a * b < 2 ^ 128 := by
    calc a * b ≤ (2 ^ 64 - 1) * (2 ^ 64 - 1) :=
          Nat.mul_le_mul (by omega) (by omega)
      _ < 2 ^ 128 := by decide
  exact reduce128_mod hab

theorem rustSquare_lt (a : Nat) : rustSquare a < 2 ^ 64 :=
  rustMul_lt a a

theorem rustSquare_mod {a : Nat} (ha : a < 2 ^ 64) :
    rustSquare a % P = a * a % P :=
  rustMul_mod ha ha

theorem rustDouble_lt (a : Nat) : rustDouble a < 2 ^ 64 :=
  rustAdd_lt a a

theorem rustDouble_mod {a : Nat} (ha : a < 2 ^ 64) :
    rustDouble a % P = 2 * a % P := by
  show rustAdd a a % P = 2 * a % P
  rw [rustAdd_mod ha ha]
  simp only [P]
  omega

theorem rustExp7_lt (a : Nat) : rustExp7 a < 2 ^ 64 :=
  rustMul_lt _ _

/-- The Poseidon2 S-box: `exp7(a) ≡ a^7 (mod P)` (the seventh power written
as an explicit product to stay `Nat.pow`-free). -/
theorem rustExp7_mod {a : Nat} (ha : a < 2 ^ 64) :
    rustExp7 a % P = a * a * a * a * a * a * a % P := by
  have h2lt : rustSquare a < 2 ^ 64 := rustSquare_lt a
  have h3lt : rustMul (rustSquare a) a < 2 ^ 64 := rustMul_lt _ _
  have h4lt : rustSquare (rustSquare a) < 2 ^ 64 := rustSquare_lt _
  have h2 : rustSquare a % P = a * a % P := rustSquare_mod ha
  have h3 : rustMul (rustSquare a) a % P = a * a * a % P := by
    rw [rustMul_mod h2lt ha, Nat.mul_mod, h2, ← Nat.mul_mod]
  have h4 : rustSquare (rustSquare a) % P = a * a * (a * a) % P := by
    rw [rustSquare_mod h2lt, Nat.mul_mod, h2, ← Nat.mul_mod]
  show rustMul (rustMul (rustSquare a) a) (rustSquare (rustSquare a)) % P = _
  rw [rustMul_mod h3lt h4lt, Nat.mul_mod, h3, h4, ← Nat.mul_mod]
  simp only [← Nat.mul_assoc]

/-! ### Capstone -/

/-- Every Tier-1 claim in one statement, so a single `#print axioms` in CI
certifies the whole package (see `ci/AxiomsCheck.lean`). Hypotheses are only
`< 2^64` — correctness holds for every (possibly non-canonical) `u64`
representative, which is the crate's actual invariant. -/
theorem goldilocks_tier1 :
    (∀ a b : Nat, a < 2 ^ 64 → b < 2 ^ 64 →
      rustAdd a b < 2 ^ 64 ∧ rustAdd a b % P = (a + b) % P) ∧
    (∀ a b : Nat, a < 2 ^ 64 → b < 2 ^ 64 →
      rustSub a b < 2 ^ 64 ∧ (rustSub a b + b) % P = a % P) ∧
    (∀ a b : Nat, a < 2 ^ 64 → b < 2 ^ 64 →
      rustMul a b < 2 ^ 64 ∧ rustMul a b % P = a * b % P) ∧
    (∀ a : Nat, a < 2 ^ 64 → rustNeg a < 2 ^ 64 ∧ (rustNeg a + a) % P = 0) ∧
    (∀ a : Nat, a < 2 ^ 64 → rustHalve a < 2 ^ 64 ∧ 2 * rustHalve a % P = a % P) ∧
    (∀ a : Nat, a < 2 ^ 64 →
      rustExp7 a < 2 ^ 64 ∧ rustExp7 a % P = a * a * a * a * a * a * a % P) ∧
    (∀ a : Nat, a < 2 ^ 64 → rustCanonical a < P ∧ rustCanonical a = a % P) ∧
    (∀ a : Nat, a < 2 ^ 64 → (rustIsZero a ↔ a % P = 0)) ∧
    (∀ a b : Nat, a < 2 ^ 64 → b < 2 ^ 64 → (rustEq a b ↔ a % P = b % P)) :=
  ⟨fun a b ha hb => ⟨rustAdd_lt a b, rustAdd_mod ha hb⟩,
   fun a b ha hb => ⟨rustSub_lt a b, rustSub_mod ha hb⟩,
   fun a b ha hb => ⟨rustMul_lt a b, rustMul_mod ha hb⟩,
   fun _ ha => ⟨rustNeg_lt _, rustNeg_mod ha⟩,
   fun _ ha => ⟨rustHalve_lt _, rustHalve_mod ha⟩,
   fun _ ha => ⟨rustExp7_lt _, rustExp7_mod ha⟩,
   fun _ ha => ⟨rustCanonical_lt_P ha, rustCanonical_eq_mod ha⟩,
   fun _ ha => rustIsZero_iff ha,
   fun _ _ ha hb => rustEq_iff ha hb⟩

/-! ### Cross-checks against the crate's own test vectors

Kernel-evaluated instances of `test_against_p3_expected_values`
(`goldilocks.rs:404–432`). These pin the hand-transcribed model to the same
concrete values the Rust test suite pins the implementation to, guarding
against transcription drift. -/

example : rustCanonical (rustAdd 13835875475997267463 13593300247443167546) =
    8982431654025850688 := by decide
example : rustCanonical (rustSub 13835875475997267463 13593300247443167546) =
    242575228554099917 := by decide
example : rustCanonical (rustMul 13835875475997267463 13593300247443167546) =
    16746386726560462281 := by decide
example : rustCanonical (rustHalve 13835875475997267463) =
    16141309772705925892 := by decide
example : rustCanonical (rustExp7 13835875475997267463) =
    5716687150516714629 := by decide
example : rustCanonical (rustMul 18446744069414584319 9223372034707292161) =
    18446744069414584320 := by decide
example : rustCanonical (rustHalve 18446744069414584319) =
    18446744069414584320 := by decide
-- `(2^32)^2 = 2^64 ≡ 2^32 - 1 (mod P)` (`test_multiplication_large`).
example : rustCanonical (rustMul 4294967296 4294967296) = 4294967295 := by decide
-- `P` is a non-canonical representative of zero (`test_canonical_reduction`).
example : rustCanonical P = 0 := by decide
example : rustIsZero P := Or.inr rfl

end GoldilocksSpec
