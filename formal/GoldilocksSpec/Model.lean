/-
  A faithful transcription of the hand-optimized Goldilocks arithmetic in
  `src/goldilocks.rs` (qp-poseidon-core), at the `u64` level.

  MODELING. A `u64` is a `Nat` together with the side condition `< 2^64`
  (carried as a hypothesis by every correctness theorem, never baked into the
  definitions). Wrapping operations are modeled explicitly:

    * `x.overflowing_add y`  ↦  value `(x + y) % 2^64`, flag `2^64 ≤ x + y`
    * `x.overflowing_sub y`  ↦  value `(x + 2^64 - y) % 2^64`, flag `x < y`
    * `x >> k`               ↦  `x / 2^k`
    * `x & (2^k - 1)`        ↦  `x % 2^k`

  Carry/borrow flags are `{0,1}`-valued `Nat`s (`if c then 1 else 0`) so each
  definition reads line-for-line against the Rust. The trailing fix-up
  additions/subtractions that the Rust performs with plain `+=`/`-=` (annotated
  "Cannot overflow"/"Cannot underflow") are modeled as WRAPPING operations:
  if those annotations were wrong, the model would compute the same wrong value
  as the machine, and the correctness theorems in `GoldilocksSpec.Correctness`
  would be unprovable. Separate lemmas there certify that the wraps never fire,
  i.e. the Rust comments and the `assume` UB-hints are sound.

  The crate stores field elements in a NON-canonical representation: the
  internal `u64` may be ≥ P, and every operation must be correct for every
  representative. Accordingly the correctness theorems assume only `< 2^64` —
  never canonicality — and conclude congruence mod P plus closure
  (`result < 2^64`).

  FIDELITY. This model is a hand transcription (there is no symbolic exporter
  for straight-line u64 Rust, unlike the gate-constraint exporter in
  qp-plonky2/formal). Two mitigations: each definition cites the
  `goldilocks.rs` lines it mirrors so the correspondence is auditable side by
  side, and `Correctness.lean` ends with kernel-evaluated cross-checks of the
  model against the crate's own `test_against_p3_expected_values` vectors.
-/

namespace GoldilocksSpec

/-- The Goldilocks prime `P = 2^64 - 2^32 + 1` (`goldilocks.rs:51`). -/
def P : Nat := 0xFFFF_FFFF_0000_0001

/-- `NEG_ORDER = P.wrapping_neg() = 2^64 - P = 2^32 - 1` (`goldilocks.rs:54`). -/
def NEG_ORDER : Nat := 0xFFFF_FFFF

/-- `HALF_P_PLUS_1 = (P + 1) >> 1` (`goldilocks.rs:110`). -/
def HALF_P_PLUS_1 : Nat := 0x7FFFFFFF80000001

theorem P_eq : P = 2 ^ 64 - 2 ^ 32 + 1 := by decide
theorem NEG_ORDER_eq : NEG_ORDER = 2 ^ 64 - P := by decide
theorem HALF_P_PLUS_1_eq : HALF_P_PLUS_1 = (P + 1) / 2 := by decide

/-- `impl Add for Goldilocks` (`goldilocks.rs:189–208`):
```rust
let (sum, over) = self.value.overflowing_add(rhs.value);
let (mut sum, over) = sum.overflowing_add(u64::from(over) * NEG_ORDER);
if over { sum += NEG_ORDER; }   // "Cannot overflow."
Self::new(sum)
``` -/
def rustAdd (a b : Nat) : Nat :=
  let sum1 := (a + b) % 2 ^ 64
  let over1 : Nat := if 2 ^ 64 ≤ a + b then 1 else 0
  let sum2 := (sum1 + over1 * NEG_ORDER) % 2 ^ 64
  let over2 : Nat := if 2 ^ 64 ≤ sum1 + over1 * NEG_ORDER then 1 else 0
  (sum2 + over2 * NEG_ORDER) % 2 ^ 64

/-- `impl Sub for Goldilocks` (`goldilocks.rs:218–237`):
```rust
let (diff, under) = self.value.overflowing_sub(rhs.value);
let (mut diff, under) = diff.overflowing_sub(u64::from(under) * NEG_ORDER);
if under { diff -= NEG_ORDER; }   // "Cannot underflow."
Self::new(diff)
``` -/
def rustSub (a b : Nat) : Nat :=
  let diff1 := (a + 2 ^ 64 - b) % 2 ^ 64
  let under1 : Nat := if a < b then 1 else 0
  let diff2 := (diff1 + 2 ^ 64 - under1 * NEG_ORDER) % 2 ^ 64
  let under2 : Nat := if diff1 < under1 * NEG_ORDER then 1 else 0
  (diff2 + 2 ^ 64 - under2 * NEG_ORDER) % 2 ^ 64

/-- `as_canonical_u64` (`goldilocks.rs:88–97`): one conditional subtraction. -/
def rustCanonical (a : Nat) : Nat :=
  if P ≤ a then a - P else a

/-- `is_zero` (`goldilocks.rs:100–103`): `value == 0 || value == P`. -/
def rustIsZero (a : Nat) : Prop :=
  a = 0 ∨ a = P

/-- `impl PartialEq` (`goldilocks.rs:143–147`): canonical representatives equal. -/
def rustEq (a b : Nat) : Prop :=
  rustCanonical a = rustCanonical b

/-- `impl Neg` (`goldilocks.rs:247–254`): `P - as_canonical_u64()`. -/
def rustNeg (a : Nat) : Nat :=
  P - rustCanonical a

/-- `halve` (`goldilocks.rs:105–115`):
```rust
let lo_bit = self.value & 1;
let half = self.value >> 1;
let mask = 0u64.wrapping_sub(lo_bit);            // all-ones when odd, zero when even
Self::new(half.wrapping_add(mask & HALF_P_PLUS_1))
```
`mask & HALF_P_PLUS_1` is `HALF_P_PLUS_1` when `lo_bit = 1` and `0` when
`lo_bit = 0`, i.e. `lo_bit * HALF_P_PLUS_1`. The `wrapping_add` wraps. -/
def rustHalve (a : Nat) : Nat :=
  let loBit := a % 2
  let half := a / 2
  (half + loBit * HALF_P_PLUS_1) % 2 ^ 64

/-- `add_no_canonicalize_trashing_input` (`goldilocks.rs:336–339`, the portable
fallback; the x86_64 asm at :315–328 computes the same function):
```rust
let (res_wrapped, carry) = x.overflowing_add(y);
res_wrapped + NEG_ORDER * u64::from(carry)      // safety doc: needs x + y < 2^64 + P
```
The trailing plain `+` is modeled wrapping; `Correctness` proves it never wraps
under the documented safety precondition. -/
def addNoCanonicalize (x y : Nat) : Nat :=
  let resWrapped := (x + y) % 2 ^ 64
  let carry : Nat := if 2 ^ 64 ≤ x + y then 1 else 0
  (resWrapped + carry * NEG_ORDER) % 2 ^ 64

/-- The straight-line body of `reduce128` (`goldilocks.rs:293–299`), after the
input has been split into `lo = x_lo` (low 64 bits), `hh = x_hi_hi` (bits
96..128) and `hl = x_hi_lo` (bits 64..96):
```rust
let (mut t0, borrow) = x_lo.overflowing_sub(x_hi_hi);
if borrow { t0 -= NEG_ORDER; }          // "Cannot underflow"
let t1 = x_hi_lo * NEG_ORDER;
let t2 = unsafe { add_no_canonicalize_trashing_input(t0, t1) };
```
The `u64` product `x_hi_lo * NEG_ORDER` is modeled wrapping (`Correctness`
proves `(2^32 - 1)^2 < 2^64`, so it never does). -/
def reducePieces (lo hh hl : Nat) : Nat :=
  let t0a := (lo + 2 ^ 64 - hh) % 2 ^ 64
  let borrow : Nat := if lo < hh then 1 else 0
  let t0 := (t0a + 2 ^ 64 - borrow * NEG_ORDER) % 2 ^ 64
  let t1 := hl * NEG_ORDER % 2 ^ 64
  addNoCanonicalize t0 t1

/-- `reduce128` (`goldilocks.rs:288–307`): `split` (:305) yields
`x_lo = x % 2^64` and `x_hi = x / 2^64`; then `x_hi >> 32` and
`x_hi & NEG_ORDER` (:290–291) select the two 32-bit halves of `x_hi`. -/
def reduce128 (x : Nat) : Nat :=
  reducePieces (x % 2 ^ 64) (x / 2 ^ 64 / 2 ^ 32) (x / 2 ^ 64 % 2 ^ 32)

/-- `impl Mul` (`goldilocks.rs:256–263`): widen to u128, multiply, reduce.
The u128 product `u128::from(a) * u128::from(b)` cannot wrap
(`(2^64 - 1)^2 < 2^128`), so it is a plain product. -/
def rustMul (a b : Nat) : Nat :=
  reduce128 (a * b)

/-- `square` (`goldilocks.rs:117–121`). -/
def rustSquare (a : Nat) : Nat :=
  rustMul a a

/-- `double` (`goldilocks.rs:123–127`). -/
def rustDouble (a : Nat) : Nat :=
  rustAdd a a

/-- `exp7` — the Poseidon2 S-box (`goldilocks.rs:129–136`):
```rust
let x2 = self.square();
let x3 = x2 * *self;
let x4 = x2.square();
x3 * x4
``` -/
def rustExp7 (a : Nat) : Nat :=
  let x2 := rustSquare a
  let x3 := rustMul x2 a
  let x4 := rustSquare x2
  rustMul x3 x4

end GoldilocksSpec
