//! Minimal Goldilocks field implementation for Poseidon2.
//!
//! This module provides a self-contained implementation of the Goldilocks prime field
//! (p = 2^64 - 2^32 + 1) with just enough operations for Poseidon2 hashing:
//! - Addition, subtraction, multiplication
//! - S-box computation (x^7)
//! - Conversion to/from canonical u64

use core::{
	fmt::{Debug, Display, Formatter},
	hash::{Hash, Hasher},
	hint::unreachable_unchecked,
	iter::Sum,
	ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

// ============================================================================
// Compiler hints for optimization
// ============================================================================

/// Tell the compiler that condition `p` is always true.
/// If `p` is false at runtime, behavior is undefined.
#[inline(always)]
fn assume(p: bool) {
	debug_assert!(p);
	if !p {
		unsafe {
			unreachable_unchecked();
		}
	}
}

/// Force the compiler to emit a branch instruction.
/// This helps when a branch is rarely taken but important to handle.
#[inline(always)]
fn branch_hint() {
	#[cfg(any(
		target_arch = "aarch64",
		target_arch = "arm",
		target_arch = "riscv32",
		target_arch = "riscv64",
		target_arch = "x86",
		target_arch = "x86_64",
	))]
	unsafe {
		core::arch::asm!("", options(nomem, nostack, preserves_flags));
	}
}

/// The Goldilocks prime: p = 2^64 - 2^32 + 1
pub const P: u64 = 0xFFFF_FFFF_0000_0001;

/// Two's complement of ORDER: 2^64 - P = 2^32 - 1
const NEG_ORDER: u64 = P.wrapping_neg();

/// A field element in the Goldilocks prime field.
///
/// Internal representation may be non-canonical (i.e., value can be >= P).
/// Use `as_canonical_u64()` to get the canonical representation.
#[derive(Copy, Clone, Default)]
#[repr(transparent)]
pub struct Goldilocks {
	/// Not necessarily canonical (can be any u64).
	pub(crate) value: u64,
}

impl Goldilocks {
	/// The additive identity.
	pub const ZERO: Self = Self::new(0);

	/// The multiplicative identity.
	pub const ONE: Self = Self::new(1);

	/// Create a new field element from a u64.
	///
	/// No reduction is performed since Goldilocks uses a non-canonical internal representation.
	#[inline]
	pub const fn new(value: u64) -> Self {
		Self { value }
	}

	/// Create a field element from a u64, reducing if necessary.
	#[inline]
	pub fn from_u64(x: u64) -> Self {
		Self::new(x)
	}

	/// Convert to canonical u64 representation (0 <= result < P).
	#[inline]
	pub fn as_canonical_u64(&self) -> u64 {
		let mut c = self.value;
		// We only need one conditional subtraction, since 2 * P would not fit in a u64.
		if c >= P {
			c -= P;
		}
		c
	}

	/// Check if this element is zero.
	#[inline]
	pub fn is_zero(&self) -> bool {
		self.value == 0 || self.value == P
	}

	/// Compute x/2 in the field (branchless).
	#[inline]
	pub fn halve(&self) -> Self {
		// Branchless halving: x/2 = (x >> 1) + ((x & 1) * (p+1)/2).
		// When x is odd, add (p+1)/2 to compensate for the lost bit.
		const HALF_P_PLUS_1: u64 = (P + 1) >> 1; // 0x7FFFFFFF80000001
		let lo_bit = self.value & 1;
		let half = self.value >> 1;
		let mask = 0u64.wrapping_sub(lo_bit); // all-ones when odd, zero when even
		Self::new(half.wrapping_add(mask & HALF_P_PLUS_1))
	}

	/// Compute x^2 in the field.
	#[inline]
	pub fn square(&self) -> Self {
		*self * *self
	}

	/// Compute x * 2 in the field.
	#[inline]
	pub fn double(&self) -> Self {
		*self + *self
	}

	/// Compute x^7 (the S-box for Poseidon2 over Goldilocks).
	#[inline]
	pub fn exp7(&self) -> Self {
		let x2 = self.square();
		let x3 = x2 * *self;
		let x4 = x2.square();
		x3 * x4
	}
}

// ============================================================================
// Equality and ordering (based on canonical representation)
// ============================================================================

impl PartialEq for Goldilocks {
	fn eq(&self, other: &Self) -> bool {
		self.as_canonical_u64() == other.as_canonical_u64()
	}
}

impl Eq for Goldilocks {}

impl Hash for Goldilocks {
	fn hash<H: Hasher>(&self, state: &mut H) {
		state.write_u64(self.as_canonical_u64());
	}
}

impl Ord for Goldilocks {
	fn cmp(&self, other: &Self) -> core::cmp::Ordering {
		self.as_canonical_u64().cmp(&other.as_canonical_u64())
	}
}

impl PartialOrd for Goldilocks {
	fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
		Some(self.cmp(other))
	}
}

// ============================================================================
// Display and Debug
// ============================================================================

impl Display for Goldilocks {
	fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
		Display::fmt(&self.as_canonical_u64(), f)
	}
}

impl Debug for Goldilocks {
	fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
		Debug::fmt(&self.as_canonical_u64(), f)
	}
}

// ============================================================================
// Arithmetic operations
// ============================================================================

impl Add for Goldilocks {
	type Output = Self;

	#[inline(always)]
	fn add(self, rhs: Self) -> Self {
		let (sum, over) = self.value.overflowing_add(rhs.value);
		let (mut sum, over) = sum.overflowing_add(u64::from(over) * NEG_ORDER);
		if over {
			// NB: self.value > P && rhs.value > P is necessary but not sufficient for double-overflow.
			// This assume does two things:
			//  1. If compiler knows that either self.value or rhs.value <= P, then it can skip this check.
			//  2. Hints to the compiler how rare this double-overflow is (thus handled better with a branch).
			assume(self.value > P && rhs.value > P);
			branch_hint();
			sum += NEG_ORDER; // Cannot overflow.
		}
		Self::new(sum)
	}
}

impl AddAssign for Goldilocks {
	#[inline]
	fn add_assign(&mut self, rhs: Self) {
		*self = *self + rhs;
	}
}

impl Sub for Goldilocks {
	type Output = Self;

	#[inline(always)]
	fn sub(self, rhs: Self) -> Self {
		let (diff, under) = self.value.overflowing_sub(rhs.value);
		let (mut diff, under) = diff.overflowing_sub(u64::from(under) * NEG_ORDER);
		if under {
			// NB: self.value < NEG_ORDER - 1 && rhs.value > P is necessary but not sufficient for double-underflow.
			// This assume does two things:
			//  1. If compiler knows that either self.value >= NEG_ORDER - 1 or rhs.value <= P,
			//     then it can skip this check.
			//  2. Hints to the compiler how rare this double-underflow is (thus handled better with a branch).
			assume(self.value < NEG_ORDER - 1 && rhs.value > P);
			branch_hint();
			diff -= NEG_ORDER; // Cannot underflow.
		}
		Self::new(diff)
	}
}

impl SubAssign for Goldilocks {
	#[inline]
	fn sub_assign(&mut self, rhs: Self) {
		*self = *self - rhs;
	}
}

impl Neg for Goldilocks {
	type Output = Self;

	#[inline]
	fn neg(self) -> Self {
		Self::new(P - self.as_canonical_u64())
	}
}

impl Mul for Goldilocks {
	type Output = Self;

	#[inline(always)]
	fn mul(self, rhs: Self) -> Self {
		reduce128(u128::from(self.value) * u128::from(rhs.value))
	}
}

impl MulAssign for Goldilocks {
	#[inline]
	fn mul_assign(&mut self, rhs: Self) {
		*self = *self * rhs;
	}
}

impl Sum for Goldilocks {
	fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
		// Accumulate in u128 to avoid repeated reductions
		let sum = iter.map(|x| x.value as u128).sum::<u128>();
		reduce128(sum)
	}
}

// ============================================================================
// Reduction from u128
// ============================================================================

/// Reduce a u128 to a Goldilocks field element.
///
/// The result might not be in canonical form; it could be between P and 2^64.
#[inline(always)]
fn reduce128(x: u128) -> Goldilocks {
	let (x_lo, x_hi) = split(x);
	let x_hi_hi = x_hi >> 32;
	let x_hi_lo = x_hi & NEG_ORDER;

	let (mut t0, borrow) = x_lo.overflowing_sub(x_hi_hi);
	if borrow {
		branch_hint(); // A borrow is exceedingly rare. It is faster to branch.
		t0 -= NEG_ORDER; // Cannot underflow
	}
	let t1 = x_hi_lo * NEG_ORDER;
	let t2 = unsafe { add_no_canonicalize_trashing_input(t0, t1) };
	Goldilocks::new(t2)
}

#[inline]
#[allow(clippy::cast_possible_truncation)]
const fn split(x: u128) -> (u64, u64) {
	(x as u64, (x >> 64) as u64)
}

/// Fast addition modulo P (result may be non-canonical).
///
/// # Safety
/// Only correct if x + y < 2^64 + P.
#[inline(always)]
#[cfg(target_arch = "x86_64")]
unsafe fn add_no_canonicalize_trashing_input(x: u64, y: u64) -> u64 {
	let res_wrapped: u64;
	let adjustment: u64;
	unsafe {
		core::arch::asm!(
			"add {0}, {1}",
			"sbb {1:e}, {1:e}",
			inlateout(reg) x => res_wrapped,
			inlateout(reg) y => adjustment,
			options(pure, nomem, nostack),
		);
	}
	res_wrapped + adjustment
}

/// Fast addition modulo P (result may be non-canonical).
///
/// # Safety
/// Only correct if x + y < 2^64 + P.
#[inline(always)]
#[cfg(not(target_arch = "x86_64"))]
unsafe fn add_no_canonicalize_trashing_input(x: u64, y: u64) -> u64 {
	let (res_wrapped, carry) = x.overflowing_add(y);
	res_wrapped + NEG_ORDER * u64::from(carry)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_basic_arithmetic() {
		let a = Goldilocks::new(5);
		let b = Goldilocks::new(3);

		assert_eq!((a + b).as_canonical_u64(), 8);
		assert_eq!((a - b).as_canonical_u64(), 2);
		assert_eq!((a * b).as_canonical_u64(), 15);
	}

	#[test]
	fn test_large_values_arithmetic() {
		// Test with large values near the field prime
		let a = Goldilocks::new(P - 1); // -1 mod P
		let b = Goldilocks::new(P - 2); // -2 mod P

		// (-1) + (-2) = -3 mod P = P - 3
		assert_eq!((a + b).as_canonical_u64(), P - 3);

		// (-1) - (-2) = 1 mod P
		assert_eq!((a - b).as_canonical_u64(), 1);

		// (-1) * (-2) = 2 mod P
		assert_eq!((a * b).as_canonical_u64(), 2);

		// Test with random-looking large values
		let x = Goldilocks::new(0xc002e770975b1607); // First round constant
		let y = Goldilocks::new(0xbca51a8dfe14593a); // Second round constant

		// Just verify these don't panic and produce canonical results
		let sum = x + y;
		let diff = x - y;
		let prod = x * y;

		assert!(sum.as_canonical_u64() < P);
		assert!(diff.as_canonical_u64() < P);
		assert!(prod.as_canonical_u64() < P);
	}

	#[test]
	fn test_exp7_large_values() {
		// Test S-box with large values
		let x = Goldilocks::new(0xc002e770975b1607);
		let y = x.exp7();

		// Verify it's canonical
		assert!(y.as_canonical_u64() < P);

		// Verify x^7 = x * x^2 * x^4
		let x2 = x * x;
		let x4 = x2 * x2;
		let x7_manual = x * x2 * x4;
		assert_eq!(y.as_canonical_u64(), x7_manual.as_canonical_u64());
	}

	#[test]
	fn test_against_p3_expected_values() {
		// Expected values from p3 field operations
		// p3: 13835875475997267463 + 13593300247443167546 = 8982431654025850688
		let a = Goldilocks::new(13835875475997267463);
		let b = Goldilocks::new(13593300247443167546);
		assert_eq!((a + b).as_canonical_u64(), 8982431654025850688, "add mismatch");

		// p3: 13835875475997267463 - 13593300247443167546 = 242575228554099917
		assert_eq!((a - b).as_canonical_u64(), 242575228554099917, "sub mismatch");

		// p3: 13835875475997267463 * 13593300247443167546 = 16746386726560462281
		assert_eq!((a * b).as_canonical_u64(), 16746386726560462281, "mul mismatch");

		// p3: halve(13835875475997267463) = 16141309772705925892
		assert_eq!(a.halve().as_canonical_u64(), 16141309772705925892, "halve mismatch");

		// p3: 13835875475997267463^7 = 5716687150516714629
		assert_eq!(a.exp7().as_canonical_u64(), 5716687150516714629, "exp7 mismatch");

		// More test cases
		// p3: 18446744069414584319 * 9223372034707292161 = 18446744069414584320
		let c = Goldilocks::new(18446744069414584319); // -2 mod P
		let d = Goldilocks::new(9223372034707292161); // 1/2 mod P
		assert_eq!((c * d).as_canonical_u64(), 18446744069414584320, "mul -2 * 1/2 mismatch");

		// p3: halve(18446744069414584319) = 18446744069414584320
		assert_eq!(c.halve().as_canonical_u64(), 18446744069414584320, "halve -2 mismatch");
	}

	#[test]
	fn test_subtraction_underflow() {
		let a = Goldilocks::new(3);
		let b = Goldilocks::new(5);
		let result = a - b;
		// 3 - 5 = -2 mod P = P - 2
		assert_eq!(result.as_canonical_u64(), P - 2);
	}

	#[test]
	fn test_negation() {
		let a = Goldilocks::new(5);
		let neg_a = -a;
		assert_eq!((a + neg_a).as_canonical_u64(), 0);
	}

	#[test]
	fn test_exp7() {
		let a = Goldilocks::new(2);
		let result = a.exp7();
		assert_eq!(result.as_canonical_u64(), 128); // 2^7 = 128
	}

	#[test]
	fn test_halve() {
		let a = Goldilocks::new(10);
		let half = a.halve();
		assert_eq!((half + half).as_canonical_u64(), 10);

		// Test odd number
		let b = Goldilocks::new(11);
		let half_b = b.halve();
		assert_eq!((half_b + half_b).as_canonical_u64(), 11);
	}

	#[test]
	fn test_canonical_reduction() {
		// P should reduce to 0
		let p = Goldilocks::new(P);
		assert_eq!(p.as_canonical_u64(), 0);

		// P + 1 should reduce to 1
		let p_plus_1 = Goldilocks::new(P) + Goldilocks::ONE;
		assert_eq!(p_plus_1.as_canonical_u64(), 1);
	}

	#[test]
	fn test_multiplication_large() {
		// Test multiplication that requires reduction
		let a = Goldilocks::new(1 << 32);
		let b = Goldilocks::new(1 << 32);
		let result = a * b;
		// (2^32)^2 = 2^64 = 2^32 - 1 mod P
		assert_eq!(result.as_canonical_u64(), (1u64 << 32) - 1);
	}

	#[test]
	fn test_sum() {
		let values =
			[Goldilocks::new(1), Goldilocks::new(2), Goldilocks::new(3), Goldilocks::new(4)];
		let sum: Goldilocks = values.iter().copied().sum();
		assert_eq!(sum.as_canonical_u64(), 10);
	}
}
