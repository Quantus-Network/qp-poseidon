//! Regression tests for audit finding #96399 "Public amount conversion panics on
//! oversized inputs".
//!
//! Converting an untrusted amount must be a recoverable validation failure, not a
//! panic: a single oversized value in a batch would otherwise unwind (or abort under
//! panic=abort) instead of being rejected cleanly.

use std::panic::{catch_unwind, AssertUnwindSafe};

use qp_poseidon_core::serialization::{
	try_felt_to_quantized_u128, try_u128_to_quantized_felt, AMOUNT_QUANTIZATION_FACTOR,
};

/// Largest amount whose quantized value still fits a 32-bit limb.
fn max_supported_amount() -> u128 {
	(u32::MAX as u128) * AMOUNT_QUANTIZATION_FACTOR
}

#[test]
fn oversized_amount_is_rejected_without_panicking() {
	let oversized = max_supported_amount() + AMOUNT_QUANTIZATION_FACTOR;

	let outcome = catch_unwind(AssertUnwindSafe(|| try_u128_to_quantized_felt(oversized)));

	let result = outcome.expect("conversion of an oversized amount must not panic");
	assert!(result.is_err(), "oversized amount should be rejected with a recoverable error");
}

#[test]
fn valid_amounts_round_trip() {
	for amount in [0u128, AMOUNT_QUANTIZATION_FACTOR, max_supported_amount()] {
		let felt = try_u128_to_quantized_felt(amount).expect("in-range amount should convert");
		let back = try_felt_to_quantized_u128(felt).expect("round trip");
		assert_eq!(back, amount - (amount % AMOUNT_QUANTIZATION_FACTOR));
	}
}
