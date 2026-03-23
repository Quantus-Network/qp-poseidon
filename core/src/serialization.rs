//! Serialization utilities for Goldilocks field elements.
//!
//! This module provides two layers of functions:
//! 1. Core functions that work with `[u64; N]` arrays (field-type agnostic)
//! 2. Wrapper functions for `p3_goldilocks::Goldilocks` (Plonky3)
//!
//! Other crates (e.g., qp-zk-circuits) can use the core `_u64` functions
//! and convert to/from their own field types, avoiding code duplication.

use alloc::{string::String, vec::Vec};
use p3_field::{integers::QuotientMap, PrimeField64};
use p3_goldilocks::Goldilocks;
use qp_poseidon_constants::POSEIDON2_OUTPUT;

const BIT_32_LIMB_MASK: u64 = 0xFFFF_FFFF;

pub type BytesDigest = [u8; 32];

pub const DIGEST_BYTES_PER_ELEMENT: usize = 8;
pub const FELTS_PER_U128: usize = 4;
pub const FELTS_PER_U64: usize = 2;
pub const AMOUNT_QUANTIZATION_FACTOR: u128 = 10_000_000_000u128; // 10^10

/// Number of field elements for a 32-byte digest with safe encoding (4 bytes/felt).
pub const SAFE_DIGEST_NUM_FELTS: usize = 8;

// ============================================================================
// Internal helpers for Goldilocks conversion
// ============================================================================

#[inline]
fn from_u64(x: u64) -> Goldilocks {
	Goldilocks::from_int(x)
}

#[inline]
fn to_u64(f: Goldilocks) -> u64 {
	f.as_canonical_u64()
}

#[inline]
fn as_32_bit_limb(felt: Goldilocks, index: usize) -> Result<u64, String> {
	let v = to_u64(felt);
	as_32_bit_limb_u64(v, index)
}

#[inline]
fn as_32_bit_limb_u64(v: u64, index: usize) -> Result<u64, String> {
	if v <= BIT_32_LIMB_MASK {
		Ok(v)
	} else {
		Err(alloc::format!("Felt at index {} with value {} exceeds 32-bit limb size", index, v))
	}
}

pub fn u128_to_felts(num: u128) -> [Goldilocks; FELTS_PER_U128] {
	let mut result = [from_u64(0); FELTS_PER_U128];
	for (i, value) in result.iter_mut().enumerate() {
		let shift = 96 - 32 * i;
		*value = from_u64(((num >> shift) & BIT_32_LIMB_MASK as u128) as u64);
	}
	result
}

pub fn u128_to_quantized_felt(num: u128) -> Goldilocks {
	let quantized = num / AMOUNT_QUANTIZATION_FACTOR;
	assert!(
		quantized <= BIT_32_LIMB_MASK as u128,
		"Quantized value {} exceeds 32-bit limb size",
		quantized
	);
	from_u64(quantized as u64)
}

pub fn u64_to_felts(num: u64) -> [Goldilocks; FELTS_PER_U64] {
	[from_u64((num >> 32) & BIT_32_LIMB_MASK), from_u64(num & BIT_32_LIMB_MASK)]
}

pub fn try_felts_to_u128(felts: [Goldilocks; FELTS_PER_U128]) -> Result<u128, String> {
	let mut out = 0u128;
	for (i, felt) in felts.into_iter().enumerate() {
		let limb = as_32_bit_limb(felt, i)?;
		out |= (limb as u128) << (96 - 32 * i);
	}
	Ok(out)
}

pub fn try_felt_to_quantized_u128(felt: Goldilocks) -> Result<u128, String> {
	let v = as_32_bit_limb(felt, 0)? as u128;
	Ok(v * AMOUNT_QUANTIZATION_FACTOR)
}

pub fn try_felts_to_u64(felts: [Goldilocks; FELTS_PER_U64]) -> Result<u64, String> {
	let mut out = 0u64;
	for (i, felt) in felts.into_iter().enumerate() {
		let limb = as_32_bit_limb(felt, i)?;
		out |= limb << (32 - 32 * i);
	}
	Ok(out)
}

/// Injective encoding: 4 bytes -> 1 felt, with terminator marker for collision resistance.
pub fn injective_bytes_to_felts(input: &[u8]) -> Vec<Goldilocks> {
	injective_bytes_to_u64s(input).into_iter().map(from_u64).collect()
}

/// Non-injective encoding: 8 bytes -> 1 felt, zero-padded.
///
/// NOT collision-resistant for variable-length inputs due to:
/// 1. Zero-padding: `[0x01]` and `[0x01, 0, 0, 0, 0, 0, 0, 0]` encode identically
/// 2. Modular reduction: u64 values >= 0xFFFFFFFF00000001 (Goldilocks order) collide with their
///    reduction mod p (~2^32 such values exist)
///
/// Safe for self-describing structures (e.g., length-prefixed data, trie nodes).
pub fn non_injective_bytes_to_felts(input: &[u8]) -> Vec<Goldilocks> {
	const BYTES_PER_ELEMENT: usize = 8;

	let padded_size = input.len().div_ceil(BYTES_PER_ELEMENT) * BYTES_PER_ELEMENT;
	let num_elements = padded_size / BYTES_PER_ELEMENT;

	let mut out = Vec::<Goldilocks>::with_capacity(num_elements);

	let full_chunks = input.len() / BYTES_PER_ELEMENT;
	for i in 0..full_chunks {
		let start = i * BYTES_PER_ELEMENT;
		let bytes: [u8; 8] = input[start..start + BYTES_PER_ELEMENT].try_into().unwrap();
		out.push(from_u64(u64::from_le_bytes(bytes)));
	}

	let remaining = input.len() % BYTES_PER_ELEMENT;
	if remaining > 0 {
		let mut bytes = [0u8; BYTES_PER_ELEMENT];
		bytes[..remaining].copy_from_slice(&input[full_chunks * BYTES_PER_ELEMENT..]);
		out.push(from_u64(u64::from_le_bytes(bytes)));
	}

	out
}

// ============================================================================
// Core u64-based functions (field-type agnostic)
// ============================================================================

/// Convert 32-byte digest to 4 u64 values (8 bytes per element).
///
/// "Unsafe" because u64 values >= 0xFFFFFFFF00000001 (Goldilocks order) are reduced mod p
/// when converted to field elements, creating non-injective mappings.
/// Safe when input is a hash output (uniform distribution makes collisions negligible).
pub fn unsafe_digest_bytes_to_u64s(input: &BytesDigest) -> [u64; POSEIDON2_OUTPUT] {
	const BYTES_PER_ELEMENT: usize = 8;
	let mut out = [0u64; POSEIDON2_OUTPUT];

	for (chunk, out_elem) in input.chunks(BYTES_PER_ELEMENT).zip(out.iter_mut()) {
		let mut bytes = [0u8; BYTES_PER_ELEMENT];
		bytes[..chunk.len()].copy_from_slice(chunk);
		*out_elem = u64::from_le_bytes(bytes);
	}
	out
}

/// Convert 32-byte digest to 8 u64 values using safe 4-bytes-per-element encoding.
///
/// Unlike `unsafe_digest_bytes_to_u64s` (8 bytes/element), this uses 4 bytes per element,
/// ensuring all values fit within u32 range with no modular reduction risk.
/// Unlike `injective_bytes_to_u64s`, this has no terminator since the length is fixed.
pub fn safe_digest_bytes_to_u64s(input: &BytesDigest) -> [u64; SAFE_DIGEST_NUM_FELTS] {
	const BYTES_PER_ELEMENT: usize = 4;
	let mut out = [0u64; SAFE_DIGEST_NUM_FELTS];

	for (i, chunk) in input.chunks(BYTES_PER_ELEMENT).enumerate() {
		let mut bytes = [0u8; BYTES_PER_ELEMENT];
		bytes[..chunk.len()].copy_from_slice(chunk);
		out[i] = u32::from_le_bytes(bytes) as u64;
	}
	out
}

/// Convert 4 u64 values to 32-byte digest (inverse of `unsafe_digest_bytes_to_u64s`).
pub fn digest_u64s_to_bytes(input: &[u64; POSEIDON2_OUTPUT]) -> BytesDigest {
	let mut bytes = [0u8; 32];
	for (i, v) in input.iter().enumerate().take(POSEIDON2_OUTPUT) {
		let start = i * 8;
		let end = start + 8;
		bytes[start..end].copy_from_slice(&v.to_le_bytes());
	}
	bytes
}

/// Convert 8 u64 values to 32-byte digest (inverse of `safe_digest_bytes_to_u64s`).
pub fn safe_digest_u64s_to_bytes(input: &[u64; SAFE_DIGEST_NUM_FELTS]) -> BytesDigest {
	let mut bytes = [0u8; 32];
	for (i, v) in input.iter().enumerate() {
		let start = i * 4;
		let end = start + 4;
		bytes[start..end].copy_from_slice(&(*v as u32).to_le_bytes());
	}
	bytes
}

/// Injective encoding: 4 bytes -> 1 u64, with terminator marker for collision resistance.
pub fn injective_bytes_to_u64s(input: &[u8]) -> Vec<u64> {
	const BYTES_PER_ELEMENT: usize = 4;

	let input_len = input.len();
	let len_with_marker = input_len + 1;
	let padding_needed =
		(BYTES_PER_ELEMENT - (len_with_marker % BYTES_PER_ELEMENT)) % BYTES_PER_ELEMENT;
	let final_padded_size = len_with_marker + padding_needed;
	let num_elements = final_padded_size / BYTES_PER_ELEMENT;

	let mut padded_input = Vec::<u8>::with_capacity(final_padded_size);
	let mut out = Vec::<u64>::with_capacity(num_elements);

	padded_input.extend_from_slice(input);
	padded_input.push(1u8);
	padded_input.resize(final_padded_size, 0u8);

	for chunk in padded_input.chunks_exact(BYTES_PER_ELEMENT) {
		let bytes = [chunk[0], chunk[1], chunk[2], chunk[3]];
		out.push(u32::from_le_bytes(bytes) as u64);
	}

	out
}

/// Inverse of `injective_bytes_to_u64s`.
pub fn try_injective_u64s_to_bytes(input: &[u64]) -> Result<Vec<u8>, &'static str> {
	if input.is_empty() {
		return Err("Expected non-empty input");
	}

	const BYTES_PER_ELEMENT: usize = 4;
	let mut words: Vec<[u8; BYTES_PER_ELEMENT]> = Vec::with_capacity(input.len());
	for (i, &v) in input.iter().enumerate() {
		let _ = as_32_bit_limb_u64(v, i).map_err(|_| "Felt value exceeds 32 bits")?;
		words.push((v as u32).to_le_bytes());
	}

	let mut out = Vec::new();

	// If original input was u32 aligned, drop the last word
	if words.last() == Some(&[1, 0, 0, 0]) {
		for w in &words[..words.len() - 1] {
			out.extend_from_slice(w);
		}
		return Ok(out);
	}

	// The first n-1 words are normal
	for w in &words[..words.len() - 1] {
		out.extend_from_slice(w);
	}

	// The last word must remove the inline terminator
	let last = words.last().unwrap();
	let mut marker_idx = None;
	for j in 0..BYTES_PER_ELEMENT {
		if last[j] == 1 && last[j + 1..].iter().all(|&b| b == 0) {
			marker_idx = Some(j);
			break;
		}
	}
	match marker_idx {
		Some(j) => {
			out.extend_from_slice(&last[..j]);
			Ok(out)
		},
		None => Err("Malformed input: missing inline terminator in last felt"),
	}
}

// ============================================================================
// Goldilocks wrapper functions (for Plonky3 / Substrate)
// ============================================================================

/// Convert 32-byte digest to field elements.
///
/// "Unsafe" because u64 values >= 0xFFFFFFFF00000001 (Goldilocks order) are reduced mod p,
/// creating non-injective mappings. Safe when input is a hash output (uniform distribution
/// makes collisions negligible in practice).
pub fn unsafe_digest_bytes_to_felts(input: &BytesDigest) -> [Goldilocks; POSEIDON2_OUTPUT] {
	let u64s = unsafe_digest_bytes_to_u64s(input);
	[from_u64(u64s[0]), from_u64(u64s[1]), from_u64(u64s[2]), from_u64(u64s[3])]
}

/// Convert 32-byte digest to 8 field elements using safe 4-bytes-per-felt encoding.
///
/// Unlike `unsafe_digest_bytes_to_felts` (8 bytes/felt), this uses 4 bytes per felt,
/// ensuring all values fit within u32 range with no modular reduction risk.
/// Unlike `injective_bytes_to_felts`, this has no terminator since the length is fixed.
pub fn safe_digest_bytes_to_felts(input: &BytesDigest) -> [Goldilocks; SAFE_DIGEST_NUM_FELTS] {
	let u64s = safe_digest_bytes_to_u64s(input);
	core::array::from_fn(|i| from_u64(u64s[i]))
}

/// Convert field elements to 32-byte digest (inverse of `unsafe_digest_bytes_to_felts`).
pub fn digest_felts_to_bytes(input: &[Goldilocks; POSEIDON2_OUTPUT]) -> BytesDigest {
	let u64s = [to_u64(input[0]), to_u64(input[1]), to_u64(input[2]), to_u64(input[3])];
	digest_u64s_to_bytes(&u64s)
}

/// Convert 8 field elements to 32-byte digest (inverse of `safe_digest_bytes_to_felts`).
pub fn safe_digest_felts_to_bytes(input: &[Goldilocks; SAFE_DIGEST_NUM_FELTS]) -> BytesDigest {
	let u64s: [u64; SAFE_DIGEST_NUM_FELTS] = core::array::from_fn(|i| to_u64(input[i]));
	safe_digest_u64s_to_bytes(&u64s)
}

/// Inverse of `injective_bytes_to_felts`.
pub fn try_injective_felts_to_bytes(input: &[Goldilocks]) -> Result<Vec<u8>, &'static str> {
	let u64s: Vec<u64> = input.iter().map(|f| to_u64(*f)).collect();
	try_injective_u64s_to_bytes(&u64s)
}

/// Convert a string to field elements using injective encoding.
pub fn injective_string_to_felts(input: &str) -> Vec<Goldilocks> {
	injective_bytes_to_felts(input.as_bytes())
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloc::{format, vec};

	#[test]
	fn test_u64_round_trip() {
		let test_values = vec![
			0u64,
			1u64,
			0xFFFFFFFFu64,
			0x1234567890ABCDEFu64,
			u64::MAX,
			0x8000000000000000u64,
			0x123456789ABCDEFu64,
		];

		for &original in &test_values {
			let felts = u64_to_felts(original);
			let reconstructed =
				try_felts_to_u64(felts).expect(&format!("Failed for input: {}", original));
			assert_eq!(original, reconstructed);
		}
	}

	#[test]
	fn test_u128_round_trip() {
		let test_values =
			vec![0u128, 1u128, 0xFFFFFFFFu128, 0x123456789ABCDEF0123456789ABCDEFu128, u128::MAX];

		for &original in &test_values {
			let felts = u128_to_felts(original);
			let reconstructed =
				try_felts_to_u128(felts).expect(&format!("Failed for input: {}", original));
			assert_eq!(original, reconstructed);
		}
	}

	#[test]
	fn test_injective_bytes_round_trip() {
		let test_cases =
			vec![vec![], vec![0u8], vec![1u8, 2u8, 3u8], vec![255u8; 32], b"hello world".to_vec()];

		for original in test_cases {
			let felts = injective_bytes_to_felts(&original);
			let reconstructed = try_injective_felts_to_bytes(&felts).unwrap();
			assert_eq!(original, reconstructed);
		}
	}

	#[test]
	fn test_digest_round_trip() {
		let original = [42u8; 32];
		let felts = unsafe_digest_bytes_to_felts(&original);
		let reconstructed = digest_felts_to_bytes(&felts);
		assert_eq!(original, reconstructed);
	}

	#[test]
	fn test_quantized_round_trip() {
		let test_values = vec![0u128, 1_000_000_000_000u128, 21_000_000_000_000_000_000u128];

		for &original in &test_values {
			let felt = u128_to_quantized_felt(original);
			let reconstructed = try_felt_to_quantized_u128(felt).unwrap();
			let expected = original - (original % AMOUNT_QUANTIZATION_FACTOR);
			assert_eq!(reconstructed, expected);
		}
	}

	#[test]
	#[should_panic(expected = "exceeds 32-bit limb size")]
	fn test_u128_to_quantized_felt_panics_when_quantized_exceeds_32bit() {
		// When quantized value exceeds 32-bit, the function should panic
		let just_over = (BIT_32_LIMB_MASK as u128 + 1) * AMOUNT_QUANTIZATION_FACTOR;
		let _ = u128_to_quantized_felt(just_over);
	}

	#[test]
	fn test_quantized_precision_loss_examples() {
		// Verify that quantization properly floors to quantization units
		let f = AMOUNT_QUANTIZATION_FACTOR;

		let cases = vec![
			(f - 1, 0),                   // below one unit -> rounds to 0
			(f + 1, f),                   // loses 1 unit
			(123 * f + 1, 123 * f),       // tiny remainder
			(123 * f + (f / 2), 123 * f), // bigger remainder
			(123 * f + (f - 1), 123 * f), // maximal remainder
			((BIT_32_LIMB_MASK as u128) * f + (f - 1), (BIT_32_LIMB_MASK as u128) * f), /* highest with remainder */
		];

		for (original, expected) in cases {
			let felt = u128_to_quantized_felt(original);
			let reconstructed = try_felt_to_quantized_u128(felt).expect("reconstruct");
			assert_eq!(reconstructed, expected, "floor-to-quantization failed for {original}");
			assert!(reconstructed <= original);
		}
	}

	#[test]
	fn test_malformed_bytes_input_error_cases() {
		// Test malformed felts that don't have proper terminator
		let malformed_cases: Vec<Vec<Goldilocks>> = vec![
			// No terminator at all - all non-terminator values
			vec![Goldilocks::from_int(0x12345678_i64), Goldilocks::from_int(0x1ABCDEF0_i64)],
			// Wrong terminator pattern - should be [1,0,0,0] not [2,0,0,0]
			vec![
				Goldilocks::from_int(0x12345678_i64),
				Goldilocks::from_int(0x00000002_i64), // should be 1 followed by zeros
			],
			// All high values that don't form proper termination
			vec![Goldilocks::from_int(0x7FFFFFFF_i64), Goldilocks::from_int(0x7FFFFFFF_i64)],
		];

		for malformed_felts in &malformed_cases {
			let result = try_injective_felts_to_bytes(malformed_felts);
			assert!(result.is_err(), "Malformed input should return error: {:?}", malformed_felts);
		}
	}

	#[test]
	fn test_felt_width_error_handling() {
		// Create felts that exceed 32-bit limb size for u64 conversion
		let invalid_felts =
			[Goldilocks::from_int(0x1_0000_0000_i64), Goldilocks::from_int(0xFFFFFFFF_i64)];
		let result = try_felts_to_u64(invalid_felts);
		assert!(result.is_err(), "Expected felt width error for invalid felts");

		// Create felts that exceed 32-bit limb size for u128 conversion
		let invalid_felts_u128 = [
			Goldilocks::from_int(0x1_0000_0000_i64),
			Goldilocks::from_int(0x00000001_i64),
			Goldilocks::from_int(0xFFFFFFFF_i64),
			Goldilocks::from_int(0x00000001_i64),
		];
		let result = try_felts_to_u128(invalid_felts_u128);
		assert!(result.is_err(), "Expected felt width error for invalid felts in u128");
	}

	// ==================== non_injective_bytes_to_felts tests ====================

	#[test]
	fn test_non_injective_encoding_basic() {
		use p3_field::PrimeField64;
		// Test basic encoding: 8 bytes -> 1 felt
		let input = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
		let felts = non_injective_bytes_to_felts(&input);
		assert_eq!(felts.len(), 1);

		// Verify the encoding is little-endian u64
		let expected = u64::from_le_bytes(input);
		assert_eq!(felts[0].as_canonical_u64(), expected);
	}

	#[test]
	fn test_non_injective_encoding_partial_block() {
		use p3_field::PrimeField64;
		// Test partial block: 5 bytes -> 1 felt (zero-padded)
		let input = [0x01, 0x02, 0x03, 0x04, 0x05];
		let felts = non_injective_bytes_to_felts(&input);
		assert_eq!(felts.len(), 1);

		// Should be zero-padded to 8 bytes
		let mut padded = [0u8; 8];
		padded[..5].copy_from_slice(&input);
		let expected = u64::from_le_bytes(padded);
		assert_eq!(felts[0].as_canonical_u64(), expected);
	}

	#[test]
	fn test_non_injective_encoding_multiple_blocks() {
		// 16 bytes -> 2 felts
		let input: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
		let felts = non_injective_bytes_to_felts(&input);
		assert_eq!(felts.len(), 2);
	}

	#[test]
	fn test_non_injective_encoding_empty() {
		let input: [u8; 0] = [];
		let felts = non_injective_bytes_to_felts(&input);
		assert_eq!(felts.len(), 0);
	}

	#[test]
	fn test_non_injective_known_collision() {
		// Document the known collision behavior:
		// Two different-length inputs that differ only in trailing zeros
		// will produce the same encoding (this is expected and documented).
		let input1 = [0x01, 0x02, 0x03];
		let input2 = [0x01, 0x02, 0x03, 0x00, 0x00];

		let felts1 = non_injective_bytes_to_felts(&input1);
		let felts2 = non_injective_bytes_to_felts(&input2);

		// Both produce the same felt because zero-padding is applied
		assert_eq!(felts1, felts2, "Non-injective encoding should collide on trailing zeros");
	}

	#[test]
	fn test_non_injective_vs_injective_size_comparison() {
		// Non-injective uses 8 bytes per felt, injective uses 4 bytes per felt
		// So non-injective should produce roughly half the felts
		let input = [0u8; 32]; // 32 bytes

		let injective_felts = injective_bytes_to_felts(&input);
		let non_injective_felts = non_injective_bytes_to_felts(&input);

		// Injective: 32 bytes + 1 terminator = 33 bytes -> ceil(33/4) = 9 felts
		// Non-injective: 32 bytes -> ceil(32/8) = 4 felts
		assert!(
			non_injective_felts.len() < injective_felts.len(),
			"Non-injective should produce fewer felts: {} vs {}",
			non_injective_felts.len(),
			injective_felts.len()
		);
	}
}
