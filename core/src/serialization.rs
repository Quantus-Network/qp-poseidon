//! Serialization utilities for Goldilocks field elements.
//!
//! This module provides functions to convert between bytes and field elements.
//!
//! ## API Overview
//!
//! - `bytes_to_felts` / `felts_to_bytes` - Variable-length byte arrays (4 bytes/felt + terminator)
//!   collision-resistant)
//! - `digest_to_bytes` / `bytes_to_digest` - Hash output (4 felts ↔ 32 bytes, 8 bytes/felt)
//!
//! The 4-bytes/felt encoding is injective (collision-resistant) for arbitrary byte data.
//! The 8-bytes/felt encoding is used only for hash outputs (which are already field elements).

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

/// Number of field elements for a 32-byte digest (8 bytes per felt).
pub const DIGEST_NUM_FELTS: usize = 8;

/// Bytes per field element in the standard encoding.
pub const BYTES_PER_FELT: usize = 4;

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

// ============================================================================
// Integer conversions (u64, u128)
// ============================================================================

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

// ============================================================================
// Variable-length bytes <-> felts
// ============================================================================

/// Convert variable-length bytes to field elements.
///
/// Uses 4 bytes per field element with a terminator marker (0x01) appended,
/// ensuring different-length inputs always produce different field element sequences.
///
/// # Example
/// ```
/// use qp_poseidon_core::serialization::bytes_to_felts;
/// let felts = bytes_to_felts(b"hello");
/// assert_eq!(felts.len(), 2); // 5 bytes + terminator = 6 bytes -> ceil(6/4) = 2 felts
/// ```
pub fn bytes_to_felts(input: &[u8]) -> Vec<Goldilocks> {
	bytes_to_u64s(input).into_iter().map(from_u64).collect()
}

/// Convert field elements back to variable-length bytes.
///
/// Inverse of `bytes_to_felts`. Returns an error if the input doesn't have
/// a valid terminator marker.
pub fn felts_to_bytes(input: &[Goldilocks]) -> Result<Vec<u8>, &'static str> {
	let u64s: Vec<u64> = input.iter().map(|f| to_u64(*f)).collect();
	u64s_to_bytes(&u64s)
}

/// Convert a string to field elements.
pub fn string_to_felts(input: &str) -> Vec<Goldilocks> {
	bytes_to_felts(input.as_bytes())
}

// ============================================================================
// Core u64-based functions (field-type agnostic)
// ============================================================================

/// Convert variable-length bytes to u64 values (4 bytes per element + terminator).
pub fn bytes_to_u64s(input: &[u8]) -> Vec<u64> {
	let input_len = input.len();
	let len_with_marker = input_len + 1;
	let padding_needed = (BYTES_PER_FELT - (len_with_marker % BYTES_PER_FELT)) % BYTES_PER_FELT;
	let final_padded_size = len_with_marker + padding_needed;
	let num_elements = final_padded_size / BYTES_PER_FELT;

	let mut padded_input = Vec::<u8>::with_capacity(final_padded_size);
	let mut out = Vec::<u64>::with_capacity(num_elements);

	padded_input.extend_from_slice(input);
	padded_input.push(1u8); // terminator marker
	padded_input.resize(final_padded_size, 0u8);

	for chunk in padded_input.chunks_exact(BYTES_PER_FELT) {
		let bytes = [chunk[0], chunk[1], chunk[2], chunk[3]];
		out.push(u32::from_le_bytes(bytes) as u64);
	}

	out
}

/// Convert u64 values back to bytes (inverse of `bytes_to_u64s`).
pub fn u64s_to_bytes(input: &[u64]) -> Result<Vec<u8>, &'static str> {
	if input.is_empty() {
		return Err("Expected non-empty input");
	}

	let mut words: Vec<[u8; BYTES_PER_FELT]> = Vec::with_capacity(input.len());
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
	for j in 0..BYTES_PER_FELT {
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

/// Convert 32-byte digest to 8 u64 values (4 bytes per element).
pub fn digest_to_u64s(input: &BytesDigest) -> [u64; DIGEST_NUM_FELTS] {
	let mut out = [0u64; DIGEST_NUM_FELTS];
	for (i, chunk) in input.chunks(BYTES_PER_FELT).enumerate() {
		let mut bytes = [0u8; BYTES_PER_FELT];
		bytes[..chunk.len()].copy_from_slice(chunk);
		out[i] = u32::from_le_bytes(bytes) as u64;
	}
	out
}

/// Convert 8 u64 values to 32-byte digest (inverse of `digest_to_u64s`).
pub fn u64s_to_digest(input: &[u64; DIGEST_NUM_FELTS]) -> BytesDigest {
	let mut bytes = [0u8; 32];
	for (i, v) in input.iter().enumerate() {
		let start = i * BYTES_PER_FELT;
		let end = start + BYTES_PER_FELT;
		bytes[start..end].copy_from_slice(&(*v as u32).to_le_bytes());
	}
	bytes
}

// ============================================================================
// Digest serialization (4 felts <-> 32 bytes)
// ============================================================================

/// Convert a digest (4 field elements) to 32 bytes.
///
/// Each field element contributes 8 bytes (its full u64 representation).
/// Use this to serialize hash outputs for storage or transmission.
pub fn digest_to_bytes(input: &[Goldilocks; POSEIDON2_OUTPUT]) -> BytesDigest {
	let mut bytes = [0u8; 32];
	for (i, v) in input.iter().enumerate().take(POSEIDON2_OUTPUT) {
		let start = i * 8;
		let end = start + 8;
		bytes[start..end].copy_from_slice(&to_u64(*v).to_le_bytes());
	}
	bytes
}

/// Convert 32 bytes to a digest (4 field elements).
///
/// Each 8-byte chunk becomes one field element.
/// Use this to deserialize hash outputs from storage.
pub fn bytes_to_digest<F>(input: &BytesDigest) -> [F; POSEIDON2_OUTPUT]
where
	F: p3_field::PrimeCharacteristicRing,
{
	core::array::from_fn(|i| {
		let start = i * 8;
		let bytes: [u8; 8] = input[start..start + 8].try_into().expect("8 bytes");
		F::from_u64(u64::from_le_bytes(bytes))
	})
}

// ============================================================================
// Compact encoding (7 bytes/felt) for variable-length data
// ============================================================================

use crate::COMPACT_BYTES_PER_FELT;

/// Convert variable-length bytes to field elements using compact encoding (7 bytes/felt).
///
/// Unlike `bytes_to_felts` (4 bytes/felt + terminator), this packs 7 bytes into each
/// Goldilocks field element. Input is zero-padded to align to 7 bytes.
///
/// We use 7 bytes (not 8) to ensure all values are less than the Goldilocks field
/// order (p = 2^64 - 2^32 + 1). With 8 bytes, values >= p would be reduced mod p,
/// causing collisions (e.g., byte encoding of p would equal 0).
///
/// **Note:** This encoding is NOT injective for variable-length data (inputs of
/// different lengths could produce the same felts if padding aligns). The caller
/// must prepend a length field to ensure injectivity.
///
/// # Example
/// ```
/// use qp_poseidon_core::serialization::bytes_to_felts_compact;
/// let felts = bytes_to_felts_compact(b"hello world!!"); // 13 bytes -> 2 felts
/// assert_eq!(felts.len(), 2);
/// ```
pub fn bytes_to_felts_compact(input: &[u8]) -> Vec<Goldilocks> {
	bytes_to_u64s_compact(input).into_iter().map(from_u64).collect()
}

/// Convert variable-length bytes to u64 values using compact encoding (7 bytes per element).
///
/// Input is zero-padded to align to 7 bytes. Each 7-byte chunk is converted to a u64
/// using little-endian byte order (with the high byte always 0).
pub fn bytes_to_u64s_compact(input: &[u8]) -> Vec<u64> {
	if input.is_empty() {
		return Vec::new();
	}

	let num_elements = input.len().div_ceil(COMPACT_BYTES_PER_FELT);
	let padded_len = num_elements * COMPACT_BYTES_PER_FELT;

	let mut padded = Vec::with_capacity(padded_len);
	padded.extend_from_slice(input);
	padded.resize(padded_len, 0u8);

	let mut out = Vec::with_capacity(num_elements);
	for chunk in padded.chunks_exact(COMPACT_BYTES_PER_FELT) {
		// Convert 7 bytes to u64 (little-endian, high byte is 0)
		let mut bytes = [0u8; 8];
		bytes[..COMPACT_BYTES_PER_FELT].copy_from_slice(chunk);
		out.push(u64::from_le_bytes(bytes));
	}

	out
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
	fn test_bytes_to_felts_round_trip() {
		let test_cases =
			vec![vec![], vec![0u8], vec![1u8, 2u8, 3u8], vec![255u8; 32], b"hello world".to_vec()];

		for original in test_cases {
			let felts = bytes_to_felts(&original);
			let reconstructed = felts_to_bytes(&felts).unwrap();
			assert_eq!(original, reconstructed);
		}
	}

	#[test]
	fn test_bytes_to_felts_adds_terminator() {
		let input = [1u8, 2, 3, 4];
		let felts = bytes_to_felts(&input);
		assert_eq!(felts.len(), 2);

		let empty: [u8; 0] = [];
		let felts_empty = bytes_to_felts(&empty);
		assert_eq!(felts_empty.len(), 1);
	}

	#[test]
	fn test_different_lengths_produce_different_felts() {
		let input1 = [0x01, 0x02, 0x03];
		let input2 = [0x01, 0x02, 0x03, 0x00];

		let felts1 = bytes_to_felts(&input1);
		let felts2 = bytes_to_felts(&input2);

		assert_ne!(felts1, felts2, "Different length inputs should produce different felts");
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
		let just_over = (BIT_32_LIMB_MASK as u128 + 1) * AMOUNT_QUANTIZATION_FACTOR;
		let _ = u128_to_quantized_felt(just_over);
	}

	#[test]
	fn test_malformed_bytes_input_error_cases() {
		let malformed_cases: Vec<Vec<Goldilocks>> = vec![
			vec![Goldilocks::from_int(0x12345678_i64), Goldilocks::from_int(0x1ABCDEF0_i64)],
			vec![Goldilocks::from_int(0x12345678_i64), Goldilocks::from_int(0x00000002_i64)],
		];

		for malformed_felts in &malformed_cases {
			let result = felts_to_bytes(malformed_felts);
			assert!(result.is_err(), "Malformed input should return error: {:?}", malformed_felts);
		}
	}

	#[test]
	fn test_felt_width_error_handling() {
		let invalid_felts =
			[Goldilocks::from_int(0x1_0000_0000_i64), Goldilocks::from_int(0xFFFFFFFF_i64)];
		let result = try_felts_to_u64(invalid_felts);
		assert!(result.is_err(), "Expected felt width error for invalid felts");
	}

	#[test]
	fn test_digest_4felts_round_trip() {
		let original = [42u8; 32];
		let felts: [Goldilocks; POSEIDON2_OUTPUT] = bytes_to_digest(&original);
		let reconstructed = digest_to_bytes(&felts);
		assert_eq!(original, reconstructed);
	}

	#[test]
	fn test_digest_4felts_uses_4_felts() {
		let original = [42u8; 32];
		let felts: [Goldilocks; POSEIDON2_OUTPUT] = bytes_to_digest(&original);
		assert_eq!(felts.len(), POSEIDON2_OUTPUT);
	}

	#[test]
	fn test_bytes_to_felts_compact_sizing() {
		// Empty input -> empty output
		let empty: [u8; 0] = [];
		assert_eq!(bytes_to_felts_compact(&empty).len(), 0);

		// 1-7 bytes -> 1 felt (7 bytes per felt)
		assert_eq!(bytes_to_felts_compact(&[1u8]).len(), 1);
		assert_eq!(bytes_to_felts_compact(&[1u8; 7]).len(), 1);

		// 8-14 bytes -> 2 felts
		assert_eq!(bytes_to_felts_compact(&[1u8; 8]).len(), 2);
		assert_eq!(bytes_to_felts_compact(&[1u8; 14]).len(), 2);

		// 32 bytes -> 5 felts (ceil(32/7) = 5)
		assert_eq!(bytes_to_felts_compact(&[1u8; 32]).len(), 5);
	}

	#[test]
	fn test_bytes_to_felts_compact_content() {
		// Verify the encoding is correct (7 bytes per felt)
		let input = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
		let felts = bytes_to_felts_compact(&input);
		assert_eq!(felts.len(), 1);

		// Should be little-endian u64 with high byte = 0
		let mut bytes = [0u8; 8];
		bytes[..7].copy_from_slice(&input);
		let expected = u64::from_le_bytes(bytes);
		assert_eq!(felts[0], Goldilocks::from_int(expected));
	}

	#[test]
	fn test_bytes_to_felts_compact_vs_injective() {
		// Compact encoding should produce fewer felts than injective encoding
		let input = [42u8; 32];
		let compact = bytes_to_felts_compact(&input);
		let injective = bytes_to_felts(&input);

		// 32 bytes: compact = 5 felts (ceil(32/7)), injective = 9 felts (8 data + 1 terminator)
		assert_eq!(compact.len(), 5);
		assert_eq!(injective.len(), 9);
	}
}
