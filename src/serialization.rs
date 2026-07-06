//! Serialization utilities for Goldilocks field elements.
//!
//! This module provides functions to convert between bytes and field elements.
//!
//! ## API Overview
//!
//! - `bytes_to_felts` / `bytes_to_felts_iter` / `felts_to_bytes` - Variable-length byte arrays
//!   (4 bytes/felt + terminator) collision-resistant)
//! - `digest_to_bytes` / `bytes_to_digest` - Hash output (4 felts ↔ 32 bytes, 8 bytes/felt)
//!
//! The 4-bytes/felt encoding is injective (collision-resistant) for arbitrary byte data.
//! The 8-bytes/felt encoding is used only for hash outputs (which are already field elements).

use alloc::{string::String, vec::Vec};

use crate::{
	goldilocks::{Goldilocks, P},
	poseidon2::POSEIDON2_OUTPUT,
};

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
	Goldilocks::from_u64(x)
}

/// Convert a raw u64 limb into a field element, rejecting non-canonical encodings.
///
/// Values `>= P` alias with `value - P` inside the field, so accepting them would
/// let byte-distinct inputs decode to the same field element (collision).
#[inline]
fn try_canonical_limb(x: u64, err: &'static str) -> Result<Goldilocks, &'static str> {
	if x < P {
		Ok(Goldilocks::from_u64(x))
	} else {
		Err(err)
	}
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

/// Lazily encode bytes into field elements (4 bytes/felt + terminator).
///
/// This is the single source of truth for the injective byte encoding. Use this
/// when you want to consume felts incrementally (e.g. sponge absorption) without
/// allocating a `Vec`. For an owned vector, use [`bytes_to_felts`].
pub fn bytes_to_felts_iter(input: &[u8]) -> impl Iterator<Item = Goldilocks> + '_ {
	bytes_to_u64s_iter(input).map(from_u64)
}

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
	bytes_to_felts_iter(input).collect()
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

/// Iterator over u64 limbs produced by the injective 4-byte encoding.
pub struct BytesToU64sIter<'a> {
	input: &'a [u8],
	pos: usize,
	emitted_terminator: bool,
}

impl<'a> Iterator for BytesToU64sIter<'a> {
	type Item = u64;

	fn next(&mut self) -> Option<Self::Item> {
		if self.pos + BYTES_PER_FELT <= self.input.len() {
			let chunk = &self.input[self.pos..self.pos + BYTES_PER_FELT];
			self.pos += BYTES_PER_FELT;
			let bytes = [chunk[0], chunk[1], chunk[2], chunk[3]];
			return Some(u32::from_le_bytes(bytes) as u64);
		}

		if self.emitted_terminator {
			return None;
		}

		self.emitted_terminator = true;
		let remainder = &self.input[self.pos..];
		let mut last = [0u8; BYTES_PER_FELT];
		last[..remainder.len()].copy_from_slice(remainder);
		last[remainder.len()] = 1u8;
		Some(u32::from_le_bytes(last) as u64)
	}
}

/// Lazily encode bytes into u64 limbs (4 bytes per element + terminator).
pub fn bytes_to_u64s_iter(input: &[u8]) -> BytesToU64sIter<'_> {
	BytesToU64sIter { input, pos: 0, emitted_terminator: false }
}

/// Convert variable-length bytes to u64 values (4 bytes per element + terminator).
pub fn bytes_to_u64s(input: &[u8]) -> Vec<u64> {
	bytes_to_u64s_iter(input).collect()
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
/// Each 8-byte chunk becomes one canonical field element.
/// Returns an error if any chunk encodes a value greater than or equal to the
/// Goldilocks modulus, since such values would alias with a canonical element.
/// Use this to deserialize hash outputs from storage.
pub fn bytes_to_digest(
	input: &BytesDigest,
) -> Result<[Goldilocks; POSEIDON2_OUTPUT], &'static str> {
	let mut out = [Goldilocks::ZERO; POSEIDON2_OUTPUT];
	for (i, felt) in out.iter_mut().enumerate() {
		let start = i * DIGEST_BYTES_PER_ELEMENT;
		let bytes: [u8; 8] = input[start..start + 8].try_into().expect("8 bytes");
		*felt = try_canonical_limb(
			u64::from_le_bytes(bytes),
			"Digest limb exceeds Goldilocks modulus",
		)?;
	}
	Ok(out)
}

// ============================================================================
// Compact encoding (8 bytes/felt) for variable-length data
// ============================================================================

/// Convert variable-length bytes to field elements using compact encoding (8 bytes/felt).
///
/// Unlike `bytes_to_felts` (4 bytes/felt + terminator), this uses the full
/// 8-byte capacity of each Goldilocks field element. Input is zero-padded to
/// align to 8 bytes.
///
/// **Note:** This encoding is NOT injective for variable-length data (inputs of
/// different lengths could produce the same felts if padding aligns). Use only when:
/// - The input length is fixed/known, OR
/// - Collision resistance is provided by other means (e.g., trie structure)
///
/// Returns an error if any 8-byte chunk encodes a value greater than or equal to
/// the Goldilocks modulus, since such values would alias with a canonical element.
///
/// # Example
/// ```
/// use qp_poseidon_core::serialization::bytes_to_felts_compact;
/// let felts = bytes_to_felts_compact(b"hello world!").unwrap(); // 12 bytes -> 2 felts
/// assert_eq!(felts.len(), 2);
/// ```
pub fn bytes_to_felts_compact(input: &[u8]) -> Result<Vec<Goldilocks>, &'static str> {
	bytes_to_u64s_compact(input)
		.into_iter()
		.map(|v| try_canonical_limb(v, "Compact encoding limb exceeds Goldilocks modulus"))
		.collect()
}

/// Convert variable-length bytes to u64 values using compact encoding (8 bytes per element).
///
/// Input is zero-padded to align to 8 bytes.
pub fn bytes_to_u64s_compact(input: &[u8]) -> Vec<u64> {
	if input.is_empty() {
		return Vec::new();
	}

	let padded_len = input.len().div_ceil(8) * 8;
	let num_elements = padded_len / 8;

	let mut padded = Vec::with_capacity(padded_len);
	padded.extend_from_slice(input);
	padded.resize(padded_len, 0u8);

	let mut out = Vec::with_capacity(num_elements);
	for chunk in padded.chunks_exact(8) {
		let bytes: [u8; 8] = chunk.try_into().expect("chunk is 8 bytes");
		out.push(u64::from_le_bytes(bytes));
	}

	out
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloc::vec;

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
			let reconstructed = try_felts_to_u64(felts)
				.unwrap_or_else(|_| panic!("Failed for input: {}", original));
			assert_eq!(original, reconstructed);
		}
	}

	#[test]
	fn test_u128_round_trip() {
		let test_values =
			vec![0u128, 1u128, 0xFFFFFFFFu128, 0x123456789ABCDEF0123456789ABCDEFu128, u128::MAX];

		for &original in &test_values {
			let felts = u128_to_felts(original);
			let reconstructed = try_felts_to_u128(felts)
				.unwrap_or_else(|_| panic!("Failed for input: {}", original));
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
	fn test_bytes_to_felts_iter_matches_collecting_api() {
		let test_cases = vec![
			vec![],
			vec![0u8],
			vec![1u8, 2, 3, 4],
			vec![1u8, 2, 3, 4, 5],
			vec![255u8; 32],
			b"hello world".to_vec(),
		];

		for input in test_cases {
			let collected = bytes_to_felts(&input);
			let iterated: Vec<_> = bytes_to_felts_iter(&input).collect();
			assert_eq!(collected, iterated, "input len {}", input.len());

			let collected_u64s = bytes_to_u64s(&input);
			let iterated_u64s: Vec<_> = bytes_to_u64s_iter(&input).collect();
			assert_eq!(collected_u64s, iterated_u64s, "input len {}", input.len());
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
			vec![Goldilocks::from_u64(0x12345678), Goldilocks::from_u64(0x1ABCDEF0)],
			vec![Goldilocks::from_u64(0x12345678), Goldilocks::from_u64(0x00000002)],
		];

		for malformed_felts in &malformed_cases {
			let result = felts_to_bytes(malformed_felts);
			assert!(result.is_err(), "Malformed input should return error: {:?}", malformed_felts);
		}
	}

	#[test]
	fn test_felt_width_error_handling() {
		let invalid_felts = [Goldilocks::from_u64(0x1_0000_0000), Goldilocks::from_u64(0xFFFFFFFF)];
		let result = try_felts_to_u64(invalid_felts);
		assert!(result.is_err(), "Expected felt width error for invalid felts");
	}

	#[test]
	fn test_digest_4felts_round_trip() {
		let original = [42u8; 32];
		let felts: [Goldilocks; POSEIDON2_OUTPUT] = bytes_to_digest(&original).unwrap();
		let reconstructed = digest_to_bytes(&felts);
		assert_eq!(original, reconstructed);
	}

	#[test]
	fn test_digest_4felts_uses_4_felts() {
		let original = [42u8; 32];
		let felts: [Goldilocks; POSEIDON2_OUTPUT] = bytes_to_digest(&original).unwrap();
		assert_eq!(felts.len(), POSEIDON2_OUTPUT);
	}

	#[test]
	fn test_bytes_to_felts_compact_sizing() {
		// Empty input -> empty output
		let empty: [u8; 0] = [];
		assert_eq!(bytes_to_felts_compact(&empty).unwrap().len(), 0);

		// 1-8 bytes -> 1 felt
		assert_eq!(bytes_to_felts_compact(&[1u8]).unwrap().len(), 1);
		assert_eq!(bytes_to_felts_compact(&[1u8; 8]).unwrap().len(), 1);

		// 9-16 bytes -> 2 felts
		assert_eq!(bytes_to_felts_compact(&[1u8; 9]).unwrap().len(), 2);
		assert_eq!(bytes_to_felts_compact(&[1u8; 16]).unwrap().len(), 2);

		// 32 bytes -> 4 felts (same as POSEIDON2_OUTPUT)
		assert_eq!(bytes_to_felts_compact(&[1u8; 32]).unwrap().len(), 4);
	}

	#[test]
	fn test_bytes_to_felts_compact_content() {
		// Verify the encoding is correct
		let input = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
		let felts = bytes_to_felts_compact(&input).unwrap();
		assert_eq!(felts.len(), 1);

		// Should be little-endian u64
		let expected = u64::from_le_bytes(input);
		assert_eq!(felts[0], Goldilocks::from_u64(expected));
	}

	#[test]
	fn test_bytes_to_felts_compact_rejects_non_canonical_limb() {
		let result = bytes_to_felts_compact(&P.to_le_bytes());
		assert_eq!(result, Err("Compact encoding limb exceeds Goldilocks modulus"));
	}

	#[test]
	fn test_bytes_to_digest_rejects_non_canonical_limb() {
		let mut digest = [0u8; 32];
		digest[..8].copy_from_slice(&P.to_le_bytes());
		let result = bytes_to_digest(&digest);
		assert_eq!(result, Err("Digest limb exceeds Goldilocks modulus"));
	}

	#[test]
	fn test_bytes_to_felts_compact_vs_injective() {
		// Compact encoding should produce fewer felts than injective encoding
		let input = [42u8; 32];
		let compact = bytes_to_felts_compact(&input).unwrap();
		let injective = bytes_to_felts(&input);

		// 32 bytes: compact = 4 felts, injective = 9 felts (8 data + 1 terminator)
		assert_eq!(compact.len(), 4);
		assert_eq!(injective.len(), 9);
	}
}
