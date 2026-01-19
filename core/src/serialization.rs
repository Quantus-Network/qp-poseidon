use crate::OUTPUT;
use alloc::{string::String, vec::Vec};

const BIT_32_LIMB_MASK: u64 = 0xFFFF_FFFF;

pub type BytesDigest = [u8; 32];

/// Unify just what we need from a Goldilocks field element.
pub trait GoldiCompat: Copy + Clone + core::ops::AddAssign + 'static {
	const ORDER_U64: u64;

	fn from_u64(x: u64) -> Self;
	fn to_u64(self) -> u64;
}

// --- Plonky3 Goldilocks ---------------------------------------------------------
#[cfg(feature = "p3")]
pub mod p3_backend {
	use super::GoldiCompat;
	use p3_field::{integers::QuotientMap, PrimeField64};
	use p3_goldilocks::Goldilocks as P3G;

	impl GoldiCompat for P3G {
		// And the trait constant via a fully-qualified path
		const ORDER_U64: u64 = <P3G as PrimeField64>::ORDER_U64;

		#[inline]
		fn from_u64(x: u64) -> Self {
			Self::from_int(x)
		}
		#[inline]
		fn to_u64(self) -> u64 {
			self.as_canonical_u64()
		}
	}

	pub type GF = P3G;
}

// --- Plonky2 Goldilocks ----------------------------------------------------------
#[cfg(feature = "p2")]
pub mod p2_backend {
	use super::GoldiCompat;
	use plonky2::field::{
		goldilocks_field::GoldilocksField as P2G,
		types::{Field, Field64, PrimeField64},
	};

	impl GoldiCompat for P2G {
		const ORDER_U64: u64 = Self::ORDER;

		#[inline]
		fn from_u64(x: u64) -> Self {
			Self::from_noncanonical_u64(x)
		}
		#[inline]
		fn to_u64(self) -> u64 {
			self.to_canonical_u64()
		}
	}

	pub type GF = P2G;
}

pub const DIGEST_BYTES_PER_ELEMENT: usize = 8;
pub const FELTS_PER_U128: usize = 4;
pub const FELTS_PER_U64: usize = 2;
pub const AMOUNT_QUANTIZATION_FACTOR: u128 = 10_000_000_000u128; // 10^10

#[inline]
fn as_32_bit_limb<G: GoldiCompat>(felt: G, index: usize) -> Result<u64, String> {
	// Prefer canonical value when checking width.
	let v = felt.to_u64();
	if v <= BIT_32_LIMB_MASK {
		Ok(v)
	} else {
		Err(alloc::format!("Felt at index {} with value {} exceeds 32-bit limb size", index, v))
	}
}

pub fn u128_to_felts<G: GoldiCompat>(num: u128) -> [G; FELTS_PER_U128] {
	let mut result = [G::from_u64(0); FELTS_PER_U128];
	for (i, value) in result.iter_mut().enumerate() {
		let shift = 96 - 32 * i;
		*value = G::from_u64(((num >> shift) & BIT_32_LIMB_MASK as u128) as u64);
	}
	result
}

pub fn u128_to_quantized_felt<G: GoldiCompat>(num: u128) -> G {
	// Here we divide the u128 by 10^10 to go from 12 to 2 decimal places
	let quantized = num / AMOUNT_QUANTIZATION_FACTOR;
	// Ensure it fits within 32 bits
	assert!(
		quantized <= BIT_32_LIMB_MASK as u128,
		"Quantized value {} exceeds 32-bit limb size",
		quantized
	);
	G::from_u64(quantized as u64)
}

pub fn u64_to_felts<G: GoldiCompat>(num: u64) -> [G; FELTS_PER_U64] {
	[G::from_u64((num >> 32) & BIT_32_LIMB_MASK), G::from_u64(num & BIT_32_LIMB_MASK)]
}

pub fn try_felts_to_u128<G: GoldiCompat>(felts: [G; FELTS_PER_U128]) -> Result<u128, String> {
	let mut out = 0u128;
	for (i, felt) in felts.into_iter().enumerate() {
		let limb = as_32_bit_limb(felt, i)?; // validate < 2^32
		out |= (limb as u128) << (96 - 32 * i);
	}
	Ok(out)
}

pub fn try_felt_to_quantized_u128<G: GoldiCompat>(felt: G) -> Result<u128, String> {
	let v = as_32_bit_limb(felt, 0)? as u128;
	Ok(v * AMOUNT_QUANTIZATION_FACTOR)
}

pub fn try_felts_to_u64<G: GoldiCompat>(felts: [G; FELTS_PER_U64]) -> Result<u64, String> {
	let mut out = 0u64;
	for (i, felt) in felts.into_iter().enumerate() {
		let limb = as_32_bit_limb(felt, i)?; // validate < 2^32
									   // i = 0 -> shift 32, i = 1 -> shift 0
		out |= limb << (32 - 32 * i);
	}
	Ok(out)
}

/// Injective, 4 bytes → 1 felt, input is variable-length padded with 1, 0... to align with u32 size
/// NOTE: we do 32 bit limbs to achieve injectivity. We could use a larger size up to 63 bits but
/// chose to do 32 bits for simplicity.
pub fn injective_bytes_to_felts<G: GoldiCompat>(input: &[u8]) -> Vec<G> {
	const BYTES_PER_ELEMENT: usize = 4;

	// Calculate exact final size to avoid any reallocation
	let input_len = input.len();
	let len_with_marker = input_len + 1; // +1 for end marker
	let padding_needed =
		(BYTES_PER_ELEMENT - (len_with_marker % BYTES_PER_ELEMENT)) % BYTES_PER_ELEMENT;
	let final_padded_size = len_with_marker + padding_needed;
	let num_elements = final_padded_size / BYTES_PER_ELEMENT;

	// Pre-allocate exact sizes - no reallocation will occur
	let mut padded_input = Vec::<u8>::with_capacity(final_padded_size);
	let mut out = Vec::<G>::with_capacity(num_elements);

	// Copy input data - no reallocation
	padded_input.extend_from_slice(input);

	// Add end marker - no reallocation (capacity was pre-allocated)
	padded_input.push(1u8);

	// Add padding zeros - no reallocation (resize to pre-calculated size)
	padded_input.resize(final_padded_size, 0u8);

	// Process in fixed chunks - no dynamic allocation
	for chunk in padded_input.chunks_exact(BYTES_PER_ELEMENT) {
		let bytes = [chunk[0], chunk[1], chunk[2], chunk[3]];
		out.push(G::from_u64(u32::from_le_bytes(bytes) as u64));
	}

	out
}

/// 8 bytes → 1 felt, for digest paths ONLY. Assumes bytes fit within field order.
pub fn unsafe_digest_bytes_to_felts<G: GoldiCompat>(input: &BytesDigest) -> [G; OUTPUT] {
	const BYTES_PER_ELEMENT: usize = 8;
	let mut out = [G::from_u64(0); OUTPUT];

	for (chunk, out_elem) in input.chunks(BYTES_PER_ELEMENT).zip(out.iter_mut()) {
		let mut bytes = [0u8; BYTES_PER_ELEMENT];
		bytes[..chunk.len()].copy_from_slice(chunk);
		*out_elem = G::from_u64(u64::from_le_bytes(bytes));
	}
	out
}

pub fn digest_felts_to_bytes<G: GoldiCompat>(input: &[G; OUTPUT]) -> BytesDigest {
	// Convert exactly OUTPUT felts to 32 bytes: OUTPUT felts × 8 bytes/felt = 32 bytes
	let mut bytes = [0u8; 32];
	for (i, v) in input.iter().enumerate().take(OUTPUT) {
		let start = i * 8;
		let end = start + 8;
		bytes[start..end].copy_from_slice(&G::to_u64(*v).to_le_bytes());
	}
	bytes
}

/// Inverse of `injective_bytes_to_felts`.
pub fn try_injective_felts_to_bytes<G: GoldiCompat>(input: &[G]) -> Result<Vec<u8>, &'static str> {
	if input.is_empty() {
		return Err("Expected non-empty input");
	}

	const BYTES_PER_ELEMENT: usize = 4;
	let mut words: Vec<[u8; BYTES_PER_ELEMENT]> = Vec::with_capacity(input.len());
	for (i, felt) in input.iter().enumerate() {
		let value = as_32_bit_limb(*felt, i).map_err(|_| "Felt value exceeds 32 bits")?;
		words.push((value as u32).to_le_bytes());
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

/// Convert a string to field elements
pub fn injective_string_to_felts<G: GoldiCompat>(input: &str) -> Vec<G> {
	// Convert string to UTF-8 bytes
	let bytes = input.as_bytes();
	injective_bytes_to_felts::<G>(bytes)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::Goldilocks;
	use alloc::{format, string::String, vec};
	use p3_field::integers::QuotientMap;

	#[test]
	fn test_u64_round_trip() {
		let test_values = vec![
			0u64,
			1u64,
			0xFFFFFFFFu64,
			0x1234567890ABCDEFu64,
			u64::MAX,
			0x8000000000000000u64, // 2^63
			0x123456789ABCDEFu64,
		];

		for &original in &test_values {
			let felts = u64_to_felts::<Goldilocks>(original);

			let reconstructed = try_felts_to_u64::<Goldilocks>(felts)
				.expect(&format!("Failed to reconstruct u64 for input: {}", original));

			assert_eq!(original, reconstructed, "u64 round-trip failed for {}", original);
		}
	}

	#[test]
	fn test_u128_round_trip() {
		let test_values = vec![
			0u128,
			1u128,
			0xFFFFFFFFu128,
			0x123456789ABCDEF0123456789ABCDEFu128,
			u128::MAX,
			0x80000000000000000000000000000000u128, // 2^127
			0x12345678_9ABCDEF0_12345678_9ABCDEFu128,
		];

		for &original in &test_values {
			let felts = u128_to_felts::<Goldilocks>(original);

			// Reconstruct the u128 from felts
			let reconstructed = try_felts_to_u128::<Goldilocks>(felts)
				.expect(&format!("Failed to reconstruct u128 for input: {}", original));

			assert_eq!(original, reconstructed, "u128 round-trip failed for {}", original);
		}
	}

	#[test]
	fn test_u128_quantized_round_trip() {
		let test_values = vec![
			0u128,
			1_000_000_000_000u128,
			1_230_000_000_000u128,          // 1.23e12
			123_456_789_012_345u128,        // 1.23456789012345e14
			21_000_000_000_000_000_000u128, /* Max quantus supply of 21 million with 12 decimals */
			42_949_672_950_000_000_000u128, /* Maximum supply of any asset we can support, as
			                                 * this is the largest value that fits within a
			                                 * 32-bit limb with 2 decimals points of precision */
		];

		for &original in &test_values {
			let quantized_felt = u128_to_quantized_felt::<Goldilocks>(original);

			// Reconstruct the u128 from quantized felt
			let reconstructed = try_felt_to_quantized_u128::<Goldilocks>(quantized_felt)
				.expect(&format!("Failed to reconstruct quantized u128 for input: {}", original));

			// Check that all significant digits match for precision of 2 decimal places
			assert_eq!(
				AMOUNT_QUANTIZATION_FACTOR * (original / AMOUNT_QUANTIZATION_FACTOR),
				reconstructed,
				"u128 quantized round-trip failed for {}",
				original
			);
		}
	}

	#[test]
	#[should_panic(expected = "exceeds 32-bit limb size")]
	fn test_u128_to_quantized_felt_panics_when_quantized_exceeds_32bit() {
		let factor = AMOUNT_QUANTIZATION_FACTOR;
		let just_over = (BIT_32_LIMB_MASK as u128 + 1) * factor; // quantized == mask+1
		let _ = u128_to_quantized_felt::<Goldilocks>(just_over);
	}

	#[test]
	fn test_u128_quantized_round_trip_precision_loss_examples() {
		let f = AMOUNT_QUANTIZATION_FACTOR;

		let cases = vec![
			f - 1,             // below one quantization unit -> rounds to 0
			f + 1,             // loses 1 unit
			123 * f + 1,       // tiny remainder
			123 * f + (f / 2), // bigger remainder
			123 * f + (f - 1), // maximal remainder
			(BIT_32_LIMB_MASK as u128) * f + (f - 1), /* highest representable original with
			                    * remainder */
		];

		for original in cases {
			let felt = u128_to_quantized_felt::<Goldilocks>(original);
			let reconstructed =
				try_felt_to_quantized_u128::<Goldilocks>(felt).expect("reconstruct");

			let expected = original - (original % f);
			assert_eq!(reconstructed, expected, "floor-to-quantization failed for {original}");

			// Extra assertions to make the intent obvious:
			assert!(reconstructed <= original);
			if original % f != 0 {
				assert_ne!(reconstructed, original, "expected precision loss for {original}");
			}
		}
	}

	#[test]
	fn test_injective_bytes_round_trip() {
		let test_cases = vec![
			vec![],
			vec![0u8],
			vec![1u8, 2u8, 3u8],
			vec![255u8; 1],
			vec![255u8; 4],  // exactly one felt
			vec![255u8; 8],  // two felts
			vec![255u8; 15], // partial last felt
			vec![255u8; 32], // multiple felts
			b"hello world".to_vec(),
			b"The quick brown fox jumps over the lazy dog".to_vec(),
			(0u8..32).collect(), // range of byte values
		];

		for original in test_cases {
			let felts = injective_bytes_to_felts::<Goldilocks>(&original);
			let reconstructed = try_injective_felts_to_bytes(&felts)
				.expect(&format!("Failed to reconstruct bytes for input: {:?}", original));

			assert_eq!(
				original, reconstructed,
				"Injective bytes round-trip failed.\nOriginal: {:?}\nReconstructed: {:?}",
				original, reconstructed
			);
		}
	}

	#[test]
	fn test_injective_string_round_trip() {
		let long_string = "A".repeat(100);
		let test_strings = vec![
			"",
			"a",
			"hello",
			"hello world",
			"The quick brown fox jumps over the lazy dog",
			"UTF-8: 🦀 Rust 🚀 💯",
			"Numbers: 1234567890",
			"Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?",
			"Newlines\nand\ttabs",
			&long_string, // long string
		];

		for &original in test_strings.iter() {
			let felts = injective_string_to_felts::<Goldilocks>(&original);
			let reconstructed_bytes = try_injective_felts_to_bytes(&felts)
				.expect(&format!("Failed to reconstruct string: {}", original));
			let reconstructed = String::from_utf8(reconstructed_bytes)
				.expect(&format!("Reconstructed bytes are not valid UTF-8 for: {}", original));

			assert_eq!(original, reconstructed, "String round-trip failed for: '{}'", original);
		}
	}

	#[test]
	fn test_digest_bytes_round_trip() {
		// Test with inputs that fit within field order (avoid values that exceed it)
		let test_cases = vec![[0u8; 32], {
			let mut bytes = [0u8; 32];
			for i in 0..32 {
				bytes[i] = (i * i % 200) as u8; // Keep values reasonable
			}
			bytes
		}];

		for original in test_cases {
			let felts = unsafe_digest_bytes_to_felts::<Goldilocks>(&original);
			let reconstructed = digest_felts_to_bytes(&[felts[0], felts[1], felts[2], felts[3]]);
			assert_eq!(
				original, reconstructed,
				"Digest bytes round-trip failed.\nOriginal: {:?}\nReconstructed: {:?}",
				original, reconstructed
			);
		}
	}

	#[test]
	fn test_edge_cases() {
		// Test empty input
		let empty_bytes = vec![];
		let felts = injective_bytes_to_felts::<Goldilocks>(&empty_bytes);
		let reconstructed = try_injective_felts_to_bytes(&felts).unwrap();
		assert_eq!(empty_bytes, reconstructed, "Empty bytes round-trip failed");

		// Test single byte values
		for byte_val in [0u8, 1u8, 42u8, 127u8, 255u8] {
			let original = vec![byte_val];
			let felts = injective_bytes_to_felts::<Goldilocks>(&original);
			let reconstructed = try_injective_felts_to_bytes(&felts).unwrap();
			assert_eq!(original, reconstructed, "Single byte {} round-trip failed", byte_val);
		}

		// Test boundary conditions for felt alignment
		for size in 1..=12 {
			let original = vec![42u8; size];
			let felts = injective_bytes_to_felts::<Goldilocks>(&original);
			let reconstructed = try_injective_felts_to_bytes(&felts).unwrap();
			assert_eq!(original, reconstructed, "Size {} bytes round-trip failed", size);
		}
	}

	#[test]
	fn test_malformed_bytes_input_error_cases() {
		// Test malformed felts that don't have proper terminator or too large to fit in 32 bit
		// limbs
		let malformed_cases = vec![
			// No terminator at all - all non-terminator values
			vec![Goldilocks::from_int(0x12345678), Goldilocks::from_int(0x1ABCDEF0)],
			// Wrong terminator pattern - should be [1,0,0,0] not [2,0,0,0]
			vec![
				Goldilocks::from_int(0x12345678),
				Goldilocks::from_int(0x00000002), // should be 1 followed by zeros
			],
			// All high values that don't form proper termination
			vec![Goldilocks::from_int(0x7FFFFFFF), Goldilocks::from_int(0x7FFFFFFF)],
			// Exceeds 32-bit limb size
			vec![Goldilocks::from_int(0x1_0000_0000 as i64), Goldilocks::from_int(0x00000001)],
		];

		for malformed_felts in &malformed_cases {
			let result = try_injective_felts_to_bytes(&malformed_felts);
			assert!(result.is_err(), "Malformed input should return error: {:?}", malformed_felts);
		}
	}

	#[test]
	fn test_felt_width_error_handling() {
		// Create felts that exceed 32-bit limb size for u64 conversion
		let invalid_felts =
			[Goldilocks::from_int(0x1_0000_0000 as i64), Goldilocks::from_int(0xFFFFFFFF as i64)];
		let result = try_felts_to_u64::<Goldilocks>(invalid_felts);
		assert!(result.is_err(), "Expected felt width error for invalid felts");
		// Create felts that exceed 32-bit limb size for u128 conversion
		let invalid_felts_u128 = [
			Goldilocks::from_int(0x1_0000_0000 as i64),
			Goldilocks::from_int(0x00000001 as i64),
			Goldilocks::from_int(0xFFFFFFFF as i64),
			Goldilocks::from_int(0x00000001 as i64),
		];
		let result = try_felts_to_u128::<Goldilocks>(invalid_felts_u128);
		assert!(result.is_err(), "Expected felt width error for invalid felts in u128");
	}

	#[test]
	#[cfg(all(feature = "p2", feature = "p3"))]
	fn test_consistency_between_backends() {
		// This test ensures that P2 and P3 backends produce identical results
		// when converting the same data to/from field elements
		use crate::serialization::{p2_backend, p3_backend};

		let test_data = vec![
			vec![],
			vec![42u8],
			vec![0u8, 1u8, 2u8, 3u8],
			b"hello world".to_vec(),
			vec![100u8; 16],
			(0u8..32).collect(),
		];

		for original in test_data {
			// Test injective bytes conversion consistency
			let p2_felts = injective_bytes_to_felts::<p2_backend::GF>(&original);
			let p3_felts = injective_bytes_to_felts::<p3_backend::GF>(&original);

			// Both should produce the same number of field elements
			assert_eq!(
				p2_felts.len(),
				p3_felts.len(),
				"Different number of felts for input: {:?}",
				original
			);

			// Each corresponding field element should have the same u64 representation
			for (i, (p2_felt, p3_felt)) in p2_felts.iter().zip(p3_felts.iter()).enumerate() {
				assert_eq!(
					p2_felt.to_u64(),
					p3_felt.to_u64(),
					"Field element {} differs between backends for input: {:?}",
					i,
					original
				);
			}

			// Test round-trip consistency
			let p2_reconstructed = try_injective_felts_to_bytes(&p2_felts).unwrap();
			let p3_reconstructed = try_injective_felts_to_bytes(&p3_felts).unwrap();

			assert_eq!(original, p2_reconstructed, "P2 round-trip failed");
			assert_eq!(original, p3_reconstructed, "P3 round-trip failed");
			assert_eq!(p2_reconstructed, p3_reconstructed, "Backend reconstructions differ");
		}

		// Test u64/u128 conversion consistency
		let u64_test_values = vec![0u64, 1u64, 0xFFFFFFFFu64, 0x1234567890ABCDEFu64];
		for &value in &u64_test_values {
			let p2_felts = u64_to_felts::<p2_backend::GF>(value);
			let p3_felts = u64_to_felts::<p3_backend::GF>(value);

			assert_eq!(p2_felts.len(), p3_felts.len());
			for (p2_felt, p3_felt) in p2_felts.iter().zip(p3_felts.iter()) {
				assert_eq!(
					p2_felt.to_u64(),
					p3_felt.to_u64(),
					"u64 conversion differs between backends for value: {}",
					value
				);
			}
		}

		let u128_test_values = vec![0u128, 1u128, 0x123456789ABCDEF0123456789ABCDEFu128];
		for &value in &u128_test_values {
			let p2_felts = u128_to_felts::<p2_backend::GF>(value);
			let p3_felts = u128_to_felts::<p3_backend::GF>(value);

			assert_eq!(p2_felts.len(), p3_felts.len());
			for (p2_felt, p3_felt) in p2_felts.iter().zip(p3_felts.iter()) {
				assert_eq!(
					p2_felt.to_u64(),
					p3_felt.to_u64(),
					"u128 conversion differs between backends for value: {}",
					value
				);
			}
		}
	}
}
