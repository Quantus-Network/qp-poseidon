use crate::RATE;
use alloc::vec::Vec;

const BIT_32_LIMB_MASK: u64 = 0xFFFF_FFFF;

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

pub fn u128_to_felts<G: GoldiCompat>(num: u128) -> Vec<G> {
	const FELTS_PER_U128: usize = 4;
	(0..FELTS_PER_U128)
		.map(|i| {
			let shift = 96 - 32 * i;
			let limb = ((num >> shift) & BIT_32_LIMB_MASK as u128) as u64;
			G::from_u64(limb)
		})
		.collect()
}

pub fn u64_to_felts<G: GoldiCompat>(num: u64) -> Vec<G> {
	alloc::vec![G::from_u64((num >> 32) & BIT_32_LIMB_MASK), G::from_u64(num & BIT_32_LIMB_MASK),]
}

/// Injective, 4 bytes → 1 felt, input is variable-length padded with 1, 0... to align with u32 size
/// NOTE: we do 32 bit limbs to achieve injectivity. We could use a larger size up to 63 bits but
/// chose to do 32 bits for simplicity.
pub fn injective_bytes_to_felts<G: GoldiCompat>(input: &[u8]) -> Vec<G> {
	const BYTES_PER_ELEMENT: usize = 4;
	let mut out = Vec::new();

	let mut padded_input = input.to_vec();
	// Mark end with 1u8
	padded_input.push(1u8);
	let mod_len = padded_input.len() % BYTES_PER_ELEMENT;
	if mod_len != 0 {
		// Fill to BYTES_PER_ELEMENT alignment with 0u8s
		padded_input.resize(padded_input.len() + BYTES_PER_ELEMENT - mod_len, 0u8);
	}

	let chunks = padded_input.chunks(BYTES_PER_ELEMENT);
	assert!(padded_input.chunks_exact(BYTES_PER_ELEMENT).remainder().is_empty());

	for chunk in chunks {
		let mut bytes = [0u8; BYTES_PER_ELEMENT];
		bytes[..chunk.len()].copy_from_slice(chunk);
		out.push(G::from_u64(u32::from_le_bytes(bytes) as u64));
	}

	out
}

/// 8 bytes → 1 felt, for digest paths, with bounds check.
pub fn noninjective_digest_bytes_to_felts<G: GoldiCompat>(input: &[u8]) -> Vec<G> {
	const BYTES_PER_ELEMENT: usize = 8;
	let mut out = Vec::new();

	for chunk in input.chunks(BYTES_PER_ELEMENT) {
		let mut bytes = [0u8; BYTES_PER_ELEMENT];
		bytes[..chunk.len()].copy_from_slice(chunk);
		out.push(G::from_u64(u64::from_le_bytes(bytes)));
	}
	out
}

pub fn digest_felts_to_bytes<G: GoldiCompat>(input: &[G; RATE]) -> [u8; 32] {
	// Convert exactly RATE felts to 32 bytes: RATE felts × 8 bytes/felt = 32 bytes
	let mut bytes = [0u8; 32];
	for (i, v) in input.iter().enumerate().take(RATE) {
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
	for felt in input {
		words.push((G::to_u64(*felt) as u32).to_le_bytes());
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
	use p3_field::{integers::QuotientMap, PrimeCharacteristicRing, PrimeField64};

	#[test]
	fn test_utility_functions() {
		// Test u64_to_felts
		let num = 0x1234567890ABCDEF;
		let felts = u64_to_felts::<Goldilocks>(num);
		assert_eq!(felts.len(), 2);

		// Test u128_to_felts
		let large_num = 0x123456789ABCDEF0123456789ABCDEF0u128;
		let felts = u128_to_felts::<Goldilocks>(large_num);
		assert_eq!(felts.len(), 4);

		// Test string conversion
		let text = "hello";
		let felts = injective_string_to_felts::<Goldilocks>(text);
		assert_eq!(felts.len(), 2);

		// Test round-trip conversion
		let original_bytes = b"test data";
		let felts = injective_bytes_to_felts::<Goldilocks>(original_bytes);
		let recovered_bytes = try_injective_felts_to_bytes(&felts).unwrap();
		// Should match the original
		assert_eq!(&recovered_bytes, original_bytes);
		// try injective felts to bytes should fail for malformed input
		let malformed_felts =
			vec![Goldilocks::from_int(0xFFFFFFFF as i64), Goldilocks::from_int(0xFFFFFFFF as i64)];
		let result = try_injective_felts_to_bytes(&malformed_felts);
		assert!(result.is_err(), "Malformed input should return an error");
	}

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
			assert_eq!(felts.len(), 2, "u64 should convert to exactly 2 felts");

			// Reconstruct the u64 from felts
			let high = felts[0].as_canonical_u64();
			let low = felts[1].as_canonical_u64();
			let reconstructed = (high << 32) | low;

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
			assert_eq!(felts.len(), 4, "u128 should convert to exactly 4 felts");

			// Reconstruct the u128 from felts
			let mut reconstructed = 0u128;
			for (i, felt) in felts.iter().enumerate() {
				let shift = 96 - 32 * i;
				reconstructed |= (felt.as_canonical_u64() as u128) << shift;
			}

			assert_eq!(original, reconstructed, "u128 round-trip failed for {}", original);
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
			let felts = noninjective_digest_bytes_to_felts::<Goldilocks>(&original);
			let reconstructed = digest_felts_to_bytes(&[felts[0], felts[1], felts[2], felts[3]]);
			assert_eq!(
				original, reconstructed,
				"Digest bytes round-trip failed.\nOriginal: {:?}\nReconstructed: {:?}",
				original, reconstructed
			);
		}
	}

	#[test]
	fn test_digest_bytes_partial_round_trip() {
		// Test with smaller inputs that are valid
		let test_cases = vec![
			vec![],
			vec![42u8],
			vec![1u8, 2u8, 3u8, 4u8],
			vec![100u8; 8], // one felt worth, reasonable values
			vec![50u8; 16], // two felts worth
			vec![25u8; 24], // three felts worth
		];

		for original in test_cases {
			let felts = noninjective_digest_bytes_to_felts::<Goldilocks>(&original);

			// Pad felts to 4 elements for digest (fill with zeros if needed)
			let mut padded_felts = vec![Goldilocks::ZERO; 4];
			for (i, &felt) in felts.iter().enumerate().take(4) {
				padded_felts[i] = felt;
			}

			let reconstructed = digest_felts_to_bytes(&[
				padded_felts[0],
				padded_felts[1],
				padded_felts[2],
				padded_felts[3],
			]);

			// For partial inputs, the reconstructed should be padded to 32 bytes
			assert_eq!(reconstructed.len(), 32, "Digest output should always be 32 bytes");

			// The original bytes should match the beginning of the reconstructed bytes
			if !original.is_empty() {
				assert_eq!(
					&reconstructed[..original.len()],
					&original[..],
					"Digest partial round-trip failed.\nOriginal: {:?}\nReconstructed prefix: {:?}",
					original,
					&reconstructed[..original.len()]
				);
			}

			// The padding should be zeros
			for &byte in &reconstructed[original.len()..] {
				assert_eq!(byte, 0, "Padding bytes should be zero");
			}
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
	fn test_malformed_input_error_cases() {
		// Test malformed felts that don't have proper terminator
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
		];

		for malformed_felts in &malformed_cases {
			let result = try_injective_felts_to_bytes(&malformed_felts);
			assert!(result.is_err(), "Malformed input should return error: {:?}", malformed_felts);
		}
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
