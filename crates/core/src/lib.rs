#![no_std]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use p3_field::integers::QuotientMap;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_symmetric::Permutation;
use rand::rngs::SmallRng;
use rand::SeedableRng;

/// The minimum number of field elements to allocate for the preimage.
pub const MIN_FIELD_ELEMENT_PREIMAGE_LEN: usize = 188;
const BIT_32_LIMB_MASK: u64 = 0xFFFF_FFFF;

/// Fixed seed for deterministic constant generation
const POSEIDON2_SEED: u64 = 0x189189189189189;

/// Core Poseidon2 hasher implementation that holds an initialized instance
#[derive(Clone)]
pub struct Poseidon2Core {
	poseidon2: Poseidon2Goldilocks<12>,
}

impl Default for Poseidon2Core {
	fn default() -> Self {
		Self::new()
	}
}

impl Poseidon2Core {
	/// Create a new Poseidon2Core instance with deterministic constants
	pub fn new() -> Self {
		let mut rng = SmallRng::seed_from_u64(POSEIDON2_SEED);
		let poseidon2 = Poseidon2Goldilocks::<12>::new_from_rng_128(&mut rng);
		Self { poseidon2 }
	}

	/// Create a new Poseidon2Core instance with a custom seed
	pub fn with_seed(seed: u64) -> Self {
		let mut rng = SmallRng::seed_from_u64(seed);
		let poseidon2 = Poseidon2Goldilocks::<12>::new_from_rng_128(&mut rng);
		Self { poseidon2 }
	}

	/// Hash field elements with padding to ensure consistent circuit behavior
	pub fn hash_padded_felts(&self, mut x: Vec<Goldilocks>) -> [u8; 32] {
		// Workaround to support variable-length input in circuit. We need to pad the preimage in
		// the same way as the circuit to ensure consistent hashes.
		if x.len() < MIN_FIELD_ELEMENT_PREIMAGE_LEN {
			x.resize(MIN_FIELD_ELEMENT_PREIMAGE_LEN, Goldilocks::ZERO);
		}

		// We need to use a fixed width for Poseidon2. Let's use 12 elements at a time.
		const CHUNK_SIZE: usize = 12;

		// Process in chunks
		let mut result = [Goldilocks::ZERO; CHUNK_SIZE];
		for chunk in x.chunks(CHUNK_SIZE) {
			let mut state = [Goldilocks::ZERO; CHUNK_SIZE];

			// Copy chunk data into state
			for (i, &elem) in chunk.iter().enumerate() {
				if i < CHUNK_SIZE {
					state[i] = elem;
				}
			}

			// XOR with previous result (chaining)
			for i in 0..CHUNK_SIZE {
				state[i] = state[i] + result[i];
			}

			// Apply Poseidon2 permutation
			result = self.poseidon2.permute(state);
		}

		// Convert first 4 field elements to bytes (32 bytes total)
		let mut bytes = [0u8; 32];
		for i in 0..4 {
			let val = result[i].as_canonical_u64();
			let val_bytes = val.to_le_bytes();
			bytes[i * 8..(i + 1) * 8].copy_from_slice(&val_bytes);
		}
		bytes
	}

	/// Hash bytes with padding to ensure consistent circuit behavior
	pub fn hash_padded(&self, x: &[u8]) -> [u8; 32] {
		self.hash_padded_felts(injective_bytes_to_felts(x))
	}

	/// Hash field elements without any padding
	pub fn hash_no_pad(&self, x: Vec<Goldilocks>) -> [u8; 32] {
		const CHUNK_SIZE: usize = 12;

		// Process in chunks without padding
		let mut result = [Goldilocks::ZERO; CHUNK_SIZE];
		for chunk in x.chunks(CHUNK_SIZE) {
			let mut state = [Goldilocks::ZERO; CHUNK_SIZE];

			// Copy chunk data into state
			for (i, &elem) in chunk.iter().enumerate() {
				if i < CHUNK_SIZE {
					state[i] = elem;
				}
			}

			// XOR with previous result (chaining)
			for i in 0..CHUNK_SIZE {
				state[i] = state[i] + result[i];
			}

			// Apply Poseidon2 permutation
			result = self.poseidon2.permute(state);
		}

		// Convert first 4 field elements to bytes (32 bytes total)
		let mut bytes = [0u8; 32];
		for i in 0..4 {
			let val = result[i].as_canonical_u64();
			let val_bytes = val.to_le_bytes();
			bytes[i * 8..(i + 1) * 8].copy_from_slice(&val_bytes);
		}
		bytes
	}

	/// Hash bytes without any padding
	pub fn hash_no_pad_bytes(&self, x: &[u8]) -> [u8; 32] {
		self.hash_no_pad(injective_bytes_to_felts(x))
	}

	/// Hash with 512-bit output by hashing input, then hashing the result, and concatenating both
	pub fn hash_512(&self, x: &[u8]) -> [u8; 64] {
		let first_hash = self.hash_padded(x);
		let second_hash = self.hash_padded(&first_hash);

		let mut result = [0u8; 64];
		result[0..32].copy_from_slice(&first_hash);
		result[32..64].copy_from_slice(&second_hash);
		result
	}

	/// Hash field elements with 512-bit output
	pub fn hash_512_felts(&self, x: Vec<Goldilocks>) -> [u8; 64] {
		let first_hash = self.hash_padded_felts(x);
		let second_hash = self.hash_padded(&first_hash);

		let mut result = [0u8; 64];
		result[0..32].copy_from_slice(&first_hash);
		result[32..64].copy_from_slice(&second_hash);
		result
	}
}

/// Convert a u128 to field elements using 32-bit limbs
pub fn u128_to_felts(num: u128) -> Vec<Goldilocks> {
	const FELTS_PER_U128: usize = 4;
	(0..FELTS_PER_U128)
		.map(|i| {
			let shift = 96 - 32 * i;
			let limb = ((num >> shift) & BIT_32_LIMB_MASK as u128) as u64;
			Goldilocks::from_int(limb)
		})
		.collect::<Vec<_>>()
}

/// Convert a u64 to field elements using 32-bit limbs
pub fn u64_to_felts(num: u64) -> Vec<Goldilocks> {
	vec![
		Goldilocks::from_int((num >> 32) & BIT_32_LIMB_MASK),
		Goldilocks::from_int(num & BIT_32_LIMB_MASK),
	]
}

/// Convert bytes to field elements in an injective manner (4 bytes per element)
pub fn injective_bytes_to_felts(input: &[u8]) -> Vec<Goldilocks> {
	const BYTES_PER_ELEMENT: usize = 4;

	let mut field_elements: Vec<Goldilocks> = Vec::new();
	for chunk in input.chunks(BYTES_PER_ELEMENT) {
		let mut bytes = [0u8; BYTES_PER_ELEMENT];
		bytes[..chunk.len()].copy_from_slice(chunk);
		// Convert the chunk to a field element.
		let value = u32::from_le_bytes(bytes);
		let field_element = Goldilocks::from_int(value as u64);
		field_elements.push(field_element);
	}

	field_elements
}

/// Convert bytes to field elements for digest operations (8 bytes per element)
pub fn digest_bytes_to_felts(input: &[u8]) -> Vec<Goldilocks> {
	const BYTES_PER_ELEMENT: usize = 8;

	let mut field_elements: Vec<Goldilocks> = Vec::new();
	for chunk in input.chunks(BYTES_PER_ELEMENT) {
		let mut bytes = [0u8; BYTES_PER_ELEMENT];
		bytes[..chunk.len()].copy_from_slice(chunk);
		// Convert the chunk to a field element.
		let value = u64::from_le_bytes(bytes);
		let field_element = Goldilocks::from_int(value);
		field_elements.push(field_element);
	}

	field_elements
}

/// Convert field elements back to bytes for digest operations
pub fn digest_felts_to_bytes(input: &[Goldilocks]) -> Vec<u8> {
	const DIGEST_BYTES_PER_ELEMENT: usize = 8;
	let mut bytes = [0u8; 32];

	for (i, field_element) in input.iter().enumerate() {
		if i * DIGEST_BYTES_PER_ELEMENT >= 32 {
			break;
		}
		let value = field_element.as_canonical_u64();
		let value_bytes = value.to_le_bytes();
		let start_index = i * DIGEST_BYTES_PER_ELEMENT;
		let end_index = core::cmp::min(start_index + DIGEST_BYTES_PER_ELEMENT, 32);
		bytes[start_index..end_index].copy_from_slice(&value_bytes[..end_index - start_index]);
	}

	bytes.to_vec()
}

/// Convert field elements back to bytes in an injective manner
pub fn injective_felts_to_bytes(input: &[Goldilocks]) -> Vec<u8> {
	const BYTES_PER_ELEMENT: usize = 4;
	let mut bytes: Vec<u8> = Vec::new();

	for field_element in input {
		let value = field_element.as_canonical_u64();
		let value_bytes = &value.to_le_bytes()[..BYTES_PER_ELEMENT];
		bytes.extend_from_slice(value_bytes);
	}

	bytes
}

/// Convert a string to field elements (up to 8 bytes)
pub fn injective_string_to_felts(input: &str) -> Vec<Goldilocks> {
	// Convert string to UTF-8 bytes
	let bytes = input.as_bytes();

	assert!(bytes.len() <= 8, "String must be at most 8 bytes long");

	let mut padded = [0u8; 8];
	padded[..bytes.len()].copy_from_slice(bytes);

	let first = u32::from_le_bytes(padded[0..4].try_into().unwrap());
	let second = u32::from_le_bytes(padded[4..8].try_into().unwrap());

	vec![Goldilocks::from_int(first as u64), Goldilocks::from_int(second as u64)]
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloc::vec;
	use hex;
	use p3_field::PrimeField64;

	#[test]
	fn test_empty_input() {
		let hasher = Poseidon2Core::new();
		let result = hasher.hash_padded(&[]);
		assert_eq!(result.len(), 32);
	}

	#[test]
	fn test_single_byte() {
		let hasher = Poseidon2Core::new();
		let input = vec![42u8];
		let result = hasher.hash_padded(&input);
		assert_eq!(result.len(), 32);
	}

	#[test]
	fn test_exactly_32_bytes() {
		let hasher = Poseidon2Core::new();
		let input = [1u8; 32];
		let result = hasher.hash_padded(&input);
		assert_eq!(result.len(), 32);
	}

	#[test]
	fn test_multiple_chunks() {
		let hasher = Poseidon2Core::new();
		let input = [2u8; 64]; // Two chunks
		let result = hasher.hash_padded(&input);
		assert_eq!(result.len(), 32);
	}

	#[test]
	fn test_partial_chunk() {
		let hasher = Poseidon2Core::new();
		let input = [3u8; 40]; // One full chunk plus 8 bytes
		let result = hasher.hash_padded(&input);
		assert_eq!(result.len(), 32);
	}

	#[test]
	fn test_consistency() {
		let hasher = Poseidon2Core::new();
		let input = [4u8; 50];
		let iterations = 10;
		let current_hash = hasher.hash_padded(&input);

		for _ in 0..iterations {
			let hash1 = hasher.hash_padded(&current_hash);
			let hash2 = hasher.hash_padded(&current_hash);
			assert_eq!(hash1, hash2, "Hash function should be deterministic");
		}
	}

	#[test]
	fn test_different_inputs() {
		let hasher = Poseidon2Core::new();
		let input1 = [5u8; 32];
		let input2 = [6u8; 32];
		let hash1 = hasher.hash_padded(&input1);
		let hash2 = hasher.hash_padded(&input2);
		assert_ne!(hash1, hash2, "Different inputs should produce different hashes");
	}

	#[test]
	fn test_poseidon2_hash_input_sizes() {
		let hasher = Poseidon2Core::new();
		// Test inputs from 1 to 128 bytes
		for size in 1..=128 {
			// Create a predictable input: repeating byte value based on size
			let input: Vec<u8> = (0..size).map(|i| (i * i % 256) as u8).collect();
			let hash = hasher.hash_padded(&input);

			// Assertions
			assert_eq!(hash.len(), 32, "Input size {} should produce 32-byte hash", size);
		}
	}

	#[test]
	fn test_big_preimage() {
		let hasher = Poseidon2Core::new();
		for overflow in 1..=10 {
			let preimage = (Goldilocks::ORDER_U64 + overflow).to_le_bytes();
			let _hash = hasher.hash_padded(&preimage);
		}
	}

	#[test]
	fn test_circuit_preimage() {
		let hasher = Poseidon2Core::new();
		let preimage =
			hex::decode("afd8e7530b95ee5ebab950c9a0c62fae1e80463687b3982233028e914f8ec7cc");
		let hash = hasher.hash_padded(&preimage.unwrap());
		let _hash = hasher.hash_padded(&hash);
	}

	#[test]
	fn test_random_inputs() {
		let hex_strings = [
			"a3f8",
			"1b7e9d",
			"4c2a6f81",
			"e5d30b9a",
			"1a4f7c2e9b0d8356",
			"3e8d2a7f5c1b09e4d6f7a2c8",
			"7b3e9a1f4c8d2e6b0a5f9d3c",
			"1a4f7c2e9b0d83561a4f7c2e9b0d83561a4f7c2e9b0d83561a4f7c2e9b0d8356",
			"e5d30b9a4c2a6f81e5d30b9a4c2a6f81e5d30b9a4c2a6f81e5d30b9a4c2a6f81",
		];

		let hasher = Poseidon2Core::new();
		for hex_string in hex_strings.iter() {
			let preimage = hex::decode(hex_string).unwrap();
			let hash = hasher.hash_padded(&preimage);
			let _hash2 = hasher.hash_padded(&hash);
		}
	}

	#[test]
	fn test_utility_functions() {
		// Test u64_to_felts
		let num = 0x1234567890ABCDEF;
		let felts = u64_to_felts(num);
		assert_eq!(felts.len(), 2);

		// Test u128_to_felts
		let large_num = 0x123456789ABCDEF0123456789ABCDEF0u128;
		let felts = u128_to_felts(large_num);
		assert_eq!(felts.len(), 4);

		// Test string conversion
		let text = "hello";
		let felts = injective_string_to_felts(text);
		assert_eq!(felts.len(), 2);

		// Test round-trip conversion
		let original_bytes = b"test data";
		let felts = injective_bytes_to_felts(original_bytes);
		let recovered_bytes = injective_felts_to_bytes(&felts);
		// Should match up to the original length
		assert_eq!(&recovered_bytes[..original_bytes.len()], original_bytes);
	}

	#[test]
	fn test_hash_no_pad() {
		let hasher = Poseidon2Core::new();
		let input = b"test";
		let padded_hash = hasher.hash_padded(input);
		let no_pad_hash = hasher.hash_no_pad_bytes(input);

		// These should be different since one is padded and the other isn't
		assert_ne!(padded_hash, no_pad_hash);
		assert_eq!(padded_hash.len(), 32);
		assert_eq!(no_pad_hash.len(), 32);
	}

	#[test]
	fn test_deterministic_constants() {
		// Test that using the same seed produces the same results
		let hasher1 = Poseidon2Core::new();
		let hasher2 = Poseidon2Core::new();
		let input = b"test deterministic";
		let hash1 = hasher1.hash_padded(input);
		let hash2 = hasher2.hash_padded(input);
		assert_eq!(hash1, hash2, "Deterministic seed should produce consistent results");
	}

	#[test]
	fn test_hash_512() {
		let hasher = Poseidon2Core::new();
		let input = b"test 512-bit hash";
		let hash512 = hasher.hash_512(input);

		// Should be exactly 64 bytes
		assert_eq!(hash512.len(), 64);

		// First 32 bytes should be hash of input
		let expected_first = hasher.hash_padded(input);
		assert_eq!(&hash512[0..32], &expected_first);

		// Second 32 bytes should be hash of first hash
		let expected_second = hasher.hash_padded(&expected_first);
		assert_eq!(&hash512[32..64], &expected_second);

		// Test deterministic
		let hash512_2 = hasher.hash_512(input);
		assert_eq!(hash512, hash512_2);

		// Different inputs should produce different outputs
		let different_hash = hasher.hash_512(b"different input");
		assert_ne!(hash512, different_hash);
	}

	#[test]
	fn test_hash_512_felts() {
		let hasher = Poseidon2Core::new();
		let felts =
			vec![Goldilocks::from_int(123), Goldilocks::from_int(456), Goldilocks::from_int(789)];
		let hash512 = hasher.hash_512_felts(felts.clone());

		// Should be exactly 64 bytes
		assert_eq!(hash512.len(), 64);

		// Should be deterministic
		let hash512_2 = hasher.hash_512_felts(felts);
		assert_eq!(hash512, hash512_2);
	}
}
