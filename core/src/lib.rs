#![no_std]

extern crate alloc;

use alloc::{format, string::String, vec, vec::Vec};
use p3_field::{integers::QuotientMap, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_symmetric::Permutation;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

/// The minimum number of field elements to allocate for the preimage.
pub const MIN_FIELD_ELEMENT_PREIMAGE_LEN: usize = 190;
const BIT_32_LIMB_MASK: u64 = 0xFFFF_FFFF;

/// Use the first 8 bytes of the pi written out 3.141592653589793
const POSEIDON2_SEED: u64 = 0x3141592653589793;

// 4 felt output => 4 felt rate per round => capacity = 12 - 4 = 8
// => 256 bits of classical preimage security => 128 bits of quantum preimage security
const WIDTH: usize = 12;
const RATE: usize = 4;

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
		let mut rng = ChaCha20Rng::seed_from_u64(POSEIDON2_SEED);
		let poseidon2 = Poseidon2Goldilocks::<12>::new_from_rng_128(&mut rng);
		Self { poseidon2 }
	}

	/// Create a new Poseidon2Core instance with a custom seed
	pub fn with_seed(seed: u64) -> Self {
		let mut rng = ChaCha20Rng::seed_from_u64(seed);
		let poseidon2 = Poseidon2Goldilocks::<12>::new_from_rng_128(&mut rng);
		Self { poseidon2 }
	}

	/// TODO: Explicitly test edge cases here
	/// Hash field elements with padding to ensure consistent circuit behavior
	pub fn hash_padded_felts(&self, mut x: Vec<Goldilocks>) -> [u8; 32] {
		// Workaround to support variable-length input in circuit. We need to pad the preimage in
		// the same way as the circuit to ensure consistent hashes.
		let len = x.len();
		// length-prefix for injectivity ([0] and [0,0] should be distinct)
		x.insert(0, Goldilocks::from_int(len));
		if len < MIN_FIELD_ELEMENT_PREIMAGE_LEN {
			x.resize(MIN_FIELD_ELEMENT_PREIMAGE_LEN, Goldilocks::ZERO);
		}

		self.hash_no_pad(x)
	}

	/// Hash bytes with padding to ensure consistent circuit behavior
	pub fn hash_padded(&self, x: &[u8]) -> [u8; 32] {
		self.hash_padded_felts(injective_bytes_to_felts(x))
	}

	/// TODO: Explicitly test edge cases here ([0, 0, 0, 1] and [0, 0, 0] should be distinct)
	/// Hash field elements without any padding
	pub fn hash_no_pad(&self, x: Vec<Goldilocks>) -> [u8; 32] {
		let state = self.hash_no_pad_state(x);

		let result = &state[..RATE];

		digest_felts_to_bytes(result)
	}

	fn hash_no_pad_state(&self, mut x: Vec<Goldilocks>) -> [Goldilocks; WIDTH] {
		let mut state = [Goldilocks::ZERO; WIDTH];

		// Variable length padding according to https://eprint.iacr.org/2019/458.pdf
		// All messages get an extra 1 at the end
		x.push(Goldilocks::ONE);
		let mod_len = x.len() % RATE;
		// If last chunk is not full
		if mod_len != 0 {
			// fill with zeros
			x.resize(x.len() + (RATE - mod_len), Goldilocks::ZERO);
		}

		// Process in chunks
		for chunk in x.chunks(RATE) {
			for i in 0..RATE {
				// Add chunk to state
				state[i] += chunk[i];
			}

			// Apply Poseidon2 permutation
			self.poseidon2.permute_mut(&mut state);
		}

		state
	}

	/// Hash bytes without any padding
	/// NOTE: Not domain-separated from hash_no_pad; use with caution
	pub fn hash_no_pad_bytes(&self, x: &[u8]) -> [u8; 32] {
		self.hash_no_pad(injective_bytes_to_felts(x))
	}

	/// Hash with 512-bit output by squeezing the sponge twice
	pub fn hash_squeeze_twice(&self, x: &[u8]) -> [u8; 64] {
		let mut state = self.hash_no_pad_state(injective_bytes_to_felts(x));
		let h1 = digest_felts_to_bytes(&state[..RATE]);
		self.poseidon2.permute_mut(&mut state);
		let h2 = digest_felts_to_bytes(&state[..RATE]);

		let mut result = [0u8; 64];
		result[0..32].copy_from_slice(&h1);
		result[32..64].copy_from_slice(&h2);
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

/// TODO: Explicitly test edge cases here
/// Convert bytes to field elements in an injective manner (4 bytes per element)
/// This function is safe and will not result in field casting overflows because u32::MAX <
/// Goldilocks::ORDER
pub fn injective_bytes_to_felts(input: &[u8]) -> Vec<Goldilocks> {
	const BYTES_PER_ELEMENT: usize = 4;

	let mut field_elements: Vec<Goldilocks> = Vec::new();
	let chunks = input.chunks(BYTES_PER_ELEMENT);
	let num_chunks = chunks.len();
	let mut unpadded = false;
	for (i, chunk) in chunks.enumerate() {
		let mut bytes = [0u8; BYTES_PER_ELEMENT];

		if i == num_chunks - 1 {
			if chunk.len() < BYTES_PER_ELEMENT {
				bytes[chunk.len()] = 1;
			} else {
				unpadded = true;
			}
		}

		bytes[..chunk.len()].copy_from_slice(chunk);
		// Convert the chunk to a field element.
		let value = u32::from_le_bytes(bytes);
		let field_element = Goldilocks::from_int(value as u64);
		field_elements.push(field_element);
	}

	if unpadded {
		let value = u32::from_le_bytes([1, 0, 0, 0]);
		let felt = Goldilocks::from_int(value as u64);
		field_elements.push(felt);
	}

	field_elements
}

/// Convert bytes to field elements for digest operations (8 bytes per element)
/// We return a Result to handle potential out-of-bounds byte chunks gracefully
pub fn try_digest_bytes_to_felts(input: &[u8]) -> Result<Vec<Goldilocks>, String> {
	const BYTES_PER_ELEMENT: usize = 8;

	let mut field_elements: Vec<Goldilocks> = Vec::new();
	for (i, chunk) in input.chunks(BYTES_PER_ELEMENT).enumerate() {
		let mut bytes = [0u8; BYTES_PER_ELEMENT];
		bytes[..chunk.len()].copy_from_slice(chunk);
		// Convert the chunk to a field element.
		let value = u64::from_le_bytes(bytes);
		// Check that the value is less than the field order, handle it gracefully
		if value >= Goldilocks::ORDER_U64 {
			// If the value is out of bounds, we will return an error specifying the byte range that
			// caused the issue
			return Err(format!(
				"Byte chunk value exceeds field order. Chunk at index {} (bytes: {:?})",
				i, chunk
			));
		}
		let field_element = Goldilocks::from_int(value);
		field_elements.push(field_element);
	}

	Ok(field_elements)
}

/// Convert field elements back to bytes for digest operations
pub fn digest_felts_to_bytes(input: &[Goldilocks]) -> [u8; 32] {
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

	bytes
}

/// Convert field elements back to bytes in an injective manner
/// Will fail if the input does not conform to the injective encoding scheme
pub fn try_injective_felts_to_bytes(input: &[Goldilocks]) -> Result<Vec<u8>, &str> {
	const BYTES_PER_ELEMENT: usize = 4;
	let mut bytes: Vec<u8> = Vec::new();

	if input.is_empty() {
		return Ok(bytes);
	}

	// Collect all words as 4-byte little-endian chunks.
	let mut words: Vec<[u8; BYTES_PER_ELEMENT]> = Vec::with_capacity(input.len());
	for fe in input {
		let v = fe.as_canonical_u64() as u32;
		words.push(v.to_le_bytes());
	}

	// Case A: if the last word is exactly 0x00000001 (LE), it's a standalone terminator.
	if words.last() == Some(&[1, 0, 0, 0]) {
		// All preceding words are full data.
		for w in &words[..words.len() - 1] {
			bytes.extend_from_slice(w);
		}
		return Ok(bytes);
	}

	// Case B: otherwise, the final word contains the inline marker:
	// data bytes, then a single 0x01, then only zeros until the end.
	// All earlier words are full data.
	for w in &words[..words.len() - 1] {
		bytes.extend_from_slice(w);
	}

	let last = words.last().unwrap();
	// WE find the marker position j such that last[j] == 1 and last[j+1..] are all zero.
	// Then the data length in the last word is j bytes; we append last[..j].
	// If no marker is found (malformed input), fall back to treating the whole word as data.
	let mut marker_index: Option<usize> = None;
	for j in 0..BYTES_PER_ELEMENT {
		if last[j] == 1 && last[j + 1..].iter().all(|&b| b == 0) {
			marker_index = Some(j);
			break;
		}
	}

	match marker_index {
		Some(j) => bytes.extend_from_slice(&last[..j]),
		None => return Err("Malformed input: no valid terminator found in the last field element"),
	}

	Ok(bytes)
}

/// Convert a string to field elements
pub fn injective_string_to_felts(input: &str) -> Vec<Goldilocks> {
	// Convert string to UTF-8 bytes
	let bytes = input.as_bytes();
	injective_bytes_to_felts(bytes)
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
	fn test_known_value_hashes() {
		let vectors = [
			(vec![], "a6fc4818a78230f52ad1c4f0b6b29abba3fd421fcb32dfa5b525a48eed1f7b85"),
			(vec![0u8], "f208459942ef56aae963c09b38eb9ea631d26f304d50628369e0373c16c2c516"),
			(vec![0u8, 0u8], "4df1066b0c88d6e3cb82a640de001d00a90f74df8de869c2b043f3d643c101fb"),
			(
				vec![0u8, 0u8, 0u8],
				"969626772357a9a50e29d32045f9dbc6292d8c479a3063e4c683470695b7c7dd",
			),
			(
				vec![0u8, 0u8, 0u8, 0u8],
				"fd36111acef038ed81719135048ad4f057a97135b59f4a0c87d1c16061b1f811",
			),
			(
				vec![0u8, 0u8, 0u8, 1u8],
				"14dbdd7765407ead3bebbda7425973a0c71dee5b1105cfc89dc331c29ee3dbdd",
			),
			(
				vec![1u8, 2, 3, 4, 5, 6, 7, 8],
				"d7d844a077c87dd71c2a9c74f4db6259cc576f067b5ba6a3da1ebd207083dce2",
			),
			(vec![255u8; 32], "7c213ed101ac7d262587405268bb0692650873d57cc56e8693792a40bff46743"),
			(
				b"hello world".to_vec(),
				"99a92e778137a1c178e482ed2e2c9b22e7a38f63ed6dc55f9b3c4d295199b4d3",
			),
			(
				(0u8..32).collect::<Vec<u8>>(),
				"c028ef4990bc5cb5ef7b5dd35cff693d4872a182866b1f442d1e8a4e1e726deb",
			),
		];
		let poseidon = Poseidon2Core::new();
		for (input, expected_hex) in vectors.iter() {
			let hash = poseidon.hash_padded(input);
			assert_eq!(
				hex::encode(hash.as_slice()),
				*expected_hex,
				"input: 0x{}",
				hex::encode(input)
			);
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
		let input = b"test deterministic";
		let hash1 = hasher1.hash_padded(input);

		for _ in 0..100 {
			let hasher2 = Poseidon2Core::new();
			let hash2 = hasher2.hash_padded(input);
			assert_eq!(hash1, hash2, "Deterministic seed should produce consistent results");
		}
	}

	#[test]
	fn test_hash_squeeze_twice() {
		let hasher = Poseidon2Core::new();
		let input = b"test 512-bit hash";
		let hash512 = hasher.hash_squeeze_twice(input);

		// Should be exactly 64 bytes
		assert_eq!(hash512.len(), 64);

		// First 32 bytes should be hash of input
		let expected_first = hasher.hash_no_pad_bytes(input);
		assert_eq!(&hash512[0..32], &expected_first);

		// Test deterministic
		let hash512_2 = hasher.hash_squeeze_twice(input);
		assert_eq!(hash512, hash512_2);

		// Different inputs should produce different outputs
		let different_hash = hasher.hash_squeeze_twice(b"different input");
		assert_ne!(hash512, different_hash);
	}
}
