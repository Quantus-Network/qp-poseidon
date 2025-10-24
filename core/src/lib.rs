#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_symmetric::Permutation;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

/// The minimum number of field elements to allocate for the preimage.
pub const MIN_FIELD_ELEMENT_PREIMAGE_LEN: usize = 189;
const BIT_32_LIMB_MASK: u64 = 0xFFFF_FFFF;

/// Use the first 8 bytes of the pi written out 3.141592653589793
const POSEIDON2_SEED: u64 = 0x3141592653589793;

// 4 felt output => 4 felt rate per round => capacity = 12 - 4 = 8
// => 256 bits of classical preimage security => 128 bits of quantum preimage security
const WIDTH: usize = 12;
const RATE: usize = 4;

/// Unify just what we need from a Goldilocks field element.
pub trait GoldiCompat: Copy + Clone + core::ops::AddAssign + 'static {
	const ORDER_U64: u64;

	fn from_u64(x: u64) -> Self;
	fn to_u64(self) -> u64;
}

// --- Plonky3 Goldilocks ---------------------------------------------------------
#[cfg(feature = "p3")]
mod p3_backend {
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
mod p2_backend {
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

// Bring the selected Goldilocks type in as `GF`
#[cfg(feature = "p2")]
pub use p2_backend::GF as P2GF;
#[cfg(feature = "p3")]
pub use p3_backend::GF as P3GF;

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

	fn hash_circuit_padding_felts<const C: usize>(&self, mut x: Vec<Goldilocks>) -> [u8; 32] {
		// This function doesn't protect against length extension attacks but is safe as
		// long as the input felts are the outputs of an injective encoding.
		// For this reason, we wrap it in hash_padded which performs injective encoding from bytes,
		// so application users are safe.
		let len = x.len();
		if len > C {
			panic!("Input too large: {} elements exceeds capacity {}", len, C);
		}
		if len < C {
			x.resize(C, Goldilocks::ZERO);
		}

		self.hash_no_pad(x)
	}

	/// Hash bytes with constant padding to size C to ensure consistent circuit behavior
	/// NOTE: Will panic if felt encoded input exceeds capacity of C
	pub fn hash_padded_bytes<const C: usize>(&self, x: &[u8]) -> [u8; 32] {
		self.hash_circuit_padding_felts::<C>(injective_bytes_to_felts(x))
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

/// Injective, 4 bytes → 1 felt (with inline 0x01 terminator in the last word if needed).
pub fn injective_bytes_to_felts<G: GoldiCompat>(input: &[u8]) -> Vec<G> {
	const BYTES_PER_ELEMENT: usize = 4;
	let mut out = Vec::new();
	let chunks = input.chunks(BYTES_PER_ELEMENT);
	let last_idx = chunks.len().saturating_sub(1);
	let mut unpadded = false;

	for (i, chunk) in chunks.enumerate() {
		let mut bytes = [0u8; BYTES_PER_ELEMENT];

		if i == last_idx {
			if chunk.len() < BYTES_PER_ELEMENT {
				bytes[chunk.len()] = 1;
			} else {
				unpadded = true;
			}
		}
		bytes[..chunk.len()].copy_from_slice(chunk);
		out.push(G::from_u64(u32::from_le_bytes(bytes) as u64));
	}

	if unpadded {
		out.push(G::from_u64(u32::from_le_bytes([1, 0, 0, 0]) as u64));
	}
	out
}

/// 8 bytes → 1 felt, for digest paths, with bounds check.
pub fn try_digest_bytes_to_felts<G: GoldiCompat>(
	input: &[u8],
) -> Result<Vec<G>, alloc::string::String> {
	const BYTES_PER_ELEMENT: usize = 8;
	let mut out = Vec::new();

	for (i, chunk) in input.chunks(BYTES_PER_ELEMENT).enumerate() {
		let mut bytes = [0u8; BYTES_PER_ELEMENT];
		bytes[..chunk.len()].copy_from_slice(chunk);
		let v = u64::from_le_bytes(bytes);
		if v >= G::ORDER_U64 {
			return Err(alloc::format!(
				"Byte chunk value exceeds field order at chunk {} (bytes: {:?})",
				i,
				chunk
			));
		}
		out.push(G::from_u64(v));
	}
	Ok(out)
}

pub fn digest_felts_to_bytes<G: GoldiCompat>(input: &[G]) -> [u8; 32] {
	const DIGEST_BYTES_PER_ELEMENT: usize = 8;
	let mut bytes = [0u8; 32];

	for (i, fe) in input.iter().enumerate() {
		let start = i * DIGEST_BYTES_PER_ELEMENT;
		if start >= 32 {
			break;
		}
		let end = core::cmp::min(start + DIGEST_BYTES_PER_ELEMENT, 32);
		let v_bytes = G::to_u64(*fe).to_le_bytes();
		bytes[start..end].copy_from_slice(&v_bytes[..end - start]);
	}
	bytes
}

/// Inverse of `injective_bytes_to_felts`.
pub fn try_injective_felts_to_bytes<G: GoldiCompat>(input: &[G]) -> Result<Vec<u8>, &'static str> {
	const BYTES_PER_ELEMENT: usize = 4;
	let mut words: Vec<[u8; BYTES_PER_ELEMENT]> = Vec::with_capacity(input.len());
	for fe in input {
		words.push((G::to_u64(*fe) as u32).to_le_bytes());
	}
	if words.is_empty() {
		return Ok(Vec::new());
	}

	let mut out = Vec::new();

	if words.last() == Some(&[1, 0, 0, 0]) {
		for w in &words[..words.len() - 1] {
			out.extend_from_slice(w);
		}
		return Ok(out);
	}

	for w in &words[..words.len() - 1] {
		out.extend_from_slice(w);
	}

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
	use alloc::vec;
	use hex;
	use p3_field::{integers::QuotientMap, PrimeField64};

	const C: usize = MIN_FIELD_ELEMENT_PREIMAGE_LEN;

	#[test]
	fn test_empty_input() {
		let hasher = Poseidon2Core::new();
		let result = hasher.hash_padded_bytes::<C>(&[]);
		assert_eq!(result.len(), 32);
	}

	#[test]
	fn test_single_byte() {
		let hasher = Poseidon2Core::new();
		let input = vec![42u8];
		let result = hasher.hash_padded_bytes::<C>(&input);
		assert_eq!(result.len(), 32);
	}

	#[test]
	fn test_exactly_32_bytes() {
		let hasher = Poseidon2Core::new();
		let input = [1u8; 32];
		let result = hasher.hash_padded_bytes::<C>(&input);
		assert_eq!(result.len(), 32);
	}

	#[test]
	fn test_multiple_chunks() {
		let hasher = Poseidon2Core::new();
		let input = [2u8; 64]; // Two chunks
		let result = hasher.hash_padded_bytes::<C>(&input);
		assert_eq!(result.len(), 32);
	}

	#[test]
	fn test_partial_chunk() {
		let hasher = Poseidon2Core::new();
		let input = [3u8; 40]; // One full chunk plus 8 bytes
		let result = hasher.hash_padded_bytes::<C>(&input);
		assert_eq!(result.len(), 32);
	}

	#[test]
	fn test_consistency() {
		let hasher = Poseidon2Core::new();
		let input = [4u8; 50];
		let iterations = 10;
		let current_hash = hasher.hash_padded_bytes::<C>(&input);

		for _ in 0..iterations {
			let hash1 = hasher.hash_padded_bytes::<C>(&current_hash);
			let hash2 = hasher.hash_padded_bytes::<C>(&current_hash);
			assert_eq!(hash1, hash2, "Hash function should be deterministic");
		}
	}

	#[test]
	fn test_different_inputs() {
		let hasher = Poseidon2Core::new();
		let input1 = [5u8; 32];
		let input2 = [6u8; 32];
		let hash1 = hasher.hash_padded_bytes::<C>(&input1);
		let hash2 = hasher.hash_padded_bytes::<C>(&input2);
		assert_ne!(hash1, hash2, "Different inputs should produce different hashes");
	}

	#[test]
	fn test_poseidon2_hash_input_sizes() {
		let hasher = Poseidon2Core::new();
		// Test inputs from 1 to 128 bytes
		for size in 1..=128 {
			// Create a predictable input: repeating byte value based on size
			let input: Vec<u8> = (0..size).map(|i| (i * i % 256) as u8).collect();
			let hash = hasher.hash_padded_bytes::<C>(&input);

			// Assertions
			assert_eq!(hash.len(), 32, "Input size {} should produce 32-byte hash", size);
		}
	}

	#[test]
	fn test_big_preimage() {
		let hasher = Poseidon2Core::new();
		for overflow in 1..=10 {
			let preimage =
				(<p3_goldilocks::Goldilocks as PrimeField64>::ORDER_U64 + overflow).to_le_bytes();
			let _hash = hasher.hash_padded_bytes::<C>(&preimage);
		}
	}

	#[test]
	fn test_circuit_preimage() {
		let hasher = Poseidon2Core::new();
		let preimage =
			hex::decode("afd8e7530b95ee5ebab950c9a0c62fae1e80463687b3982233028e914f8ec7cc");
		let hash = hasher.hash_padded_bytes::<C>(&preimage.unwrap());
		let _hash = hasher.hash_padded_bytes::<C>(&hash);
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
			let hash = hasher.hash_padded_bytes::<C>(&preimage);
			let _hash2 = hasher.hash_padded_bytes::<C>(&hash);
		}
	}

	#[test]
	fn test_known_value_hashes() {
		let vectors = [
			(vec![], "405e03f9a0aea73447ad4310e2b225167482e2f2a78d5b402bbfef7b671bfae7"),
			(vec![0u8], "dbb29ba5d3bf3246356a8918dc2808ea5130a9ae02afefe360703afc848d3769"),
			(vec![0u8, 0u8], "23b58c9f2aa60a1677e9bb360be87db2f48f52e8bd2702948f7f11b36cb1d607"),
			(
				vec![0u8, 0u8, 0u8],
				"1799097faca4e7faa34fa7e17c2e16ae281a655cd502f6ef9f1c993d74f161d6",
			),
			(
				vec![0u8, 0u8, 0u8, 0u8],
				"5d1e9b2cdf43cce05de115f156dcf2062e3102341303613eeb1547886ebba4cc",
			),
			(
				vec![0u8, 0u8, 0u8, 1u8],
				"779f5f6d4ae11964fc2efd012bb691899ccc317ed9e186f9efdab73a2bf3af9e",
			),
			(
				vec![1u8, 2, 3, 4, 5, 6, 7, 8],
				"ecdf30787278c049402e704b298c30c7787116d75e4dbcd8ce6b5757ed8833e5",
			),
			(vec![255u8; 32], "fac64f5ed32acfa79a37cd5d1c4e48c67c500ae48043a61a95e51a2e181527ec"),
			(
				b"hello world".to_vec(),
				"95d6a29c17bfd2149cda69c8becbc8cc33c527f39b3a2f7d12865272fd7f5677",
			),
			(
				(0u8..32).collect::<Vec<u8>>(),
				"66f2c7df65a0f456314999fcf95899e27a5a5436cb4f04d79f11f12f8f86f0e0",
			),
		];
		let poseidon = Poseidon2Core::new();
		for (input, expected_hex) in vectors.iter() {
			let hash = poseidon.hash_padded_bytes::<C>(input);
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
	fn test_hash_no_pad() {
		let hasher = Poseidon2Core::new();
		let input = b"test";
		let padded_hash = hasher.hash_padded_bytes::<C>(input);
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
		let hash1 = hasher1.hash_padded_bytes::<C>(input);

		for _ in 0..100 {
			let hasher2 = Poseidon2Core::new();
			let hash2 = hasher2.hash_padded_bytes::<C>(input);
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
