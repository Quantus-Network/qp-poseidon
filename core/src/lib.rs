#![no_std]

extern crate alloc;

#[cfg(feature = "p3")]
pub mod constants;

pub mod serialization;

use crate::serialization::{
	digest_felts_to_bytes, injective_bytes_to_felts
};
use alloc::vec::Vec;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_symmetric::Permutation;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

/// The minimum number of field elements to allocate for the preimage.
pub const MIN_FIELD_ELEMENT_PREIMAGE_LEN: usize = 189;

/// Use the first 8 bytes of the pi written out 3.141592653589793
const POSEIDON2_SEED: u64 = 0x3141592653589793;

// 4 felt output => 4 felt rate per round => capacity = 12 - 4 = 8
// => 256 bits of classical preimage security => 128 bits of quantum preimage security
const WIDTH: usize = 12;
const RATE: usize = 4;

// Bring the selected Goldilocks type in as `GF`
#[cfg(feature = "p2")]
pub use serialization::p2_backend::GF as P2GF;
#[cfg(feature = "p3")]
pub use serialization::p3_backend::GF as P3GF;

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
	/// Create a new Poseidon2Core instance deriving constants
	pub fn new_unoptimized() -> Self {
		let mut rng = ChaCha20Rng::seed_from_u64(POSEIDON2_SEED);
		let poseidon2 = Poseidon2Goldilocks::<12>::new_from_rng_128(&mut rng);
		Self { poseidon2 }
	}

	/// Create an optimized Poseidon2Core instance using precomputed constants
	///
	/// This is significantly faster than `new_unoptimized()` since it avoids the expensive
	/// constant derivation process on each instantiation.
	#[cfg(feature = "p3")]
	pub fn new() -> Self {
		let poseidon2 = constants::create_optimized_poseidon2();
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

		self.hash_variable_length(x)
	}

	/// Hash bytes with constant padding to size C to ensure consistent circuit behavior
	/// NOTE: Will panic if felt encoded input exceeds capacity of C
	pub fn hash_padded_bytes<const C: usize>(&self, x: &[u8]) -> [u8; 32] {
		self.hash_circuit_padding_felts::<C>(injective_bytes_to_felts(x))
	}

	/// Hash field elements without any padding
	pub fn hash_variable_length(&self, x: Vec<Goldilocks>) -> [u8; 32] {
		let state = self.hash_variable_length_state(x);

		let result = &state[..RATE];

		digest_felts_to_bytes(result)
	}

	/// Hash field elements with message-end padding of 1 and fill 0 to alignment to RATE
	fn hash_variable_length_state(&self, mut x: Vec<Goldilocks>) -> [Goldilocks; WIDTH] {
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
	/// NOTE: Not domain-separated from hash_variable_length; use with caution
	pub fn hash_variable_length_bytes(&self, x: &[u8]) -> [u8; 32] {
		self.hash_variable_length(injective_bytes_to_felts(x))
	}

	/// Hash with 512-bit output by squeezing the sponge twice
	pub fn hash_squeeze_twice(&self, x: &[u8]) -> [u8; 64] {
		let mut state = self.hash_variable_length_state(injective_bytes_to_felts(x));
		let h1 = digest_felts_to_bytes(&state[..RATE]);
		self.poseidon2.permute_mut(&mut state);
		let h2 = digest_felts_to_bytes(&state[..RATE]);

		let mut result = [0u8; 64];
		result[0..32].copy_from_slice(&h1);
		result[32..64].copy_from_slice(&h2);
		result
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloc::vec;
	use hex;
	use p3_field::PrimeField64;

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
			(
			    vec![], 
				"405e03f9a0aea73447ad4310e2b225167482e2f2a78d5b402bbfef7b671bfae7",
				"1c72d2c98082a45bf49dc58bc06fd3f4a5155aa3bc924267fea3735ccdd59b34"
			),
			(
			    vec![0u8], 
				"dbb29ba5d3bf3246356a8918dc2808ea5130a9ae02afefe360703afc848d3769",
				"8f5b42e350ff5a12788210c86c2bcd49243b8f9350de818b3b0c56839a42ebad",
			),
			(
			    vec![0u8, 0u8], 
				"23b58c9f2aa60a1677e9bb360be87db2f48f52e8bd2702948f7f11b36cb1d607",
				"3e6ee24fb61a22f4d825b72fc8ebd359e3b3b9566e246c71c3e450ebe3262f9c",
			),
			(
				vec![0u8, 0u8, 0u8],
				"1799097faca4e7faa34fa7e17c2e16ae281a655cd502f6ef9f1c993d74f161d6",
				"34f4338a6f1b671062a3ac00b37ca05a47b43e16e589ccaa5b063416ba42356b",
			),
			(
				vec![0u8, 0u8, 0u8, 0u8],
				"5d1e9b2cdf43cce05de115f156dcf2062e3102341303613eeb1547886ebba4cc",
				"7bac8c6bc49b0b750f2ce0912b815a2cb4ae20c75ac430850257882d9d321afa",
			),
			(
				vec![0u8, 0u8, 0u8, 0u8, 0u8],
				"d941bb3132ac34a919add937354f09cf302c5e972411c1854f2e5ebf5b054fc4",
				"c95cfddb573adf4070b3d7c8d2dfbbee48b4b973d80cbda2b458abe7bb6f0def",
			),
			(
				vec![0u8, 0u8, 0u8, 0u8, 0u8, 0u8],
				"8d2fdb09cd31ab6fd59f0b429d50684a6425a7f21bc5e32e38ab19ced4fc5492",
				"a4dc08d0a8c5ea44007462fe1fd8e45962d4ea85c420eab4140fbb30b5b5e111",
			),
			(
				vec![0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8],
				"490936de1357c80889dd9fee7f0ee58e7d7fe4c11e66bda55fa860bb6b94cddd",
				"b01975012df91d9f9f040c34655f23f3ec1f6d1738d85679e9848143756637c9",
			),
			(
				vec![0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8],
				"eaa5c78853eac1ee6240512dd85077776ec909186fe46ec463e167790d768a40",
				"eacd9e48d2e968131e48c8e69f2a211cc06c7778db6c5467348b45418fc7f585",
			),
			(
				vec![0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8],
				"2d2822c6cc2fd816ceb90cd9561bb1f5eb1638c2574b838a16b426e01d929928",
				"00df670e8ec0751d3fb9b5f0281d0af9a7a82f62ad35a21247a9d6117daec151",
			),
			(
				vec![0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8],
				"9cd82ca4f742f54f62d577b3254d5138e4f5c9eea3f4173a6c1733c08cff79f2",
				"6488c3c47c17114e3998bf90d6c50dc323a82e6e91768dca6977cfe152415ad5",
			),
			(
				vec![0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8],
				"9794607d182df1504c1a5af25d51105332b4520c06e9c669669a4060e704b15c",
				"a5ba11e5959cdb59e6b2b0d25d470d656caf59aae961b52c159ffd6e0f04baff",
			),
			(
				vec![0u8, 0u8, 0u8, 1u8],
				"779f5f6d4ae11964fc2efd012bb691899ccc317ed9e186f9efdab73a2bf3af9e",
				"6ffff0c97262139567c426e916c1fd70c924010153c366bb2a8957ea89902942",
			),
			(
				vec![1u8, 2, 3, 4, 5, 6, 7, 8],
				"ecdf30787278c049402e704b298c30c7787116d75e4dbcd8ce6b5757ed8833e5",
				"131020b2e74819343f8568258ae2e9717e9b2253d57baabab78a518bc7499a8b",
			),
			(
			    vec![255u8; 32], 
				"fac64f5ed32acfa79a37cd5d1c4e48c67c500ae48043a61a95e51a2e181527ec",
				"05a90ac8e3c4b7635fa3735c3a9c4fef620479fa68a9e4ae1421c39aa6939125",
			),
			(
				b"hello world".to_vec(),
				"95d6a29c17bfd2149cda69c8becbc8cc33c527f39b3a2f7d12865272fd7f5677",
				"fd1f5d7d4701c25bbdd5dd6e3be6abb474fffbaa402f814dce95f8283abbf3e7",
			),
			(
				(0u8..32).collect::<Vec<u8>>(),
				"66f2c7df65a0f456314999fcf95899e27a5a5436cb4f04d79f11f12f8f86f0e0",
				"2e3e4a00be0d8520cddaf3000d98c1f1d73c19bfe9fe181694bfa9afdfce7687",
			),
		];
		let poseidon = Poseidon2Core::new();
		for (input, expected_hex1, expected_hex2) in vectors.iter() {
			let hash = poseidon.hash_padded_bytes::<C>(input);
			assert_eq!(
				hex::encode(hash.as_slice()),
				*expected_hex1,
				"input: 0x{}",
				hex::encode(input)
			);

			let hash2 = poseidon.hash_variable_length_bytes(input);
			assert_eq!(
				hex::encode(hash2.as_slice()),
				*expected_hex2,
				"input: 0x{}",
				hex::encode(input)
			);

		}

	}


	#[test]
	fn test_hash_variable_length() {
		let hasher = Poseidon2Core::new();
		let input = b"test";
		let padded_hash = hasher.hash_padded_bytes::<C>(input);
		let no_pad_hash = hasher.hash_variable_length_bytes(input);

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
		let expected_first = hasher.hash_variable_length_bytes(input);
		assert_eq!(&hash512[0..32], &expected_first);

		// Test deterministic
		let hash512_2 = hasher.hash_squeeze_twice(input);
		assert_eq!(hash512, hash512_2);

		// Different inputs should produce different outputs
		let different_hash = hasher.hash_squeeze_twice(b"different input");
		assert_ne!(hash512, different_hash);
	}
}
