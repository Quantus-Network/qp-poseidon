#![no_std]

extern crate alloc;

#[cfg(feature = "p3")]
pub mod constants;

pub mod serialization;

use crate::serialization::{digest_felts_to_bytes, injective_bytes_to_felts};
use alloc::vec::Vec;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_symmetric::Permutation;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

/// The number of field elements to which inputs are padded in circuit-compatible hashing functions.
pub const FIELD_ELEMENT_PREIMAGE_PADDING_LEN: usize = 189;

// 4 felt output => 4 felt rate per round => capacity = 12 - 4 = 8
// => 256 bits of classical preimage security => 128 bits security against Grover's algorithm
const WIDTH: usize = 12;
const RATE: usize = 4;
const OUTPUT: usize = 4;

// Bring the selected Goldilocks type in as `GF`
#[cfg(feature = "p2")]
pub use serialization::p2_backend::GF as P2GF;
#[cfg(feature = "p3")]
pub use serialization::p3_backend::GF as P3GF;

// Internal state for Poseidon2 hashing
pub struct Poseidon2State {
	poseidon2: Poseidon2Goldilocks<WIDTH>,
	state: [Goldilocks; WIDTH],
	buf: [Goldilocks; RATE],
	buf_len: usize,
}

impl Poseidon2State {
	fn new() -> Self {
		Self {
			poseidon2: constants::create_poseidon(),
			state: [Goldilocks::ZERO; WIDTH],
			buf: [Goldilocks::ZERO; RATE],
			buf_len: 0,
		}
	}

	#[inline]
	fn push_to_buf(&mut self, x: Goldilocks) {
		self.buf[self.buf_len] = x;
		self.buf_len += 1;
		if self.buf_len == RATE {
			self.absorb_full_block();
		}
	}

	#[inline]
	fn absorb_full_block(&mut self) {
		// absorb RATE elements into state, then permute
		for i in 0..RATE {
			self.state[i] += self.buf[i];
		}
		self.poseidon2.permute_mut(&mut self.state);
		self.buf = [Goldilocks::ZERO; RATE];
		self.buf_len = 0;
	}

	fn append(&mut self, blocks: &[Goldilocks]) {
		for &b in blocks {
			self.push_to_buf(b);
		}
	}

	fn append_bytes(&mut self, bytes: &[u8]) {
		let felts = injective_bytes_to_felts(bytes);
		self.append(&felts);
	}

	/// Finalize with variable-length padding (…||1||0* to RATE) and return the full WIDTH state.
	fn finalize_state(mut self) -> [Goldilocks; WIDTH] {
		// message-end '1'
		self.push_to_buf(Goldilocks::ONE);
		// zero-fill remaining of final block
		while self.buf_len != 0 {
			self.push_to_buf(Goldilocks::ZERO);
		}
		self.state
	}

	/// Finalize and return a 32-byte digest (first RATE felts).
	fn finalize(self) -> [u8; 32] {
		let state = self.finalize_state();
		digest_felts_to_bytes(&state[..OUTPUT].try_into().expect("OUTPUT <= WIDTH"))
	}

	/// Finalize and squeeze 64 bytes (two squeezes).
	fn finalize_twice(mut self) -> [u8; 64] {
		// message-end '1'
		self.push_to_buf(Goldilocks::ONE);
		// zero-fill remaining of final block
		while self.buf_len != 0 {
			self.push_to_buf(Goldilocks::ZERO);
		}

		let h1: [u8; 32] =
			digest_felts_to_bytes(&self.state[..RATE].try_into().expect("RATE <= WIDTH"));
		// second squeeze
		self.poseidon2.permute_mut(&mut self.state);
		let h2: [u8; 32] =
			digest_felts_to_bytes(&self.state[..RATE].try_into().expect("RATE <= WIDTH"));

		[h1, h2].concat().try_into().expect("64 bytes")
	}
}

pub fn poseidon2_from_seed(seed: u64) -> Poseidon2State {
	let mut rng = ChaCha20Rng::seed_from_u64(seed);
	let poseidon2 = Poseidon2Goldilocks::<WIDTH>::new_from_rng_128(&mut rng);
	Poseidon2State {
		poseidon2,
		state: [Goldilocks::ZERO; WIDTH],
		buf: [Goldilocks::ZERO; RATE],
		buf_len: 0,
	}
}

// This function is for hashing field elements in the storage trie. It pads to 189 field elements
// because the zk-circuit we use for transaction inclusion verifies a storage proof and requires a
// fixed amount of field elements (the maximum that could be enountered in the storage proof) as a
// preimage
fn hash_circuit_padding_felts<const C: usize>(mut x: Vec<Goldilocks>) -> [u8; 32] {
	// This function doesn't protect against length extension attacks but is safe as
	// long as the input felts are the outputs of an injective encoding.
	// For this reason, we wrap it in hash_padded which performs injective encoding from bytes,
	// so application users are safe.
	let len = x.len();
	if len < C {
		x.resize(C, Goldilocks::ZERO);
	}

	hash_variable_length(x)
}

/// Hash bytes with constant padding to size C to ensure consistent circuit behavior
/// NOTE: Will panic if felt encoded input exceeds capacity of C
pub fn hash_padded_bytes<const C: usize>(x: &[u8]) -> [u8; 32] {
	hash_circuit_padding_felts::<C>(injective_bytes_to_felts(x))
}

/// Hash field elements without any padding
pub fn hash_variable_length(x: Vec<Goldilocks>) -> [u8; 32] {
	let mut st = Poseidon2State::new();
	st.append(&x);
	st.finalize()
}

/// Double hash (preimage -> hash -> hash) field elements without any padding
pub fn double_hash_variable_length(x: Vec<Goldilocks>) -> [u8; 32] {
	let mut st = Poseidon2State::new();
	st.append(&x);
	// Extract first digest
	let state_0 = st.finalize_state();
	let output_0 = &state_0[..OUTPUT];
	// Hash the digest again
	st = Poseidon2State::new();
	st.append(output_0);
	st.finalize()
}

/// Hash bytes without any padding
/// NOTE: Not domain-separated from hash_variable_length; use with caution
pub fn hash_variable_length_bytes(x: &[u8]) -> [u8; 32] {
	let mut st = Poseidon2State::new();
	st.append_bytes(x);
	st.finalize()
}

/// Hash with 512-bit output by squeezing the sponge twice
pub fn hash_squeeze_twice(x: &[u8]) -> [u8; 64] {
	let mut st = Poseidon2State::new();
	st.append_bytes(x);
	st.finalize_twice()
}

#[cfg(test)]
mod tests {
	use crate::serialization::unsafe_digest_bytes_to_felts;

	use super::*;
	use alloc::vec;
	use hex;
	use p3_field::PrimeField64;

	const C: usize = FIELD_ELEMENT_PREIMAGE_PADDING_LEN;

	#[test]
	fn test_empty_input() {
		let result = hash_padded_bytes::<C>(&[]);
		assert_eq!(result.len(), 32);
	}

	#[test]
	fn test_single_byte() {
		let input = vec![42u8];
		let result = hash_padded_bytes::<C>(&input);
		assert_eq!(result.len(), 32);
	}

	#[test]
	fn test_exactly_32_bytes() {
		let input = [1u8; 32];
		let result = hash_padded_bytes::<C>(&input);
		assert_eq!(result.len(), 32);
	}

	#[test]
	fn test_multiple_chunks() {
		let input = [2u8; 64]; // Two chunks
		let result = hash_padded_bytes::<C>(&input);
		assert_eq!(result.len(), 32);
	}

	#[test]
	fn test_partial_chunk() {
		let input = [3u8; 40]; // One full chunk plus 8 bytes
		let result = hash_padded_bytes::<C>(&input);
		assert_eq!(result.len(), 32);
	}

	#[test]
	fn test_consistency() {
		let input = [4u8; 50];
		let iterations = 10;
		let current_hash = hash_padded_bytes::<C>(&input);

		for _ in 0..iterations {
			let hash1 = hash_padded_bytes::<C>(&current_hash);
			let hash2 = hash_padded_bytes::<C>(&current_hash);
			assert_eq!(hash1, hash2, "Hash function should be deterministic");
		}
	}

	#[test]
	fn test_different_inputs() {
		let input1 = [5u8; 32];
		let input2 = [6u8; 32];
		let hash1 = hash_padded_bytes::<C>(&input1);
		let hash2 = hash_padded_bytes::<C>(&input2);
		assert_ne!(hash1, hash2, "Different inputs should produce different hashes");
	}

	#[test]
	fn test_poseidon2_hash_input_sizes() {
		// Test inputs from 1 to 128 bytes
		for size in 1..=128 {
			// Create a predictable input: repeating byte value based on size
			let input: Vec<u8> = (0..size).map(|i| (i * i % 256) as u8).collect();
			let hash = hash_padded_bytes::<C>(&input);

			// Assertions
			assert_eq!(hash.len(), 32, "Input size {} should produce 32-byte hash", size);
		}
	}

	#[test]
	fn test_big_preimage() {
		for overflow in 1..=10 {
			let preimage =
				(<p3_goldilocks::Goldilocks as PrimeField64>::ORDER_U64 + overflow).to_le_bytes();
			let _hash = hash_padded_bytes::<C>(&preimage);
		}
	}

	#[test]
	fn test_circuit_preimage() {
		let preimage =
			hex::decode("afd8e7530b95ee5ebab950c9a0c62fae1e80463687b3982233028e914f8ec7cc");
		let hash = hash_padded_bytes::<C>(&preimage.unwrap());
		let _hash = hash_padded_bytes::<C>(&hash);
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

		for hex_string in hex_strings.iter() {
			let preimage = hex::decode(hex_string).unwrap();
			let hash = hash_padded_bytes::<C>(&preimage);
			let _hash2 = hash_padded_bytes::<C>(&hash);
		}
	}

	#[test]
	fn test_known_value_hashes() {
		let vectors = [
			(
				vec![],
				"89d1c547f1b828c8659fe0600c90d58e95b435d91d04439b67c83b88a679380a",
				"4d8d22af81f6c27a005a07028590ef4ee480f6c4b93f813daf9de47a07c8ae86",
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
		for (input, expected_hex1, expected_hex2) in vectors.iter() {
			let hash = hash_padded_bytes::<C>(input);
			assert_eq!(
				hex::encode(hash.as_slice()),
				*expected_hex1,
				"input: 0x{}",
				hex::encode(input)
			);

			let hash2 = hash_variable_length_bytes(input);
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
		let input = b"test";
		let padded_hash = hash_padded_bytes::<C>(input);
		let no_pad_hash = hash_variable_length_bytes(input);

		// These should be different since one is padded and the other isn't
		assert_ne!(padded_hash, no_pad_hash);
		assert_eq!(padded_hash.len(), 32);
		assert_eq!(no_pad_hash.len(), 32);
	}

	#[test]
	fn test_hash_squeeze_twice() {
		let input = b"test 512-bit hash";
		let hash512 = hash_squeeze_twice(input);

		// Should be exactly 64 bytes
		assert_eq!(hash512.len(), 64);

		// First 32 bytes should be hash of input
		let expected_first = hash_variable_length_bytes(input);
		assert_eq!(&hash512[0..32], &expected_first);

		// Test deterministic
		let hash512_2 = hash_squeeze_twice(input);
		assert_eq!(hash512, hash512_2);

		// Different inputs should produce different outputs
		let different_hash = hash_squeeze_twice(b"different input");
		assert_ne!(hash512, different_hash);
	}

	#[test]
	fn test_double_hash_variable_length() {
		let preimage = b"double hash test";
		let first_hash = hash_variable_length_bytes(preimage);
		let double_hash = double_hash_variable_length(injective_bytes_to_felts(preimage));

		// Double hash should not equal single hash
		assert_ne!(first_hash, double_hash);

		// Double hash should equal hashing the first hash with the hash_variable_length function
		let recomputed_double_hash =
			hash_variable_length(unsafe_digest_bytes_to_felts(&first_hash).to_vec());
		assert_eq!(double_hash, recomputed_double_hash);
	}
}
