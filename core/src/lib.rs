#![no_std]

extern crate alloc;

use qp_poseidon_constants as constants;

pub mod serialization;

use crate::serialization::{
	digest_felts_to_bytes, injective_bytes_to_felts, non_injective_bytes_to_felts,
};
use alloc::vec::Vec;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_symmetric::Permutation;
use qp_poseidon_constants::{POSEIDON2_OUTPUT, SPONGE_RATE, SPONGE_WIDTH};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

/// The number of field elements to which inputs are padded in circuit-compatible hashing functions.
pub const FIELD_ELEMENT_PREIMAGE_PADDING_LEN: usize = 80;

// Internal state for Poseidon2 hashing
pub struct Poseidon2State {
	poseidon2: Poseidon2Goldilocks<SPONGE_WIDTH>,
	state: [Goldilocks; SPONGE_WIDTH],
	buf: [Goldilocks; SPONGE_RATE],
	buf_len: usize,
}

impl Poseidon2State {
	fn new() -> Self {
		Self {
			poseidon2: constants::create_poseidon(),
			state: [Goldilocks::ZERO; SPONGE_WIDTH],
			buf: [Goldilocks::ZERO; SPONGE_RATE],
			buf_len: 0,
		}
	}

	#[inline]
	fn push_to_buf(&mut self, x: Goldilocks) {
		self.buf[self.buf_len] = x;
		self.buf_len += 1;
		if self.buf_len == SPONGE_RATE {
			self.absorb_full_block();
		}
	}

	#[inline]
	fn absorb_full_block(&mut self) {
		// absorb SPONGE_RATE elements into state, then permute
		for i in 0..SPONGE_RATE {
			self.state[i] += self.buf[i];
		}
		self.poseidon2.permute_mut(&mut self.state);
		self.buf = [Goldilocks::ZERO; SPONGE_RATE];
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

	/// Finalize with variable-length padding (…||1||0* to SPONGE_RATE) and return the full state.
	fn finalize_state(mut self) -> [Goldilocks; SPONGE_WIDTH] {
		// message-end '1'
		self.push_to_buf(Goldilocks::ONE);
		// zero-fill remaining of final block
		while self.buf_len != 0 {
			self.push_to_buf(Goldilocks::ZERO);
		}
		self.state
	}

	/// Finalize and return a 32-byte digest (first POSEIDON2_OUTPUT felts).
	fn finalize(self) -> [u8; 32] {
		let state = self.finalize_state();
		digest_felts_to_bytes(
			&state[..POSEIDON2_OUTPUT]
				.try_into()
				.expect("POSEIDON2_OUTPUT finalize <= SPONGE_WIDTH"),
		)
	}

	/// Finalize and squeeze 64 bytes (two squeezes).
	fn finalize_twice(mut self) -> [u8; 64] {
		// message-end '1'
		self.push_to_buf(Goldilocks::ONE);
		// zero-fill remaining of final block
		while self.buf_len != 0 {
			self.push_to_buf(Goldilocks::ZERO);
		}

		let h1: [u8; 32] = digest_felts_to_bytes(
			&self.state[..POSEIDON2_OUTPUT]
				.try_into()
				.expect("POSEIDON2_OUTPUT <= SPONGE_WIDTH"),
		);
		// second squeeze
		self.poseidon2.permute_mut(&mut self.state);
		let h2: [u8; 32] = digest_felts_to_bytes(
			&self.state[..POSEIDON2_OUTPUT]
				.try_into()
				.expect("POSEIDON2_OUTPUT second squeeze <= SPONGE_WIDTH"),
		);

		[h1, h2].concat().try_into().expect("64 bytes")
	}
}

pub fn poseidon2_from_seed(seed: u64) -> Poseidon2State {
	let mut rng = ChaCha20Rng::seed_from_u64(seed);
	let poseidon2 = Poseidon2Goldilocks::<SPONGE_WIDTH>::new_from_rng_128(&mut rng);
	Poseidon2State {
		poseidon2,
		state: [Goldilocks::ZERO; SPONGE_WIDTH],
		buf: [Goldilocks::ZERO; SPONGE_RATE],
		buf_len: 0,
	}
}

fn hash_circuit_padding_felts<const C: usize>(mut x: Vec<Goldilocks>) -> [u8; 32] {
	let len = x.len();
	if len < C {
		x.resize(C, Goldilocks::ZERO);
	}

	hash_variable_length(x)
}

/// Hash bytes with constant padding to size C to ensure consistent circuit behavior.
/// Pads to C elements if shorter; no padding if C or more elements.
pub fn hash_padded_bytes<const C: usize>(x: &[u8]) -> [u8; 32] {
	hash_circuit_padding_felts::<C>(injective_bytes_to_felts(x))
}

/// Hash bytes with non-injective encoding and constant padding to size C.
/// Uses 8 bytes per felt (vs 4 for injective). Not collision-resistant for variable-length inputs.
/// Pads to C elements if shorter; no padding if C or more elements.
pub fn hash_padded_bytes_non_injective<const C: usize>(x: &[u8]) -> [u8; 32] {
	hash_circuit_padding_felts::<C>(non_injective_bytes_to_felts(x))
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
	let output_0 = &state_0[..POSEIDON2_OUTPUT];
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
				"55334d59983b44a3f2d665c2cc0deac520503820c2f250f5ab6edb037c73caea",
				"4d8d22af81f6c27a005a07028590ef4ee480f6c4b93f813daf9de47a07c8ae86",
			),
			(
				vec![0u8],
				"57c635f16d94de8936a4d0a0856501e1130e74a6fad0d588cd2b92e3b2006bae",
				"8f5b42e350ff5a12788210c86c2bcd49243b8f9350de818b3b0c56839a42ebad",
			),
			(
				vec![0u8, 0u8],
				"2eb8c89584a5838e26263204f741981fd6fead53736991652c4896764266422e",
				"3e6ee24fb61a22f4d825b72fc8ebd359e3b3b9566e246c71c3e450ebe3262f9c",
			),
			(
				vec![0u8, 0u8, 0u8],
				"e7fc4ca465774d1aa97377c9c11af0e374d02cbe925a3fe5fd8c031db28c9b03",
				"34f4338a6f1b671062a3ac00b37ca05a47b43e16e589ccaa5b063416ba42356b",
			),
			(
				vec![0u8, 0u8, 0u8, 0u8],
				"479b6f46eb42ce8e6a8aecc552a2ee240a39d59c88cc9a8474c2b0b690303f66",
				"7bac8c6bc49b0b750f2ce0912b815a2cb4ae20c75ac430850257882d9d321afa",
			),
			(
				vec![0u8, 0u8, 0u8, 0u8, 0u8],
				"b7b00d9f32b25353e426583a2805bf750a9a64b9d2c21d606ef1e04e2efe1546",
				"c95cfddb573adf4070b3d7c8d2dfbbee48b4b973d80cbda2b458abe7bb6f0def",
			),
			(
				vec![0u8, 0u8, 0u8, 0u8, 0u8, 0u8],
				"c89c1b7e4eb764bbaa67789d5d3ebfa0c937f14abff4899cf43345c0c9597b2a",
				"a4dc08d0a8c5ea44007462fe1fd8e45962d4ea85c420eab4140fbb30b5b5e111",
			),
			(
				vec![0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8],
				"c5eb1fba387c58329ce040da2957d346c279fddeb0c939f03d755d914f0f1453",
				"b01975012df91d9f9f040c34655f23f3ec1f6d1738d85679e9848143756637c9",
			),
			(
				vec![0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8],
				"8bc5641f1bdc24671962aa16d8b04c590227b41a8fec3f6c93a5a58ff55f82dd",
				"eacd9e48d2e968131e48c8e69f2a211cc06c7778db6c5467348b45418fc7f585",
			),
			(
				vec![0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8],
				"b9b8e15cb341ba3f8a0cb308d1f688b31672363dc91bbcc7c7851f426283b60c",
				"00df670e8ec0751d3fb9b5f0281d0af9a7a82f62ad35a21247a9d6117daec151",
			),
			(
				vec![0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8],
				"23723c463921f216a0a11cf0dbc3e8f8efe1a58c77cfeee04056777ff41b1d59",
				"d6182896f274c5d9640972e2bf2a5e893e516a21adfdd8ebd39969128d619934",
			),
			(
				vec![0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8],
				"5914c2191325e6b4c6e0682890aec6c1842534881488ca896764c58d05afceac",
				"15fc2f3c3bc51c96797b889d4fecfcd3535b959f510c007598a87f099e356303",
			),
			(
				vec![0u8, 0u8, 0u8, 1u8],
				"c157c163cf6e476ecc83bdb70e3d3cf7c33522ed649da75a77c0a63512f8325c",
				"6ffff0c97262139567c426e916c1fd70c924010153c366bb2a8957ea89902942",
			),
			(
				vec![1u8, 2, 3, 4, 5, 6, 7, 8],
				"4030ecfc78d7a57f683a73e39bebcb020b670cb72e55712b4159b34405e870a0",
				"131020b2e74819343f8568258ae2e9717e9b2253d57baabab78a518bc7499a8b",
			),
			(
				vec![255u8; 32],
				"6e0e281ff27d6e0d7ec1f482cbe16183b962c7c4f6cbd624205bf8961effcb6c",
				"41260a4322e97dc3dda2b5f70b5ffb1b43071ad5510e101f34209721042c0987",
			),
			(
				b"hello world".to_vec(),
				"05fb9811b47254651831fee2d611b94c1d71e78bedb50fed479192096bef6608",
				"fd1f5d7d4701c25bbdd5dd6e3be6abb474fffbaa402f814dce95f8283abbf3e7",
			),
			(
				(0u8..32).collect::<Vec<u8>>(),
				"3b280392f79bf5d238d2835d94cc43a297bfd42b8f4a1563528009e52a1014d2",
				"36884f9093be80632397f5736dce2fece627a4182daf3cdbf8bf12c8e3e02668",
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
