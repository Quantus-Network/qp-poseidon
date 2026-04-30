#![no_std]

extern crate alloc;

use qp_poseidon_constants as constants;

pub mod serialization;

use crate::serialization::{bytes_to_felts, bytes_to_felts_compact};
use alloc::vec::Vec;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_symmetric::Permutation;
use qp_poseidon_constants::{POSEIDON2_OUTPUT, SPONGE_RATE, SPONGE_WIDTH};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

// ============================================================================
// Compact Encoding Parameters (for storage trie hashing)
// ============================================================================

/// Bytes per field element in compact encoding.
/// Uses the full 8-byte capacity of Goldilocks field elements.
pub const COMPACT_BYTES_PER_FELT: usize = 8;

/// Maximum size of a storage proof node in bytes.
/// Worst-case branch node: 8 (header) + 32 (partial key) + 8 (bitmap) + 512 (16 children) + 40
/// (value) = 600 bytes. We use 640 bytes to provide some margin.
pub const PROOF_NODE_MAX_SIZE_BYTES: usize = 640;

/// Maximum storage proof node size in field elements using compact encoding (8 bytes/felt).
/// This is the single source of truth for circuit witness sizing.
pub const PROOF_NODE_MAX_SIZE_FELTS: usize = PROOF_NODE_MAX_SIZE_BYTES / COMPACT_BYTES_PER_FELT; // = 80

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
		let felts = bytes_to_felts(bytes);
		self.append(&felts);
	}

	fn finalize_state(mut self) -> [Goldilocks; SPONGE_WIDTH] {
		self.push_to_buf(Goldilocks::ONE);
		while self.buf_len != 0 {
			self.push_to_buf(Goldilocks::ZERO);
		}
		self.state
	}

	fn finalize_to_felts(self) -> [Goldilocks; POSEIDON2_OUTPUT] {
		let state = self.finalize_state();
		state[..POSEIDON2_OUTPUT].try_into().expect("POSEIDON2_OUTPUT <= SPONGE_WIDTH")
	}

	fn finalize_to_bytes(self) -> [u8; 32] {
		serialization::digest_to_bytes(&self.finalize_to_felts())
	}

	fn finalize_squeeze_twice(mut self) -> [u8; 64] {
		self.push_to_buf(Goldilocks::ONE);
		while self.buf_len != 0 {
			self.push_to_buf(Goldilocks::ZERO);
		}

		let h1: [u8; 32] = serialization::digest_to_bytes(
			self.state[..POSEIDON2_OUTPUT]
				.try_into()
				.expect("POSEIDON2_OUTPUT <= SPONGE_WIDTH"),
		);
		self.poseidon2.permute_mut(&mut self.state);
		let h2: [u8; 32] = serialization::digest_to_bytes(
			self.state[..POSEIDON2_OUTPUT]
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

fn pad_and_hash<const C: usize>(mut x: Vec<Goldilocks>) -> [Goldilocks; POSEIDON2_OUTPUT] {
	let len = x.len();
	if len < C {
		x.resize(C, Goldilocks::ZERO);
	}
	hash_to_felts(&x)
}

// ============================================================================
// Public hash functions
// ============================================================================

/// Hash field elements to 4 field elements (native Poseidon2 output).
///
/// This is the primary hash function. Use this when you need to chain hashes
/// or work with field elements directly (e.g., in circuits).
pub fn hash_to_felts(x: &[Goldilocks]) -> [Goldilocks; POSEIDON2_OUTPUT] {
	let mut st = Poseidon2State::new();
	st.append(x);
	st.finalize_to_felts()
}

/// Hash field elements to a 32-byte digest.
///
/// Converts the 4-felt hash output to bytes (8 bytes per felt).
/// Use this when you need bytes for storage, transmission, or display.
pub fn hash_to_bytes(x: &[Goldilocks]) -> [u8; 32] {
	let mut st = Poseidon2State::new();
	st.append(x);
	st.finalize_to_bytes()
}

/// Hash bytes to a 32-byte digest.
///
/// Converts bytes to field elements (4 bytes per felt with terminator),
/// then hashes the resulting field elements.
pub fn hash_bytes(x: &[u8]) -> [u8; 32] {
	let mut st = Poseidon2State::new();
	st.append_bytes(x);
	st.finalize_to_bytes()
}

/// Hash bytes for circuit compatibility using compact encoding (8 bytes/felt).
///
/// Converts bytes to field elements using compact encoding, then hashes. If the
/// resulting field element count is less than C, the input is zero-padded to
/// exactly C elements before hashing.
///
/// Use this when the hash must match an in-circuit computation with fixed input size.
/// The compact encoding uses 8 bytes per felt (vs 4 bytes/felt in injective encoding),
/// resulting in ~50% fewer constraints in ZK circuits.
pub fn hash_for_circuit<const C: usize>(x: &[u8]) -> [u8; 32] {
	hash_felts_for_circuit::<C>(bytes_to_felts_compact(x))
}

/// Hash field elements for circuit compatibility.
///
/// If the input has fewer than C elements, it is zero-padded to exactly C elements
/// before hashing. Use this when the hash must match an in-circuit computation with
/// fixed input size.
pub fn hash_felts_for_circuit<const C: usize>(x: Vec<Goldilocks>) -> [u8; 32] {
	serialization::digest_to_bytes(&pad_and_hash::<C>(x))
}

/// Double hash: hash(hash(input)), returning 4 field elements.
///
/// The inner hash output (4 felts) is re-hashed directly as field elements.
/// Used for wormhole address derivation.
pub fn hash_twice_to_felts(x: &[Goldilocks]) -> [Goldilocks; POSEIDON2_OUTPUT] {
	let inner = hash_to_felts(x);
	hash_to_felts(&inner)
}

/// Double hash: hash(hash(input)), returning bytes.
///
/// The inner hash output (4 felts) is re-hashed directly as field elements.
/// Used for wormhole address derivation.
pub fn hash_twice(x: &[Goldilocks]) -> [u8; 32] {
	serialization::digest_to_bytes(&hash_twice_to_felts(x))
}

/// Re-hash a 32-byte digest to produce a new 32-byte digest.
///
/// Decodes the input bytes as 4 field elements (8 bytes/felt), hashes them,
/// and returns the result as 32 bytes. Use this when chaining hash outputs.
pub fn rehash_to_bytes(x: &[u8; 32]) -> [u8; 32] {
	let felts: [Goldilocks; POSEIDON2_OUTPUT] = serialization::bytes_to_digest(x);
	hash_to_bytes(&felts)
}

/// Hash with 512-bit output by squeezing the sponge twice.
///
/// Returns 64 bytes: first 32 from initial squeeze, next 32 from second squeeze.
/// Used for mining proof-of-work.
pub fn hash_squeeze_twice(x: &[u8]) -> [u8; 64] {
	let mut st = Poseidon2State::new();
	st.append_bytes(x);
	st.finalize_squeeze_twice()
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::alloc::string::ToString;
	use alloc::{format, vec};
	use p3_field::PrimeField64;

	const C: usize = PROOF_NODE_MAX_SIZE_FELTS;

	#[test]
	fn test_empty_input() {
		let result = hash_for_circuit::<C>(&[]);
		assert_eq!(result.len(), 32);
	}

	#[test]
	fn test_single_byte() {
		let input = vec![42u8];
		let result = hash_for_circuit::<C>(&input);
		assert_eq!(result.len(), 32);
	}

	#[test]
	fn test_exactly_32_bytes() {
		let input = [1u8; 32];
		let result = hash_for_circuit::<C>(&input);
		assert_eq!(result.len(), 32);
	}

	#[test]
	fn test_multiple_chunks() {
		let input = [2u8; 64];
		let result = hash_for_circuit::<C>(&input);
		assert_eq!(result.len(), 32);
	}

	#[test]
	fn test_partial_chunk() {
		let input = [3u8; 40];
		let result = hash_for_circuit::<C>(&input);
		assert_eq!(result.len(), 32);
	}

	#[test]
	fn test_consistency() {
		let input = [4u8; 50];
		let iterations = 10;
		let current_hash = hash_for_circuit::<C>(&input);

		for _ in 0..iterations {
			let hash1 = hash_for_circuit::<C>(&current_hash);
			let hash2 = hash_for_circuit::<C>(&current_hash);
			assert_eq!(hash1, hash2, "Hash function should be deterministic");
		}
	}

	#[test]
	fn test_different_inputs() {
		let input1 = [5u8; 32];
		let input2 = [6u8; 32];
		let hash1 = hash_for_circuit::<C>(&input1);
		let hash2 = hash_for_circuit::<C>(&input2);
		assert_ne!(hash1, hash2, "Different inputs should produce different hashes");
	}

	#[test]
	fn test_poseidon2_hash_input_sizes() {
		for size in 1..=128 {
			let input: Vec<u8> = (0..size).map(|i| (i * i % 256) as u8).collect();
			let hash = hash_for_circuit::<C>(&input);
			assert_eq!(hash.len(), 32, "Input size {} should produce 32-byte hash", size);
		}
	}

	#[test]
	fn test_big_preimage() {
		for overflow in 1..=10 {
			let preimage =
				(<p3_goldilocks::Goldilocks as PrimeField64>::ORDER_U64 + overflow).to_le_bytes();
			let _hash = hash_for_circuit::<C>(&preimage);
		}
	}

	#[test]
	fn test_circuit_preimage() {
		let preimage =
			hex::decode("afd8e7530b95ee5ebab950c9a0c62fae1e80463687b3982233028e914f8ec7cc");
		let hash = hash_for_circuit::<C>(&preimage.unwrap());
		let _hash = hash_for_circuit::<C>(&hash);
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
			let hash = hash_for_circuit::<C>(&preimage);
			let _hash2 = hash_for_circuit::<C>(&hash);
		}
	}

	#[test]
	fn test_hash_bytes_vs_circuit() {
		let input = b"test";
		let circuit_hash = hash_for_circuit::<C>(input);
		let no_pad_hash = hash_bytes(input);

		// These should be different since one is padded and the other isn't
		assert_ne!(circuit_hash, no_pad_hash);
		assert_eq!(circuit_hash.len(), 32);
		assert_eq!(no_pad_hash.len(), 32);
	}

	#[test]
	fn test_hash_squeeze_twice() {
		let input = b"test 512-bit hash";
		let hash512 = hash_squeeze_twice(input);

		assert_eq!(hash512.len(), 64);

		let expected_first = hash_bytes(input);
		assert_eq!(&hash512[0..32], &expected_first);

		let hash512_2 = hash_squeeze_twice(input);
		assert_eq!(hash512, hash512_2);

		let different_hash = hash_squeeze_twice(b"different input");
		assert_ne!(hash512, different_hash);
	}

	#[test]
	fn test_hash_twice() {
		let preimage = b"double hash test";
		let input_felts = bytes_to_felts(preimage);

		let first_hash_felts = hash_to_felts(&input_felts);
		let first_hash_bytes = hash_to_bytes(&input_felts);

		let double_hash_bytes = hash_twice(&input_felts);
		let double_hash_felts = hash_twice_to_felts(&input_felts);

		assert_ne!(first_hash_bytes, double_hash_bytes);

		let manual_double = hash_to_felts(&first_hash_felts);
		assert_eq!(double_hash_felts, manual_double);

		assert_eq!(serialization::digest_to_bytes(&double_hash_felts), double_hash_bytes);

		let double_hash_again = hash_twice(&input_felts);
		assert_eq!(double_hash_bytes, double_hash_again);
	}

	#[test]
	fn test_hash_to_felts_and_bytes_consistency() {
		let input = bytes_to_felts(b"test input");
		let hash_felts_result = hash_to_felts(&input);
		let hash_bytes_result = hash_to_bytes(&input);

		assert_eq!(serialization::digest_to_bytes(&hash_felts_result), hash_bytes_result);

		let roundtrip =
			serialization::digest_to_bytes(&serialization::bytes_to_digest(&hash_bytes_result));
		assert_eq!(roundtrip, hash_bytes_result);
	}

	#[test]
	fn test_hash_chaining() {
		let input = bytes_to_felts(b"chain test");
		let h1 = hash_to_felts(&input);
		let h2 = hash_to_felts(&h1);
		let h3 = hash_to_felts(&h2);

		assert_ne!(h1, h2);
		assert_ne!(h2, h3);
		assert_ne!(h1, h3);

		let h1_again = hash_to_felts(&input);
		assert_eq!(h1, h1_again);
	}

	#[test]
	fn test_rehash_equals_hash_twice() {
		// This test verifies that the two-step process used in wormhole derivation
		// (hash_to_bytes followed by rehash_to_bytes) produces the same result
		// as the direct hash_twice function.
		let input = bytes_to_felts(b"wormhole derivation test");

		// Method 1: hash_twice (direct double hash)
		let double_hash = hash_twice(&input);

		// Method 2: hash_to_bytes then rehash_to_bytes (used in chain for wormhole)
		let first_hash = hash_to_bytes(&input);
		let rehashed = rehash_to_bytes(&first_hash);

		assert_eq!(
			double_hash, rehashed,
			"hash_twice and hash_to_bytes+rehash_to_bytes should produce identical results"
		);

		// Also verify with different inputs
		for test_input in [b"secret1".as_slice(), b"another_secret", b""] {
			let felts = bytes_to_felts(test_input);
			let via_hash_twice = hash_twice(&felts);
			let via_rehash = rehash_to_bytes(&hash_to_bytes(&felts));
			assert_eq!(via_hash_twice, via_rehash);
		}
	}

	/// Helper to generate test vectors - run with: cargo test generate_test_vectors -- --nocapture
	/// Then copy the output into test_known_value_hashes
	#[test]
	fn generate_test_vectors() {
		extern crate std;
		use std::println;

		let inputs: [Vec<u8>; 18] = [
			vec![],
			vec![0u8],
			vec![0u8, 0u8],
			vec![0u8, 0u8, 0u8],
			vec![0u8, 0u8, 0u8, 0u8],
			vec![0u8, 0u8, 0u8, 0u8, 0u8],
			vec![0u8, 0u8, 0u8, 0u8, 0u8, 0u8],
			vec![0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8],
			vec![0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8],
			vec![0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8],
			vec![0u8; 14],
			vec![0u8; 15],
			vec![0u8, 0u8, 0u8, 1u8],
			vec![1u8, 2, 3, 4, 5, 6, 7, 8],
			vec![255u8; 32],
			b"hello world".to_vec(),
			(0u8..32).collect::<Vec<u8>>(),
			(0u8..64).collect::<Vec<u8>>(),
		];

		println!("\n// Generated test vectors - copy into test_known_value_hashes:");
		println!("let vectors: [(Vec<u8>, &str, &str); 18] = [");
		for (i, input) in inputs.iter().enumerate() {
			let circuit_hash = hash_for_circuit::<C>(input);
			let bytes_hash = hash_bytes(input);
			let input_repr = match i {
				0 => "vec![]".to_string(),
				1..=9 => format!(
					"vec![{}]",
					input.iter().map(|b| format!("{}u8", b)).collect::<Vec<_>>().join(", ")
				),
				10 => "vec![0u8; 14]".to_string(),
				11 => "vec![0u8; 15]".to_string(),
				12 => "vec![0u8, 0u8, 0u8, 1u8]".to_string(),
				13 => "vec![1u8, 2, 3, 4, 5, 6, 7, 8]".to_string(),
				14 => "vec![255u8; 32]".to_string(),
				15 => "b\"hello world\".to_vec()".to_string(),
				16 => "(0u8..32).collect::<Vec<u8>>()".to_string(),
				17 => "(0u8..64).collect::<Vec<u8>>()".to_string(),
				_ => unreachable!(),
			};
			println!(
				"\t({}, \"{}\", \"{}\"),",
				input_repr,
				hex::encode(circuit_hash),
				hex::encode(bytes_hash)
			);
		}
		println!("];");
	}

	/// Known Answer Tests (KAT) for hash functions.
	/// These test vectors ensure hash outputs remain stable across versions.
	/// Format: (input_bytes, hash_for_circuit_output, hash_bytes_output)
	#[test]
	fn test_known_value_hashes() {
		// Generated test vectors - copy into test_known_value_hashes:
		let vectors: [(Vec<u8>, &str, &str); 18] = [
			(
				vec![],
				"f65f4601aae1cec423d21750d4010f1653db3332655aae3e50cff3d08db9a1bb",
				"4d8d22af81f6c27a005a07028590ef4ee480f6c4b93f813daf9de47a07c8ae86",
			),
			(
				vec![0u8],
				"f65f4601aae1cec423d21750d4010f1653db3332655aae3e50cff3d08db9a1bb",
				"8f5b42e350ff5a12788210c86c2bcd49243b8f9350de818b3b0c56839a42ebad",
			),
			(
				vec![0u8, 0u8],
				"f65f4601aae1cec423d21750d4010f1653db3332655aae3e50cff3d08db9a1bb",
				"3e6ee24fb61a22f4d825b72fc8ebd359e3b3b9566e246c71c3e450ebe3262f9c",
			),
			(
				vec![0u8, 0u8, 0u8],
				"f65f4601aae1cec423d21750d4010f1653db3332655aae3e50cff3d08db9a1bb",
				"34f4338a6f1b671062a3ac00b37ca05a47b43e16e589ccaa5b063416ba42356b",
			),
			(
				vec![0u8, 0u8, 0u8, 0u8],
				"f65f4601aae1cec423d21750d4010f1653db3332655aae3e50cff3d08db9a1bb",
				"7bac8c6bc49b0b750f2ce0912b815a2cb4ae20c75ac430850257882d9d321afa",
			),
			(
				vec![0u8, 0u8, 0u8, 0u8, 0u8],
				"f65f4601aae1cec423d21750d4010f1653db3332655aae3e50cff3d08db9a1bb",
				"c95cfddb573adf4070b3d7c8d2dfbbee48b4b973d80cbda2b458abe7bb6f0def",
			),
			(
				vec![0u8, 0u8, 0u8, 0u8, 0u8, 0u8],
				"f65f4601aae1cec423d21750d4010f1653db3332655aae3e50cff3d08db9a1bb",
				"a4dc08d0a8c5ea44007462fe1fd8e45962d4ea85c420eab4140fbb30b5b5e111",
			),
			(
				vec![0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8],
				"f65f4601aae1cec423d21750d4010f1653db3332655aae3e50cff3d08db9a1bb",
				"b01975012df91d9f9f040c34655f23f3ec1f6d1738d85679e9848143756637c9",
			),
			(
				vec![0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8],
				"f65f4601aae1cec423d21750d4010f1653db3332655aae3e50cff3d08db9a1bb",
				"eacd9e48d2e968131e48c8e69f2a211cc06c7778db6c5467348b45418fc7f585",
			),
			(
				vec![0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8],
				"f65f4601aae1cec423d21750d4010f1653db3332655aae3e50cff3d08db9a1bb",
				"00df670e8ec0751d3fb9b5f0281d0af9a7a82f62ad35a21247a9d6117daec151",
			),
			(
				vec![0u8; 14],
				"f65f4601aae1cec423d21750d4010f1653db3332655aae3e50cff3d08db9a1bb",
				"d6182896f274c5d9640972e2bf2a5e893e516a21adfdd8ebd39969128d619934",
			),
			(
				vec![0u8; 15],
				"f65f4601aae1cec423d21750d4010f1653db3332655aae3e50cff3d08db9a1bb",
				"15fc2f3c3bc51c96797b889d4fecfcd3535b959f510c007598a87f099e356303",
			),
			(
				vec![0u8, 0u8, 0u8, 1u8],
				"e7fc4ca465774d1aa97377c9c11af0e374d02cbe925a3fe5fd8c031db28c9b03",
				"6ffff0c97262139567c426e916c1fd70c924010153c366bb2a8957ea89902942",
			),
			(
				vec![1u8, 2, 3, 4, 5, 6, 7, 8],
				"1b34c6db4eae6950ad48a63d31f846a1e7d140e6ecccb50a712ce6a9d536e5da",
				"131020b2e74819343f8568258ae2e9717e9b2253d57baabab78a518bc7499a8b",
			),
			(
				vec![255u8; 32],
				"4e6ec9a3d2beb1b978d38f6a5e0181d762a02e68a9647194a52b1db0cfa74985",
				"41260a4322e97dc3dda2b5f70b5ffb1b43071ad5510e101f34209721042c0987",
			),
			(
				b"hello world".to_vec(),
				"6c2f70750bd9ceafc7802e8bfd7f2e12ae018d55ba76c56cf5e5e2ca66381635",
				"fd1f5d7d4701c25bbdd5dd6e3be6abb474fffbaa402f814dce95f8283abbf3e7",
			),
			(
				(0u8..32).collect::<Vec<u8>>(),
				"9afdc770a4de1e6f6a5acdbce33c895608e0ef4e0df29c7dd3bb55166fc3aeb4",
				"36884f9093be80632397f5736dce2fece627a4182daf3cdbf8bf12c8e3e02668",
			),
			(
				(0u8..64).collect::<Vec<u8>>(),
				"89fcde335d31dc115a79fa485352812f8d4ed3055ec9c1e297ac39bd93e9db3e",
				"dd0d06fbe4e7575d0eeac53706482cbbe592e269a35bcd5591a495814371724e",
			),
		];

		for (input, expected_circuit, expected_bytes) in vectors.iter() {
			let circuit_hash = hash_for_circuit::<C>(input);
			assert_eq!(
				hex::encode(circuit_hash),
				*expected_circuit,
				"hash_for_circuit mismatch for input: 0x{}",
				hex::encode(input)
			);

			let bytes_hash = hash_bytes(input);
			assert_eq!(
				hex::encode(bytes_hash),
				*expected_bytes,
				"hash_bytes mismatch for input: 0x{}",
				hex::encode(input)
			);
		}
	}
}
