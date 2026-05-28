#![no_std]

extern crate alloc;

use qp_poseidon_constants as constants;

pub mod serialization;

use crate::serialization::{bytes_to_felts, bytes_to_felts_compact};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_symmetric::Permutation;
use qp_poseidon_constants::{POSEIDON2_OUTPUT, SPONGE_RATE, SPONGE_WIDTH};

// Internal state for Poseidon2 hashing
struct Poseidon2State {
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

// ============================================================================
// Compact encoding hash functions
// ============================================================================

/// Hash a Dilithium ML-DSA-87 public key (2592 bytes) using compact encoding.
///
/// Uses compact encoding (8 bytes/felt) for circuit compatibility.
/// This is the recommended way to derive an account ID from a Dilithium public key.
///
/// # Safety
/// This function uses compact encoding which is only collision-resistant for fixed-size
/// inputs. The fixed array size ensures callers provide exactly 2592 bytes.
pub fn hash_pubkey(pubkey: &[u8; 2592]) -> [u8; 32] {
	hash_compact(pubkey)
}

/// Hash bytes using compact encoding (8 bytes/felt).
///
/// Converts bytes to field elements using compact encoding, then hashes.
///
/// # Warning
/// This function is NOT collision-resistant for variable-length inputs because:
/// 1. Compact encoding doesn't include a length marker (trailing zeros collide)
/// 2. Values >= Goldilocks prime are reduced (field element collisions)
///
/// Only use this with fixed-size inputs where the size is known and enforced.
/// Prefer the type-safe wrappers like `hash_pubkey` for public APIs.
pub(crate) fn hash_compact(x: &[u8]) -> [u8; 32] {
	hash_to_bytes(&bytes_to_felts_compact(x))
}

/// Double hash: hash(hash(input)), returning bytes.
///
/// The inner hash output (4 felts) is re-hashed directly as field elements.
/// Used for wormhole address derivation.
pub fn hash_twice(x: &[Goldilocks]) -> [u8; 32] {
	let inner = hash_to_felts(x);
	hash_to_bytes(&inner)
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
	use alloc::{format, vec, vec::Vec};
	use p3_field::PrimeField64;

	#[test]
	fn test_empty_input() {
		let result = hash_compact(&[]);
		assert_eq!(result.len(), 32);
	}

	#[test]
	fn test_single_byte() {
		let input = vec![42u8];
		let result = hash_compact(&input);
		assert_eq!(result.len(), 32);
	}

	#[test]
	fn test_exactly_32_bytes() {
		let input = [1u8; 32];
		let result = hash_compact(&input);
		assert_eq!(result.len(), 32);
	}

	#[test]
	fn test_multiple_chunks() {
		let input = [2u8; 64];
		let result = hash_compact(&input);
		assert_eq!(result.len(), 32);
	}

	#[test]
	fn test_partial_chunk() {
		let input = [3u8; 40];
		let result = hash_compact(&input);
		assert_eq!(result.len(), 32);
	}

	#[test]
	fn test_consistency() {
		let input = [4u8; 50];
		let iterations = 10;
		let current_hash = hash_compact(&input);

		for _ in 0..iterations {
			let hash1 = hash_compact(&current_hash);
			let hash2 = hash_compact(&current_hash);
			assert_eq!(hash1, hash2, "Hash function should be deterministic");
		}
	}

	#[test]
	fn test_different_inputs() {
		let input1 = [5u8; 32];
		let input2 = [6u8; 32];
		let hash1 = hash_compact(&input1);
		let hash2 = hash_compact(&input2);
		assert_ne!(hash1, hash2, "Different inputs should produce different hashes");
	}

	#[test]
	fn test_poseidon2_hash_input_sizes() {
		for size in 1..=128 {
			let input: Vec<u8> = (0..size).map(|i| (i * i % 256) as u8).collect();
			let hash = hash_compact(&input);
			assert_eq!(hash.len(), 32, "Input size {} should produce 32-byte hash", size);
		}
	}

	#[test]
	fn test_big_preimage() {
		for overflow in 1..=10 {
			let preimage =
				(<p3_goldilocks::Goldilocks as PrimeField64>::ORDER_U64 + overflow).to_le_bytes();
			let _hash = hash_compact(&preimage);
		}
	}

	#[test]
	fn test_circuit_preimage() {
		let preimage =
			hex::decode("afd8e7530b95ee5ebab950c9a0c62fae1e80463687b3982233028e914f8ec7cc");
		let hash = hash_compact(&preimage.unwrap());
		let _hash = hash_compact(&hash);
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
			let hash = hash_compact(&preimage);
			let _hash2 = hash_compact(&hash);
		}
	}

	#[test]
	fn test_hash_bytes_vs_compact() {
		let input = b"test";
		let compact_hash = hash_compact(input);
		let injective_hash = hash_bytes(input);

		// These should be different since they use different encodings
		// (compact: 8 bytes/felt vs injective: 4 bytes/felt with terminator)
		assert_ne!(compact_hash, injective_hash);
		assert_eq!(compact_hash.len(), 32);
		assert_eq!(injective_hash.len(), 32);
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

		assert_ne!(first_hash_bytes, double_hash_bytes);

		// Verify hash_twice matches manual double hash
		let manual_double_felts = hash_to_felts(&first_hash_felts);
		let manual_double_bytes = serialization::digest_to_bytes(&manual_double_felts);
		assert_eq!(double_hash_bytes, manual_double_bytes);

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
			let compact_hash = hash_compact(input);
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
				hex::encode(compact_hash),
				hex::encode(bytes_hash)
			);
		}
		println!("];");
	}

	/// Known Answer Tests (KAT) for hash functions.
	/// These test vectors ensure hash outputs remain stable across versions.
	///
	/// hash_bytes uses injective encoding (4 bytes/felt with terminator).
	#[test]
	fn test_known_value_hashes() {
		// Test vectors for hash_bytes (injective encoding)
		let vectors: [(Vec<u8>, &str); 18] = [
			(vec![], "4d8d22af81f6c27a005a07028590ef4ee480f6c4b93f813daf9de47a07c8ae86"),
			(vec![0u8], "8f5b42e350ff5a12788210c86c2bcd49243b8f9350de818b3b0c56839a42ebad"),
			(vec![0u8, 0u8], "3e6ee24fb61a22f4d825b72fc8ebd359e3b3b9566e246c71c3e450ebe3262f9c"),
			(
				vec![0u8, 0u8, 0u8],
				"34f4338a6f1b671062a3ac00b37ca05a47b43e16e589ccaa5b063416ba42356b",
			),
			(
				vec![0u8, 0u8, 0u8, 0u8],
				"7bac8c6bc49b0b750f2ce0912b815a2cb4ae20c75ac430850257882d9d321afa",
			),
			(
				vec![0u8, 0u8, 0u8, 0u8, 0u8],
				"c95cfddb573adf4070b3d7c8d2dfbbee48b4b973d80cbda2b458abe7bb6f0def",
			),
			(
				vec![0u8, 0u8, 0u8, 0u8, 0u8, 0u8],
				"a4dc08d0a8c5ea44007462fe1fd8e45962d4ea85c420eab4140fbb30b5b5e111",
			),
			(
				vec![0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8],
				"b01975012df91d9f9f040c34655f23f3ec1f6d1738d85679e9848143756637c9",
			),
			(
				vec![0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8],
				"eacd9e48d2e968131e48c8e69f2a211cc06c7778db6c5467348b45418fc7f585",
			),
			(
				vec![0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8],
				"00df670e8ec0751d3fb9b5f0281d0af9a7a82f62ad35a21247a9d6117daec151",
			),
			(vec![0u8; 14], "d6182896f274c5d9640972e2bf2a5e893e516a21adfdd8ebd39969128d619934"),
			(vec![0u8; 15], "15fc2f3c3bc51c96797b889d4fecfcd3535b959f510c007598a87f099e356303"),
			(
				vec![0u8, 0u8, 0u8, 1u8],
				"6ffff0c97262139567c426e916c1fd70c924010153c366bb2a8957ea89902942",
			),
			(
				vec![1u8, 2, 3, 4, 5, 6, 7, 8],
				"131020b2e74819343f8568258ae2e9717e9b2253d57baabab78a518bc7499a8b",
			),
			(vec![255u8; 32], "41260a4322e97dc3dda2b5f70b5ffb1b43071ad5510e101f34209721042c0987"),
			(
				b"hello world".to_vec(),
				"fd1f5d7d4701c25bbdd5dd6e3be6abb474fffbaa402f814dce95f8283abbf3e7",
			),
			(
				(0u8..32).collect::<Vec<u8>>(),
				"36884f9093be80632397f5736dce2fece627a4182daf3cdbf8bf12c8e3e02668",
			),
			(
				(0u8..64).collect::<Vec<u8>>(),
				"dd0d06fbe4e7575d0eeac53706482cbbe592e269a35bcd5591a495814371724e",
			),
		];

		for (input, expected_bytes) in vectors.iter() {
			let bytes_hash = hash_bytes(input);
			assert_eq!(
				hex::encode(bytes_hash),
				*expected_bytes,
				"hash_bytes mismatch for input: 0x{}",
				hex::encode(input)
			);
		}

		// Test that hash_compact produces consistent results (not testing specific values
		// since compact encoding without padding is only safe for fixed-size inputs)
		let compact_hash1 = hash_compact(b"test");
		let compact_hash2 = hash_compact(b"test");
		assert_eq!(compact_hash1, compact_hash2, "hash_compact should be deterministic");

		// Test that different inputs produce different hashes
		let hash_a = hash_compact(b"a");
		let hash_b = hash_compact(b"b");
		assert_ne!(hash_a, hash_b, "Different inputs should produce different hashes");
	}

	/// Test vectors for hash_twice and rehash_to_bytes.
	/// These ensure hash chaining operations remain stable across versions.
	#[test]
	fn test_hash_twice_vectors() {
		use p3_field::PrimeCharacteristicRing;

		// hash_twice test vectors (input felts -> output bytes)
		// Empty input
		let empty: Vec<Goldilocks> = vec![];
		assert_eq!(
			hex::encode(hash_twice(&empty)),
			"b8a2f205ad2e2682ab8af6e49946a597920a24d916ca1139b6fce113c207365b"
		);

		// Single zero felt
		let single_zero = vec![Goldilocks::ZERO];
		assert_eq!(
			hex::encode(hash_twice(&single_zero)),
			"6e962ae00104d1c8907142439156035ad71242caab590a74ba8c9850df03ff11"
		);

		// Single one felt
		let single_one = vec![Goldilocks::ONE];
		assert_eq!(
			hex::encode(hash_twice(&single_one)),
			"50be997dba65a402610d93f8fe853b0974fc72e4605effd5603deb900667e497"
		);

		// Four felts (typical hash output size)
		let four_felts: Vec<Goldilocks> = (1u64..=4).map(Goldilocks::from_u64).collect();
		assert_eq!(
			hex::encode(hash_twice(&four_felts)),
			"153624f84074a4503ea9139d64ad54da77849d83eb0e6a8e1f839bfe31c222b5"
		);

		// Eight felts
		let eight_felts: Vec<Goldilocks> = (1u64..=8).map(Goldilocks::from_u64).collect();
		assert_eq!(
			hex::encode(hash_twice(&eight_felts)),
			"958293c7f14ec2ef872955b510eee16f041217f37f8db0c0287fbe182afde6af"
		);
	}

	/// Test vectors for rehash_to_bytes (32-byte input -> 32-byte output).
	#[test]
	fn test_rehash_to_bytes_vectors() {
		// All zeros
		let zeros = [0u8; 32];
		assert_eq!(
			hex::encode(rehash_to_bytes(&zeros)),
			"ca0aefbd2e87c9ecc4716b7db8e83937a45dfb06ea10e1d62a4c2f2784002290"
		);

		// Sequential bytes 0..32
		let seq: [u8; 32] = core::array::from_fn(|i| i as u8);
		assert_eq!(
			hex::encode(rehash_to_bytes(&seq)),
			"c0877470eb2fbfc7cc6f22ab70955509de54f3b89856d6a58399a7b7d9d26252"
		);

		// All 0xFF
		let ones = [0xFFu8; 32];
		assert_eq!(
			hex::encode(rehash_to_bytes(&ones)),
			"242fcadf76ea91d398421eb1136b1dbf9f79bdadd79662a21689a0823cf46746"
		);
	}
}
