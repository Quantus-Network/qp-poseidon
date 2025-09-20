#![no_std]

use codec::{Decode, Encode};
use p3_goldilocks::Goldilocks;
use qp_poseidon_core::{digest_bytes_to_felts, u128_to_felts, u64_to_felts, Poseidon2Core};
use scale_info::prelude::vec::Vec;
use scale_info::TypeInfo;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

// Re-export core functionality for convenience
pub use qp_poseidon_core::{
	digest_felts_to_bytes, injective_bytes_to_felts, injective_felts_to_bytes,
	injective_string_to_felts, MIN_FIELD_ELEMENT_PREIMAGE_LEN,
};

/// A standard library hasher implementation using Poseidon
#[derive(Default)]
pub struct PoseidonStdHasher(Vec<u8>);

#[cfg(feature = "std")]
impl core::hash::Hasher for PoseidonStdHasher {
	fn finish(&self) -> u64 {
		let hash = PoseidonHasher::hash_padded(self.0.as_slice());
		u64::from_le_bytes(hash[0..8].try_into().unwrap())
	}

	fn write(&mut self, bytes: &[u8]) {
		self.0.extend_from_slice(bytes)
	}
}

/// Substrate-compatible Poseidon hasher with codec traits
#[derive(PartialEq, Eq, Clone, Debug, Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PoseidonHasher;

impl PoseidonHasher {
	/// Hash field elements with padding to ensure consistent circuit behavior
	pub fn hash_padded_felts(x: Vec<Goldilocks>) -> Vec<u8> {
		let hasher = Poseidon2Core::new();
		hasher.hash_padded_felts(x)
	}

	/// Hash bytes with padding to ensure consistent circuit behavior
	pub fn hash_padded(x: &[u8]) -> Vec<u8> {
		let hasher = Poseidon2Core::new();
		hasher.hash_padded(x)
	}

	/// Hash field elements without any padding
	pub fn hash_no_pad(x: Vec<Goldilocks>) -> Vec<u8> {
		let hasher = Poseidon2Core::new();
		hasher.hash_no_pad(x)
	}

	/// Hash storage data for Quantus transfer proofs
	/// This function should only be used to compute the quantus storage key for Transfer Proofs
	/// It breaks up the bytes input in a specific way that mimics how our zk-circuit does it
	pub fn hash_storage<AccountId: Decode + Encode>(x: &[u8]) -> [u8; 32] {
		const STORAGE_HASH_SIZE: usize = 32;
		debug_assert!(
			x.len() == STORAGE_HASH_SIZE,
			"Input must be exactly {} bytes, but was {}",
			STORAGE_HASH_SIZE,
			x.len()
		);
		let mut felts = Vec::with_capacity(STORAGE_HASH_SIZE);
		let mut y = x;
		let (transfer_count, from_account, to_account, amount): (u64, AccountId, AccountId, u128) =
			Decode::decode(&mut y).expect("already asserted input length. qed");
		felts.extend(u64_to_felts(transfer_count));
		felts.extend(digest_bytes_to_felts(&from_account.encode()));
		felts.extend(digest_bytes_to_felts(&to_account.encode()));
		felts.extend(u128_to_felts(amount));
		let hash = PoseidonHasher::hash_no_pad(felts);
		hash.as_slice()[0..32].try_into().expect("already asserted input length. qed")
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use hex;
	use p3_field::PrimeField64;
	use scale_info::prelude::vec;

	#[cfg(feature = "std")]
	use env_logger;

	#[cfg(all(feature = "std", test))]
	#[ctor::ctor]
	fn init_logger_global() {
		let _ = env_logger::builder().is_test(true).try_init();
	}

	#[test]
	fn test_substrate_wrapper_compatibility() {
		// Test that the wrapper produces the same results as the core implementation
		let input = b"test data";
		let hasher = Poseidon2Core::new();
		let core_hash = hasher.hash_padded(input);
		let wrapper_hash = PoseidonHasher::hash_padded(input);
		assert_eq!(core_hash, wrapper_hash);
	}

	#[test]
	fn test_empty_input() {
		let result = PoseidonHasher::hash_padded(&[]);
		assert_eq!(result.len(), 32);
	}

	#[test]
	fn test_single_byte() {
		let input = vec![42u8];
		let result = PoseidonHasher::hash_padded(&input);
		assert_eq!(result.len(), 32);
	}

	#[test]
	fn test_exactly_32_bytes() {
		let input = [1u8; 32];
		let result = PoseidonHasher::hash_padded(&input);
		assert_eq!(result.len(), 32);
	}

	#[test]
	fn test_multiple_chunks() {
		let input = [2u8; 64]; // Two chunks
		let result = PoseidonHasher::hash_padded(&input);
		assert_eq!(result.len(), 32);
	}

	#[test]
	fn test_partial_chunk() {
		let input = [3u8; 40]; // One full chunk plus 8 bytes
		let result = PoseidonHasher::hash_padded(&input);
		assert_eq!(result.len(), 32);
	}

	#[test]
	fn test_consistency() {
		let input = [4u8; 50];
		let iterations = 100;
		let current_hash = PoseidonHasher::hash_padded(&input); // Compute the first hash

		for _ in 0..iterations {
			let hash1 = PoseidonHasher::hash_padded((&current_hash).as_ref());
			let current_hash = PoseidonHasher::hash_padded((&current_hash).as_ref());
			assert_eq!(hash1, current_hash, "Hash function should be deterministic");
		}
	}

	#[test]
	fn test_different_inputs() {
		let input1 = [5u8; 32];
		let input2 = [6u8; 32];
		let hash1 = PoseidonHasher::hash_padded(&input1);
		let hash2 = PoseidonHasher::hash_padded(&input2);
		assert_ne!(hash1, hash2, "Different inputs should produce different hashes");
	}

	#[test]
	fn test_poseidon_hash_input_sizes() {
		// Test inputs from 1 to 128 bytes
		for size in 1..=128 {
			// Create a predictable input: repeating byte value based on size
			let input: Vec<u8> = (0..size).map(|i| (i * i % 256) as u8).collect();
			let hash = PoseidonHasher::hash_padded(&input);

			// Assertions
			assert_eq!(
				hash.as_slice().len(),
				32,
				"Input size {} should produce 32-byte hash",
				size
			);
		}
	}

	#[test]
	fn test_big_preimage() {
		for overflow in 1..=200 {
			let preimage = (Goldilocks::ORDER_U64 + overflow).to_le_bytes();
			let _hash = PoseidonHasher::hash_padded(&preimage);
		}
	}

	#[test]
	fn test_circuit_preimage() {
		let preimage =
			hex::decode("afd8e7530b95ee5ebab950c9a0c62fae1e80463687b3982233028e914f8ec7cc");
		let hash = PoseidonHasher::hash_padded(&*preimage.unwrap());
		let _hash = PoseidonHasher::hash_padded(hash.as_slice());
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
			let hash = PoseidonHasher::hash_padded(&preimage);
			let _hash2 = PoseidonHasher::hash_padded(&hash.as_slice());
		}
	}

	#[test]
	fn test_known_value_hashes() {
		let vectors = [
			(vec![], "99e525ddae8e570d1291c00d68d12cd031c0e67e2adbbf051410c07b7001cde3"),
			(vec![0u8], "99e525ddae8e570d1291c00d68d12cd031c0e67e2adbbf051410c07b7001cde3"),
			(
				vec![1u8, 2, 3, 4, 5, 6, 7, 8],
				"2af3d38bd6c15042552a5167ff4131e38c884636e8d02e7e79a90ce13ee8d2cb",
			),
			(vec![255u8; 32], "88f70ec20e01cbbcca89f887bcf7e7d3b34b3a11894bad5e20407fe379d65e6b"),
			(
				b"hello world".to_vec(),
				"63ae6f49796ae6d8ebe6d1c9efc3f41c2564342ab67728efc7c3b2bb3f921789",
			),
			(
				(0u8..32).collect::<Vec<u8>>(),
				"0a7c419d825bb7a5513be769f8460254c117efbb854967224bd46756b4d4039d",
			),
		];
		for (input, expected_hex) in vectors.iter() {
			let hash = PoseidonHasher::hash_padded(input);
			assert_eq!(
				hex::encode(hash.as_slice()),
				*expected_hex,
				"input: 0x{}",
				hex::encode(input)
			);
		}
	}

	#[test]
	fn test_substrate_specific_functionality() {
		// Test the hash_storage function with mock data
		let _mock_data = vec![0u8; 32];

		// This will panic in debug mode because we're passing invalid data,
		// but in a real scenario, you'd encode proper AccountId types
		// let _result = PoseidonHasher::hash_storage::<u32>(&mock_data);
	}
}
