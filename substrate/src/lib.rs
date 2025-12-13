#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use codec::{Decode, Encode, MaxEncodedLen};
use core::{
	clone::Clone,
	cmp::{Eq, PartialEq},
	convert::TryInto,
	debug_assert,
	default::Default,
	fmt::Debug,
	iter::Extend,
	prelude::rust_2024::derive,
};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use qp_poseidon_core::{
	double_hash_variable_length, hash_padded_bytes, hash_squeeze_twice, hash_variable_length,
	hash_variable_length_bytes,
	serialization::{u128_to_felts, u64_to_felts, unsafe_digest_bytes_to_felts},
};
use scale_info::TypeInfo;
use sp_core::{Hasher, H256};
use sp_storage::StateVersion;
use sp_trie::{LayoutV0, LayoutV1, TrieConfiguration};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

// Re-export core functionality for convenience
pub use qp_poseidon_core::{
	serialization::{injective_bytes_to_felts, injective_string_to_felts},
	FIELD_ELEMENT_PREIMAGE_PADDING_LEN,
};

/// A standard library hasher implementation using Poseidon
#[derive(Default)]
pub struct PoseidonStdHasher(Vec<u8>);

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

impl Hasher for PoseidonHasher {
	type Out = H256;
	type StdHasher = PoseidonStdHasher;
	const LENGTH: usize = 32;

	fn hash(x: &[u8]) -> H256 {
		H256::from_slice(&Self::hash_padded(x))
	}
}

impl PoseidonHasher {
	/// Hash bytes with padding to ensure consistent circuit behavior
	pub fn hash_padded(x: &[u8]) -> [u8; 32] {
		hash_padded_bytes::<FIELD_ELEMENT_PREIMAGE_PADDING_LEN>(x)
	}

	/// Hash field elements without any padding
	pub fn hash_variable_length(x: Vec<Goldilocks>) -> [u8; 32] {
		hash_variable_length(x)
	}

	pub fn hash_variable_length_bytes(x: &[u8]) -> [u8; 32] {
		hash_variable_length_bytes(x)
	}

	/// Hash with 512-bit output by hashing input, then hashing the result, and concatenating both
	pub fn hash_squeeze_twice(x: &[u8]) -> [u8; 64] {
		hash_squeeze_twice(x)
	}

	/// Hash storage data for Quantus transfer proofs
	/// This function should only be used to compute the quantus storage key for Transfer Proofs
	/// It breaks up the bytes input in a specific way that mimics how our zk-circuit does it
	pub fn hash_storage<AccountId: Decode + Encode + MaxEncodedLen>(x: &[u8]) -> [u8; 32] {
		let max_encoded_len = u64::max_encoded_len() +
			AccountId::max_encoded_len() +
			AccountId::max_encoded_len() +
			u128::max_encoded_len() +
			u32::max_encoded_len();

		debug_assert!(
			x.len() == max_encoded_len,
			"Input must be exactly {} bytes, but was {}",
			max_encoded_len,
			x.len()
		);
		let mut felts = Vec::with_capacity(max_encoded_len);
		let mut y = x;
		let (asset_id, transfer_count, from_account, to_account, amount): (
			u32,
			u64,
			AccountId,
			AccountId,
			u128,
		) = Decode::decode(&mut y).expect("already asserted input length. qed");
		felts.push(Goldilocks::from_u32(asset_id));
		felts.extend(u64_to_felts::<Goldilocks>(transfer_count));
		felts.extend(unsafe_digest_bytes_to_felts::<Goldilocks>(
			&from_account.encode().try_into().expect("AccountId expected to equal 32 bytes"),
		));
		felts.extend(unsafe_digest_bytes_to_felts::<Goldilocks>(
			&to_account.encode().try_into().expect("AccountId expected to equal 32 bytes"),
		));
		felts.extend(u128_to_felts::<Goldilocks>(amount));
		hash_variable_length(felts)
	}

	pub fn double_hash_felts(felts: Vec<Goldilocks>) -> [u8; 32] {
		double_hash_variable_length(felts)
	}
}

impl sp_runtime::traits::Hash for PoseidonHasher {
	type Output = H256;

	fn hash(s: &[u8]) -> Self::Output {
		H256::from_slice(&Self::hash_padded(s))
	}

	/// Produce the hash of some codec-encodable value.
	fn hash_of<S: Encode>(s: &S) -> Self::Output {
		Encode::using_encoded(s, <Self as Hasher>::hash)
	}

	fn ordered_trie_root(input: Vec<Vec<u8>>, state_version: StateVersion) -> Self::Output {
		log::debug!(target: "poseidon",
			"PoseidonHasher::ordered_trie_root input={input:?} version={state_version:?}",
		);
		let res = match state_version {
			StateVersion::V0 => LayoutV0::<PoseidonHasher>::ordered_trie_root(input),
			StateVersion::V1 => LayoutV1::<PoseidonHasher>::ordered_trie_root(input),
		};
		log::debug!(target: "poseidon", "PoseidonHasher::ordered_trie_root res={res:?}");
		res
	}

	fn trie_root(input: Vec<(Vec<u8>, Vec<u8>)>, version: StateVersion) -> Self::Output {
		log::debug!(target: "poseidon",
			"PoseidonHasher::trie_root input={input:?} version={version:?}"
		);
		let res = match version {
			StateVersion::V0 => LayoutV0::<PoseidonHasher>::trie_root(input),
			StateVersion::V1 => LayoutV1::<PoseidonHasher>::trie_root(input),
		};
		log::debug!(target: "poseidon", "PoseidonHasher::trie_root res={res:?}");
		res
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
		let core_hash = hash_padded_bytes::<FIELD_ELEMENT_PREIMAGE_PADDING_LEN>(input);
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
	fn test_substrate_hash_512() {
		let input = b"test substrate 512-bit";
		let hash512 = PoseidonHasher::hash_squeeze_twice(input);

		// Should be exactly 64 bytes
		assert_eq!(hash512.len(), 64);

		// Should be deterministic
		let hash512_2 = PoseidonHasher::hash_squeeze_twice(input);
		assert_eq!(hash512, hash512_2);

		// First 32 bytes should match regular hash
		let regular_hash = PoseidonHasher::hash_variable_length_bytes(input);
		assert_eq!(&hash512[0..32], &regular_hash);
	}

	#[test]
	fn test_double_hash() {
		let preimage =
			hex::decode("afd8e7530b95ee5ebab950c9a0c62fae1e80463687b3982233028e914f8ec7cc")
				.unwrap();
		let felts = injective_bytes_to_felts(&preimage);
		let _hash = PoseidonHasher::double_hash_felts(felts);
	}

	#[test]
	fn test_hash_storage() {
		use sp_core::crypto::AccountId32;

		let asset_id: u32 = 42;
		let transfer_count: u64 = 7;
		let from_account = AccountId32::new([1u8; 32]);
		let to_account = AccountId32::new([2u8; 32]);
		let amount: u128 = 1_000_000;

		let mut encoded = Vec::new();
		asset_id.encode_to(&mut encoded);
		transfer_count.encode_to(&mut encoded);
		from_account.encode_to(&mut encoded);
		to_account.encode_to(&mut encoded);
		amount.encode_to(&mut encoded);

		let hash = PoseidonHasher::hash_storage::<AccountId32>(&encoded);
		assert_eq!(hash.len(), 32);

		// Should fail if the input length is incorrect
		let invalid_encoded = &encoded[0..encoded.len() - 1];

		let result = std::panic::catch_unwind(|| {
			let _ = PoseidonHasher::hash_storage::<AccountId32>(invalid_encoded);
		});
		assert!(result.is_err(), "Expected panic due to invalid input length");
	}
}
