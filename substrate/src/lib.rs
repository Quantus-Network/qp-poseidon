#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;

use codec::{Decode, Encode};
use core::{
	clone::Clone,
	cmp::{Eq, PartialEq},
	convert::TryInto,
	default::Default,
	fmt::Debug,
	iter::Extend,
	prelude::rust_2024::derive,
};

use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use qp_poseidon_core::{
	hash_for_circuit, hash_to_bytes,
	serialization::{bytes_to_digest, u128_to_quantized_felt, u64_to_felts},
	PROOF_NODE_MAX_SIZE_FELTS,
};
use scale_info::TypeInfo;
use sp_core::{Hasher, H256};
use sp_storage::StateVersion;
use sp_trie::{LayoutV0, LayoutV1, TrieConfiguration};

/// Converts types to Goldilocks field elements for Poseidon hashing.
///
/// Implementations must align with the circuit's expected layout for the given type.
/// All byte array types (digests, accounts) use 4 bytes per field element for
/// collision-resistant encoding.
pub trait ToFelts {
	/// Append felts to the buffer to minimize allocations
	fn write_felts(&self, dest: &mut Vec<Goldilocks>);

	/// Convenience method to convert to a vector of felts
	fn to_felts(&self) -> Vec<Goldilocks> {
		let mut vec = Vec::new();
		self.write_felts(&mut vec);
		vec
	}
}

// Specific implementations for primitives and types used in the system.
// We use specific implementations instead of a blanket `MaxEncodedLen` impl to allow
// for structural composition of tuples via macros, which is required for correct circuit alignment.

impl ToFelts for u32 {
	fn write_felts(&self, dest: &mut Vec<Goldilocks>) {
		dest.push(Goldilocks::from_u32(*self));
	}
}

impl ToFelts for u64 {
	fn write_felts(&self, dest: &mut Vec<Goldilocks>) {
		dest.extend(u64_to_felts(*self));
	}
}

/// Here we quantize the u128 balance type to a u64 (constrained to 32-bit range) and then to a
/// single felt.
impl ToFelts for u128 {
	fn write_felts(&self, dest: &mut Vec<Goldilocks>) {
		dest.push(u128_to_quantized_felt(*self));
	}
}

/// 32-byte arrays are encoded as 4 field elements (8 bytes per felt).
/// This encoding is used for hash outputs and account IDs in storage.
/// The values in the leaf are constrained by the storage proof, so
/// collision resistance is provided by the merkle proof verification.
impl ToFelts for [u8; 32] {
	fn write_felts(&self, dest: &mut Vec<Goldilocks>) {
		dest.extend(bytes_to_digest::<Goldilocks>(self));
	}
}

/// Account IDs are encoded as 4 field elements (8 bytes per felt).
/// The values are constrained by the storage proof, so collision resistance
/// is provided by the merkle proof verification rather than the encoding.
impl ToFelts for sp_core::crypto::AccountId32 {
	fn write_felts(&self, dest: &mut Vec<Goldilocks>) {
		let bytes: &[u8; 32] = self.as_ref();
		dest.extend(bytes_to_digest::<Goldilocks>(bytes));
	}
}

impl<T: ToFelts> ToFelts for Option<T> {
	fn write_felts(&self, dest: &mut Vec<Goldilocks>) {
		match self {
			Some(v) => {
				dest.push(Goldilocks::ONE);
				v.write_felts(dest);
			},
			None => {
				dest.push(Goldilocks::ZERO);
			},
		}
	}
}

impl<T: ToFelts> ToFelts for Vec<T> {
	fn write_felts(&self, dest: &mut Vec<Goldilocks>) {
		// Length prefix + items
		dest.push(Goldilocks::from_u32(self.len() as u32));
		for item in self {
			item.write_felts(dest);
		}
	}
}

// Macro to implement ToFelts for tuples
macro_rules! impl_to_felts_tuple {
	($($name:ident)+) => {
		impl<$($name: ToFelts),+> ToFelts for ($($name,)+) {
			fn write_felts(&self, dest: &mut Vec<Goldilocks>) {
				#[allow(non_snake_case)]
				let ($($name,)+) = self;
				$($name.write_felts(dest);)+
			}
		}
	}
}

impl_to_felts_tuple!(A);
impl_to_felts_tuple!(A B);
impl_to_felts_tuple!(A B C);
impl_to_felts_tuple!(A B C D);
impl_to_felts_tuple!(A B C D E);
impl_to_felts_tuple!(A B C D E F);

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// A standard library hasher implementation using Poseidon
#[derive(Default)]
pub struct PoseidonStdHasher(Vec<u8>);

impl core::hash::Hasher for PoseidonStdHasher {
	fn finish(&self) -> u64 {
		let hash = PoseidonHasher::hash_for_circuit(self.0.as_slice());
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
		H256::from_slice(&Self::hash_for_circuit(x))
	}
}

impl PoseidonHasher {
	/// Hash bytes for circuit compatibility (used by Substrate's Hasher trait).
	///
	/// Converts bytes to field elements (4 bytes per felt with terminator),
	/// pads to a fixed number of elements, then hashes.
	pub fn hash_for_circuit(x: &[u8]) -> [u8; 32] {
		hash_for_circuit::<PROOF_NODE_MAX_SIZE_FELTS>(x)
	}

	/// Hash storage key or value.
	///
	/// Decodes the input bytes into `T` and converts to felts according to `ToFelts`.
	/// This ensures the hash matches the circuit's expected preimage for type `T`.
	pub fn hash_storage<T: Decode + ToFelts>(x: &[u8]) -> [u8; 32] {
		let t = T::decode(&mut &x[..])
			.expect("Input bytes length or format mismatch for the expected type");

		let felts = t.to_felts();
		hash_to_bytes(&felts)
	}
}

impl sp_runtime::traits::Hash for PoseidonHasher {
	type Output = H256;

	fn hash(s: &[u8]) -> Self::Output {
		H256::from_slice(&Self::hash_for_circuit(s))
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
	use qp_poseidon_constants::POSEIDON2_OUTPUT;
	use qp_poseidon_core::serialization::bytes_to_felts;
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
		let input = b"test data";
		let core_hash = hash_for_circuit::<PROOF_NODE_MAX_SIZE_FELTS>(input);
		let wrapper_hash = PoseidonHasher::hash_for_circuit(input);
		assert_eq!(core_hash, wrapper_hash);
	}

	#[test]
	fn test_empty_input() {
		let result = PoseidonHasher::hash_for_circuit(&[]);
		assert_eq!(result.len(), 32);
	}

	#[test]
	fn test_single_byte() {
		let input = vec![42u8];
		let result = PoseidonHasher::hash_for_circuit(&input);
		assert_eq!(result.len(), 32);
	}

	#[test]
	fn test_exactly_32_bytes() {
		let input = [1u8; 32];
		let result = PoseidonHasher::hash_for_circuit(&input);
		assert_eq!(result.len(), 32);
	}

	#[test]
	fn test_multiple_chunks() {
		let input = [2u8; 64];
		let result = PoseidonHasher::hash_for_circuit(&input);
		assert_eq!(result.len(), 32);
	}

	#[test]
	fn test_partial_chunk() {
		let input = [3u8; 40];
		let result = PoseidonHasher::hash_for_circuit(&input);
		assert_eq!(result.len(), 32);
	}

	#[test]
	fn test_consistency() {
		let input = [4u8; 50];
		let iterations = 100;
		let current_hash = PoseidonHasher::hash_for_circuit(&input);

		for _ in 0..iterations {
			let hash1 = PoseidonHasher::hash_for_circuit((&current_hash).as_ref());
			let current_hash = PoseidonHasher::hash_for_circuit((&current_hash).as_ref());
			assert_eq!(hash1, current_hash, "Hash function should be deterministic");
		}
	}

	#[test]
	fn test_different_inputs() {
		let input1 = [5u8; 32];
		let input2 = [6u8; 32];
		let hash1 = PoseidonHasher::hash_for_circuit(&input1);
		let hash2 = PoseidonHasher::hash_for_circuit(&input2);
		assert_ne!(hash1, hash2, "Different inputs should produce different hashes");
	}

	#[test]
	fn test_poseidon_hash_input_sizes() {
		for size in 1..=128 {
			let input: Vec<u8> = (0..size).map(|i| (i * i % 256) as u8).collect();
			let hash = PoseidonHasher::hash_for_circuit(&input);
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
			let preimage = (18446744069414584321u64 + overflow).to_le_bytes();
			let _hash = PoseidonHasher::hash_for_circuit(&preimage);
		}
	}

	#[test]
	fn test_circuit_preimage() {
		let preimage =
			hex::decode("afd8e7530b95ee5ebab950c9a0c62fae1e80463687b3982233028e914f8ec7cc");
		let hash = PoseidonHasher::hash_for_circuit(&*preimage.unwrap());
		let _hash = PoseidonHasher::hash_for_circuit(hash.as_slice());
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
			let hash = PoseidonHasher::hash_for_circuit(&preimage);
			let _hash2 = PoseidonHasher::hash_for_circuit(&hash.as_slice());
		}
	}

	#[test]
	fn test_substrate_hash_512() {
		use qp_poseidon_core::{hash_bytes, hash_squeeze_twice};

		let input = b"test substrate 512-bit";
		let hash512 = hash_squeeze_twice(input);

		// Should be exactly 64 bytes
		assert_eq!(hash512.len(), 64);

		// Should be deterministic
		let hash512_2 = hash_squeeze_twice(input);
		assert_eq!(hash512, hash512_2);

		// First 32 bytes should match regular hash
		let regular_hash = hash_bytes(input);
		assert_eq!(&hash512[0..32], &regular_hash);
	}

	#[test]
	fn test_hash_twice() {
		use qp_poseidon_core::hash_twice;

		let preimage =
			hex::decode("afd8e7530b95ee5ebab950c9a0c62fae1e80463687b3982233028e914f8ec7cc")
				.unwrap();
		let felts = bytes_to_felts(&preimage);
		let _hash = hash_twice(&felts);
	}

	#[test]
	fn test_hash_storage() {
		use sp_core::crypto::AccountId32;

		let asset_id = 42_u32;
		let transfer_count = 7_u64;
		let from_account = AccountId32::new([1u8; 32]);
		let to_account = AccountId32::new([2u8; 32]);
		let amount = 1_000_000_u128;

		let encoded =
			(asset_id, transfer_count, from_account.clone(), to_account.clone(), amount).encode();

		// The generic type T must match the structure of the encoded data
		type TransferKey = (u32, u64, AccountId32, AccountId32, u128);

		let hash = PoseidonHasher::hash_storage::<TransferKey>(&encoded);
		assert_eq!(hash.len(), 32);

		// Should fail if the input length is incorrect
		let invalid_encoded = &encoded[0..encoded.len() - 1];

		let result = std::panic::catch_unwind(|| {
			let _ = PoseidonHasher::hash_storage::<TransferKey>(invalid_encoded);
		});
		assert!(result.is_err(), "Expected panic due to invalid input length");
	}

	#[test]
	fn test_hash_storage_generic() {
		// Test with simple u64
		let val = 12345_u64;
		let encoded = val.encode();
		let hash = PoseidonHasher::hash_storage::<u64>(&encoded);
		assert_eq!(hash.len(), 32);

		// Test with tuple
		let val_tuple = (1u32, 2u64);
		let encoded_tuple = val_tuple.encode();
		let hash_tuple = PoseidonHasher::hash_storage::<(u32, u64)>(&encoded_tuple);
		assert_eq!(hash_tuple.len(), 32);

		// Test with u32
		let val_u32 = 12345_u32;
		let encoded_u32 = val_u32.encode();
		let hash_u32 = PoseidonHasher::hash_storage::<u32>(&encoded_u32);
		assert_eq!(hash_u32.len(), 32);

		// Test with Vec
		let val_vec = vec![1u32, 2u32, 3u32];
		let encoded_vec = val_vec.encode();
		let hash_vec = PoseidonHasher::hash_storage::<Vec<u32>>(&encoded_vec);
		assert_eq!(hash_vec.len(), 32);
	}

	#[test]
	fn test_to_felts_uses_4_felts_for_accounts() {
		use sp_core::crypto::AccountId32;

		let account = AccountId32::new([42u8; 32]);
		let felts = account.to_felts();

		// Should produce 4 felts (8 bytes per felt for 32 bytes)
		assert_eq!(felts.len(), POSEIDON2_OUTPUT);
	}

	#[test]
	fn test_to_felts_uses_4_felts_for_byte_arrays() {
		let bytes = [42u8; 32];
		let felts = bytes.to_felts();

		// Should produce 4 felts (8 bytes per felt for 32 bytes)
		assert_eq!(felts.len(), POSEIDON2_OUTPUT);
	}
}
