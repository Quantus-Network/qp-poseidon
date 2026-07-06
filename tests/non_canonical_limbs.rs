//! Regression tests for audit finding #96398 "Non-canonical 8-byte limb decoding".
//!
//! Byte strings whose 8-byte limbs encode values `>= P` would alias with canonical
//! field elements (`P` and `0` are the same element), letting byte-distinct inputs
//! hash to identical outputs. The decoders must reject such inputs.

use qp_poseidon_core::{
	goldilocks::P,
	hash_to_bytes, rehash_to_bytes,
	serialization::{bytes_to_digest, bytes_to_felts_compact, digest_to_bytes},
	Goldilocks,
};

#[test]
fn bytes_to_digest_rejects_non_canonical_limb() {
	let mut aliased_digest = [0u8; 32];
	aliased_digest[..8].copy_from_slice(&P.to_le_bytes());
	assert_eq!(bytes_to_digest(&aliased_digest), Err("Digest limb exceeds Goldilocks modulus"));
}

#[test]
fn rehash_to_bytes_rejects_non_canonical_digest() {
	let mut aliased_digest = [0u8; 32];
	aliased_digest[..8].copy_from_slice(&P.to_le_bytes());
	assert_eq!(rehash_to_bytes(&aliased_digest), Err("Digest limb exceeds Goldilocks modulus"));
}

#[test]
fn bytes_to_felts_compact_rejects_non_canonical_limb() {
	assert_eq!(
		bytes_to_felts_compact(&P.to_le_bytes()),
		Err("Compact encoding limb exceeds Goldilocks modulus")
	);
}

#[test]
fn canonical_digest_roundtrip_and_rehash_remain_stable() {
	let canonical_digest = digest_to_bytes(&[Goldilocks::ZERO; 4]);
	let decoded = bytes_to_digest(&canonical_digest).unwrap();
	assert_eq!(digest_to_bytes(&decoded), canonical_digest);

	let rehashed = rehash_to_bytes(&canonical_digest).unwrap();
	let rehashed_again = rehash_to_bytes(&canonical_digest).unwrap();
	assert_eq!(rehashed, rehashed_again);
}

#[test]
fn canonical_compact_encoding_still_hashes() {
	let canonical_felts = bytes_to_felts_compact(&[0u8; 8]).unwrap();
	let hash = hash_to_bytes(&canonical_felts);
	assert_eq!(hash.len(), 32);
}
