//! Regression tests for audit finding #96397 "Digest limbs silently truncate".
//!
//! `u64s_to_digest` takes eight u64 limbs, but the wire format only holds 32 bits
//! per limb. Narrowing with `as u32` silently discarded the high bits, so distinct
//! limb arrays aliased to the same serialized digest. Oversized limbs are now
//! rejected, matching the adjacent `u64s_to_bytes` serializer.

use qp_poseidon_core::hash_bytes;
use qp_poseidon_core::serialization::{digest_to_u64s, u64s_to_digest};

#[test]
fn oversized_limbs_are_rejected_instead_of_aliasing() {
	let canonical_wire_digest = hash_bytes(b"authorization-boundary-example");
	let canonical_limbs = digest_to_u64s(&canonical_wire_digest);
	assert!(canonical_limbs.iter().all(|v| *v <= 0xFFFF_FFFF));

	let mut forged_limbs = canonical_limbs;
	forged_limbs[1] |= 1u64 << 40;
	forged_limbs[6] |= 0x55AAu64 << 32;
	assert_ne!(forged_limbs, canonical_limbs);

	assert_eq!(
		u64s_to_digest(&forged_limbs),
		Err("Digest limb exceeds 32 bits"),
		"limbs exceeding 32 bits should be rejected, not silently truncated"
	);
}

#[test]
fn valid_limbs_round_trip() {
	let digest = hash_bytes(b"round trip");
	let limbs = digest_to_u64s(&digest);
	let back = u64s_to_digest(&limbs).expect("canonical limbs should serialize");
	assert_eq!(back, digest);
}
