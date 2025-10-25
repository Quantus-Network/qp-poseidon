// Auto-generated Poseidon2 constants for WIDTH=12
// Generated with seed: 0x3141592653589793
// External rounds: 8, Internal rounds: 22

extern crate alloc;

use alloc::{vec, vec::Vec};
use once_cell::sync::Lazy;
use p3_field::integers::QuotientMap;
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_poseidon2::{ExternalLayerConstants, Poseidon2};

/// Pre-computed internal round constants for Poseidon2 with WIDTH=12
static POSEIDON2_INTERNAL_CONSTANTS_12: Lazy<Vec<Goldilocks>> = Lazy::new(|| {
	vec![
		Goldilocks::from_int(0x97f7798a784ad863u64),
		Goldilocks::from_int(0xd1d2bf082f60d4f0u64),
		Goldilocks::from_int(0x69a377a79f9ad206u64),
		Goldilocks::from_int(0xa9d06906a3858e24u64),
		Goldilocks::from_int(0x295275001eede5b5u64),
		Goldilocks::from_int(0x5874e441117bd746u64),
		Goldilocks::from_int(0x8a084bbba8ed86ccu64),
		Goldilocks::from_int(0x3defd7645cde6425u64),
		Goldilocks::from_int(0x3998cfe6871cc137u64),
		Goldilocks::from_int(0x3e52ef8bca48314au64),
		Goldilocks::from_int(0x964a209f85dc9eccu64),
		Goldilocks::from_int(0x3fcc9ee82cc4577eu64),
		Goldilocks::from_int(0x8e79b4a5d0096d6du64),
		Goldilocks::from_int(0x8492362ad2392556u64),
		Goldilocks::from_int(0xee72f470262574d6u64),
		Goldilocks::from_int(0x1e0e18496da2444au64),
		Goldilocks::from_int(0x0f3a74bf215eaac6u64),
		Goldilocks::from_int(0x1b061b76a1c0ded3u64),
		Goldilocks::from_int(0x192c42d86803d7a6u64),
		Goldilocks::from_int(0xf6d49ff997ae0260u64),
		Goldilocks::from_int(0x3ec372e7a0fa3786u64),
		Goldilocks::from_int(0x5538cdf4f23445d3u64),
	]
});

/// Pre-computed initial external round constants for Poseidon2 with WIDTH=12
static POSEIDON2_INITIAL_EXTERNAL_CONSTANTS_12: Lazy<Vec<[Goldilocks; 12]>> = Lazy::new(|| {
	vec![
		[
			Goldilocks::from_int(0xc002e770975b1607u64),
			Goldilocks::from_int(0xbca51a8dfe14593au64),
			Goldilocks::from_int(0x72938dfbe774f7f9u64),
			Goldilocks::from_int(0xe4f2fe29e03234acu64),
			Goldilocks::from_int(0xd5e0ba2f541b6449u64),
			Goldilocks::from_int(0xec33b868f3cc46c1u64),
			Goldilocks::from_int(0x486dcb55419d475au64),
			Goldilocks::from_int(0x6c1cb2a358cc24f1u64),
			Goldilocks::from_int(0xe3f30d509a1436bbu64),
			Goldilocks::from_int(0xd9a64f068dca7c29u64),
			Goldilocks::from_int(0xe59b3f57aabba1aeu64),
			Goldilocks::from_int(0x2a3dd4505b478fdcu64),
		],
		[
			Goldilocks::from_int(0xada1f8dc7676ed25u64),
			Goldilocks::from_int(0x2711aa8b5509d516u64),
			Goldilocks::from_int(0x4ae6acd0c9c92897u64),
			Goldilocks::from_int(0x56eb3d6b5256d67au64),
			Goldilocks::from_int(0x1f7a9d55923bf51eu64),
			Goldilocks::from_int(0x3600427d397a7f68u64),
			Goldilocks::from_int(0xe5076df75b72c3d0u64),
			Goldilocks::from_int(0xfcd59aa12c6090adu64),
			Goldilocks::from_int(0xcd895e8c68b57a9eu64),
			Goldilocks::from_int(0x41df7ef9d730ae3eu64),
			Goldilocks::from_int(0xee3e2b889abe977du64),
			Goldilocks::from_int(0xd29bb7edbeb9c405u64),
		],
		[
			Goldilocks::from_int(0x7d5c08eef608e382u64),
			Goldilocks::from_int(0x89ae889caaf0802cu64),
			Goldilocks::from_int(0xb35a8e976d2af617u64),
			Goldilocks::from_int(0xdb14234eafaf5173u64),
			Goldilocks::from_int(0x78f04462d48b1c98u64),
			Goldilocks::from_int(0x265293b0e47ce88au64),
			Goldilocks::from_int(0x999a649b69b9d32fu64),
			Goldilocks::from_int(0x64b0a186698e01d3u64),
			Goldilocks::from_int(0xee0b22d0dfae8bb8u64),
			Goldilocks::from_int(0x4fd53e50ca04a7eeu64),
			Goldilocks::from_int(0x5762bfe181f25047u64),
			Goldilocks::from_int(0xf51593e2beb5e3bdu64),
		],
		[
			Goldilocks::from_int(0x1e5e2b5760e32477u64),
			Goldilocks::from_int(0x622462a1f9aaaeedu64),
			Goldilocks::from_int(0xaa284b3ecdb222aeu64),
			Goldilocks::from_int(0x63c8e72f542bf3fcu64),
			Goldilocks::from_int(0x3ba588cacb43b5e0u64),
			Goldilocks::from_int(0x23eda6f3c99150ddu64),
			Goldilocks::from_int(0xaad3bea4baac9a5au64),
			Goldilocks::from_int(0xe9da8d699b94184au64),
			Goldilocks::from_int(0xcdb13f4cd93e024cu64),
			Goldilocks::from_int(0x902cbd0956f655e3u64),
			Goldilocks::from_int(0x5b4e40ffc759532fu64),
			Goldilocks::from_int(0xde795c20a2357af7u64),
		],
	]
});

/// Pre-computed terminal external round constants for Poseidon2 with WIDTH=12
static POSEIDON2_TERMINAL_EXTERNAL_CONSTANTS_12: Lazy<Vec<[Goldilocks; 12]>> = Lazy::new(|| {
	vec![
		[
			Goldilocks::from_int(0x7b72c539e0ea4c6eu64),
			Goldilocks::from_int(0x144573dae2ce9976u64),
			Goldilocks::from_int(0x802028b68f35fc88u64),
			Goldilocks::from_int(0x6d36c5022c4fe7c2u64),
			Goldilocks::from_int(0xa205d0ffa9b9def3u64),
			Goldilocks::from_int(0xf6e7e38b1ea6ba2fu64),
			Goldilocks::from_int(0x34f7909ae5258d64u64),
			Goldilocks::from_int(0xb0464d9d77b97fcau64),
			Goldilocks::from_int(0x64ddb9d5de7e00a6u64),
			Goldilocks::from_int(0x0ed0d75c27975d97u64),
			Goldilocks::from_int(0x1cbb36f11127338bu64),
			Goldilocks::from_int(0x6673e505cfd0b6bau64),
		],
		[
			Goldilocks::from_int(0x605f902830872e01u64),
			Goldilocks::from_int(0x3fd5eb927e95fe4fu64),
			Goldilocks::from_int(0xe81025b5a24c69cdu64),
			Goldilocks::from_int(0xf7d0ce75de23f74eu64),
			Goldilocks::from_int(0xf39942b6a8585089u64),
			Goldilocks::from_int(0x6d808a08f7b71df6u64),
			Goldilocks::from_int(0xf8806b6588f49a8bu64),
			Goldilocks::from_int(0x57df2d8c2a32107au64),
			Goldilocks::from_int(0x16e7c2074d654a2du64),
			Goldilocks::from_int(0x213de241fcf33835u64),
			Goldilocks::from_int(0xb0f2b8905a0976f6u64),
			Goldilocks::from_int(0xd8e3cf2bbd355417u64),
		],
		[
			Goldilocks::from_int(0xe498691679d9330fu64),
			Goldilocks::from_int(0x763b45d2a3821b28u64),
			Goldilocks::from_int(0x0908bf65eb0a1f0du64),
			Goldilocks::from_int(0x7691eb2d194b24f4u64),
			Goldilocks::from_int(0x0e43551233ae13b2u64),
			Goldilocks::from_int(0x93c393dbfc2fe76fu64),
			Goldilocks::from_int(0x98f607485d48cdeau64),
			Goldilocks::from_int(0xe3d95f30309819c0u64),
			Goldilocks::from_int(0x1ef581a93eaf6acfu64),
			Goldilocks::from_int(0x0b24c1b7a030fca4u64),
			Goldilocks::from_int(0x624370be5670b327u64),
			Goldilocks::from_int(0x5f1e28615a11e486u64),
		],
		[
			Goldilocks::from_int(0xfe04051f909e042bu64),
			Goldilocks::from_int(0x7257e5b147fd3803u64),
			Goldilocks::from_int(0xe6ae134bb82f2e78u64),
			Goldilocks::from_int(0x5711fd5cf4784511u64),
			Goldilocks::from_int(0xf83a42660c08c0bcu64),
			Goldilocks::from_int(0x2cd8c96d9a3ce855u64),
			Goldilocks::from_int(0x7d2ffb1bb0e17271u64),
			Goldilocks::from_int(0x85ae1528caea3811u64),
			Goldilocks::from_int(0x52a345d5c7adb0b8u64),
			Goldilocks::from_int(0x504c4c51f3faee94u64),
			Goldilocks::from_int(0xbce34a649cfccaf9u64),
			Goldilocks::from_int(0xe0a3389266fb6dc9u64),
		],
	]
});

/// Create a Poseidon2 instance using precomputed constants
///
/// This is significantly faster than `Poseidon2Core::new()` since it avoids
/// the expensive constant derivation process and runtime conversions.
/// The constants are computed only once and stored in the exact format needed.
pub fn create_poseidon() -> Poseidon2Goldilocks<12> {
	let internal_constants = POSEIDON2_INTERNAL_CONSTANTS_12.clone();
	let initial_constants = POSEIDON2_INITIAL_EXTERNAL_CONSTANTS_12.clone();
	let terminal_constants = POSEIDON2_TERMINAL_EXTERNAL_CONSTANTS_12.clone();

	let external_constants = ExternalLayerConstants::new(initial_constants, terminal_constants);
	Poseidon2::new(external_constants, internal_constants)
}

#[cfg(test)]
mod tests {
	use super::*;
	use p3_field::PrimeCharacteristicRing;
	use p3_symmetric::Permutation;
	use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

	const POSEIDON2_SEED: u64 = 0x3141592653589793;

	#[test]
	fn test_hardcoded_matches_derived() {
		let mut rng = ChaCha20Rng::seed_from_u64(POSEIDON2_SEED);
		let original = Poseidon2Goldilocks::<12>::new_from_rng_128(&mut rng);
		let optimized = create_poseidon();

		// Test with zero input
		let mut state1 = [Goldilocks::ZERO; 12];
		let mut state2 = [Goldilocks::ZERO; 12];

		original.permute_mut(&mut state1);
		optimized.permute_mut(&mut state2);

		assert_eq!(state1, state2, "Zero input test failed");

		// Test with sequential input
		let test_input: [Goldilocks; 12] =
			core::array::from_fn(|i| Goldilocks::from_int(i as u64 + 1));

		let mut state1 = test_input;
		let mut state2 = test_input;

		original.permute_mut(&mut state1);
		optimized.permute_mut(&mut state2);

		assert_eq!(state1, state2, "Sequential input test failed");
	}

	#[test]
	fn test_multiple_permutations() {
		let optimized = create_poseidon();

		// Test multiple permutations to ensure consistency
		let test_inputs = [
			[Goldilocks::ZERO; 12],
			core::array::from_fn(|i| Goldilocks::from_int(i as u64)),
			core::array::from_fn(|i| Goldilocks::from_int((i * i) as u64)),
		];

		for input in test_inputs {
			let mut state1 = input;
			let mut state2 = input;

			// Apply the same permutation twice - should be deterministic
			optimized.permute_mut(&mut state1);
			optimized.permute_mut(&mut state2);

			assert_eq!(state1, state2, "Permutation should be deterministic");
		}
	}
}
