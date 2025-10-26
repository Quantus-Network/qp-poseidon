// Auto-generated Poseidon2 constants for WIDTH=12
// Generated with seed: 0x3141592653589793
// External rounds: 8, Internal rounds: 22

extern crate alloc;

use alloc::vec::Vec;
use p3_field::integers::QuotientMap;
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_poseidon2::{ExternalLayerConstants, Poseidon2};

/// Raw u64 values for internal round constants
pub const POSEIDON2_INTERNAL_CONSTANTS_RAW: [u64; 22] = [
	0x97f7798a784ad863,
	0xd1d2bf082f60d4f0,
	0x69a377a79f9ad206,
	0xa9d06906a3858e24,
	0x295275001eede5b5,
	0x5874e441117bd746,
	0x8a084bbba8ed86cc,
	0x3defd7645cde6425,
	0x3998cfe6871cc137,
	0x3e52ef8bca48314a,
	0x964a209f85dc9ecc,
	0x3fcc9ee82cc4577e,
	0x8e79b4a5d0096d6d,
	0x8492362ad2392556,
	0xee72f470262574d6,
	0x1e0e18496da2444a,
	0x0f3a74bf215eaac6,
	0x1b061b76a1c0ded3,
	0x192c42d86803d7a6,
	0xf6d49ff997ae0260,
	0x3ec372e7a0fa3786,
	0x5538cdf4f23445d3,
];

/// Raw u64 values for initial external round constants
pub const POSEIDON2_INITIAL_EXTERNAL_CONSTANTS_RAW: [[u64; 12]; 4] = [
	[
		0xc002e770975b1607,
		0xbca51a8dfe14593a,
		0x72938dfbe774f7f9,
		0xe4f2fe29e03234ac,
		0xd5e0ba2f541b6449,
		0xec33b868f3cc46c1,
		0x486dcb55419d475a,
		0x6c1cb2a358cc24f1,
		0xe3f30d509a1436bb,
		0xd9a64f068dca7c29,
		0xe59b3f57aabba1ae,
		0x2a3dd4505b478fdc,
	],
	[
		0xada1f8dc7676ed25,
		0x2711aa8b5509d516,
		0x4ae6acd0c9c92897,
		0x56eb3d6b5256d67a,
		0x1f7a9d55923bf51e,
		0x3600427d397a7f68,
		0xe5076df75b72c3d0,
		0xfcd59aa12c6090ad,
		0xcd895e8c68b57a9e,
		0x41df7ef9d730ae3e,
		0xee3e2b889abe977d,
		0xd29bb7edbeb9c405,
	],
	[
		0x7d5c08eef608e382,
		0x89ae889caaf0802c,
		0xb35a8e976d2af617,
		0xdb14234eafaf5173,
		0x78f04462d48b1c98,
		0x265293b0e47ce88a,
		0x999a649b69b9d32f,
		0x64b0a186698e01d3,
		0xee0b22d0dfae8bb8,
		0x4fd53e50ca04a7ee,
		0x5762bfe181f25047,
		0xf51593e2beb5e3bd,
	],
	[
		0x1e5e2b5760e32477,
		0x622462a1f9aaaeed,
		0xaa284b3ecdb222ae,
		0x63c8e72f542bf3fc,
		0x3ba588cacb43b5e0,
		0x23eda6f3c99150dd,
		0xaad3bea4baac9a5a,
		0xe9da8d699b94184a,
		0xcdb13f4cd93e024c,
		0x902cbd0956f655e3,
		0x5b4e40ffc759532f,
		0xde795c20a2357af7,
	],
];

/// Raw u64 values for terminal external round constants
pub const POSEIDON2_TERMINAL_EXTERNAL_CONSTANTS_RAW: [[u64; 12]; 4] = [
	[
		0x7b72c539e0ea4c6e,
		0x144573dae2ce9976,
		0x802028b68f35fc88,
		0x6d36c5022c4fe7c2,
		0xa205d0ffa9b9def3,
		0xf6e7e38b1ea6ba2f,
		0x34f7909ae5258d64,
		0xb0464d9d77b97fca,
		0x64ddb9d5de7e00a6,
		0x0ed0d75c27975d97,
		0x1cbb36f11127338b,
		0x6673e505cfd0b6ba,
	],
	[
		0x605f902830872e01,
		0x3fd5eb927e95fe4f,
		0xe81025b5a24c69cd,
		0xf7d0ce75de23f74e,
		0xf39942b6a8585089,
		0x6d808a08f7b71df6,
		0xf8806b6588f49a8b,
		0x57df2d8c2a32107a,
		0x16e7c2074d654a2d,
		0x213de241fcf33835,
		0xb0f2b8905a0976f6,
		0xd8e3cf2bbd355417,
	],
	[
		0xe498691679d9330f,
		0x763b45d2a3821b28,
		0x0908bf65eb0a1f0d,
		0x7691eb2d194b24f4,
		0x0e43551233ae13b2,
		0x93c393dbfc2fe76f,
		0x98f607485d48cdea,
		0xe3d95f30309819c0,
		0x1ef581a93eaf6acf,
		0x0b24c1b7a030fca4,
		0x624370be5670b327,
		0x5f1e28615a11e486,
	],
	[
		0xfe04051f909e042b,
		0x7257e5b147fd3803,
		0xe6ae134bb82f2e78,
		0x5711fd5cf4784511,
		0xf83a42660c08c0bc,
		0x2cd8c96d9a3ce855,
		0x7d2ffb1bb0e17271,
		0x85ae1528caea3811,
		0x52a345d5c7adb0b8,
		0x504c4c51f3faee94,
		0xbce34a649cfccaf9,
		0xe0a3389266fb6dc9,
	],
];

/// Create a Poseidon2 instance using precomputed constants
///
/// This is significantly faster than `Poseidon2Core::new()` since it avoids
/// the expensive constant derivation process and runtime conversions.
/// The constants are computed only once and stored as raw u64 values, then
/// converted to field elements when this function is called.
pub fn create_poseidon() -> Poseidon2Goldilocks<12> {
	// Convert raw u64 arrays to Goldilocks field elements at runtime
	let internal_constants: Vec<Goldilocks> = POSEIDON2_INTERNAL_CONSTANTS_RAW
		.iter()
		.map(|&x| Goldilocks::from_int(x))
		.collect();

	let initial_constants: Vec<[Goldilocks; 12]> = POSEIDON2_INITIAL_EXTERNAL_CONSTANTS_RAW
		.iter()
		.map(|round| {
			let mut round_constants = [Goldilocks::from_int(0); 12];
			for (i, &val) in round.iter().enumerate() {
				round_constants[i] = Goldilocks::from_int(val);
			}
			round_constants
		})
		.collect();

	let terminal_constants: Vec<[Goldilocks; 12]> = POSEIDON2_TERMINAL_EXTERNAL_CONSTANTS_RAW
		.iter()
		.map(|round| {
			let mut round_constants = [Goldilocks::from_int(0); 12];
			for (i, &val) in round.iter().enumerate() {
				round_constants[i] = Goldilocks::from_int(val);
			}
			round_constants
		})
		.collect();

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
