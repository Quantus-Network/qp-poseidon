//! Self-contained Poseidon2 permutation for Goldilocks field (WIDTH=12).
//!
//! This implements the Poseidon2 hash function without any external dependencies.
//! Based on the paper: https://eprint.iacr.org/2023/323

use crate::goldilocks::Goldilocks;

// ============================================================================
// Poseidon2 Parameters for WIDTH=12
// ============================================================================

/// Width of the Poseidon2 sponge (number of field elements in state).
pub const SPONGE_WIDTH: usize = 12;

/// Rate of the sponge construction (number of field elements absorbed per permutation).
pub const SPONGE_RATE: usize = 8;

/// Capacity of the sponge (security parameter = WIDTH - RATE).
pub const SPONGE_CAPACITY: usize = SPONGE_WIDTH - SPONGE_RATE;

/// Number of output field elements in a Poseidon2 hash digest.
pub const POSEIDON2_OUTPUT: usize = 4;

/// Number of internal (partial) rounds in the Poseidon2 permutation.
pub const INTERNAL_ROUNDS: usize = 22;

/// Number of external (full) rounds in the Poseidon2 permutation (4 initial + 4 terminal).
pub const EXTERNAL_ROUNDS: usize = 8;

/// Half external rounds (4 initial, 4 terminal).
pub const HALF_EXTERNAL_ROUNDS: usize = EXTERNAL_ROUNDS / 2;

// ============================================================================
// Round Constants (generated with seed 0x3141592653589793)
// ============================================================================

/// Internal round constants (22 scalars).
pub const INTERNAL_CONSTANTS: [u64; INTERNAL_ROUNDS] = [
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

/// Diagonal values for the internal diffusion matrix.
///
/// p3-goldilocks 0.3.x uses `state[i] = sum(state) + state[i] * MATRIX_DIAG[i]`.
pub const MATRIX_DIAG: [u64; SPONGE_WIDTH] = [
	0xc3b6c08e23ba9300,
	0xd84b5de94a324fb6,
	0x0d0c371c5b35b84f,
	0x7964f570e7188037,
	0x5daf18bbd996604b,
	0x6743bc47b9595257,
	0x5528b9362c59bb70,
	0xac45e25b7127b68b,
	0xa2077d7dfbb606b5,
	0xf3faac6faee378ae,
	0x0c6388b51545e883,
	0xd27dbb6944917b60,
];

/// Initial external round constants (4 rounds x 12 elements).
pub const INITIAL_EXTERNAL_CONSTANTS: [[u64; SPONGE_WIDTH]; HALF_EXTERNAL_ROUNDS] = [
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

/// Terminal external round constants (4 rounds x 12 elements).
pub const TERMINAL_EXTERNAL_CONSTANTS: [[u64; SPONGE_WIDTH]; HALF_EXTERNAL_ROUNDS] = [
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

// ============================================================================
// Poseidon2 Permutation
// ============================================================================

/// The Poseidon2 permutation for Goldilocks field with WIDTH=12.
#[derive(Clone, Debug)]
pub struct Poseidon2 {
	internal_constants: [Goldilocks; INTERNAL_ROUNDS],
	matrix_diag: [Goldilocks; SPONGE_WIDTH],
	initial_external_constants: [[Goldilocks; SPONGE_WIDTH]; HALF_EXTERNAL_ROUNDS],
	terminal_external_constants: [[Goldilocks; SPONGE_WIDTH]; HALF_EXTERNAL_ROUNDS],
}

impl Default for Poseidon2 {
	fn default() -> Self {
		Self::new()
	}
}

impl Poseidon2 {
	/// Create a new Poseidon2 instance with precomputed constants.
	pub fn new() -> Self {
		let internal_constants = core::array::from_fn(|i| Goldilocks::new(INTERNAL_CONSTANTS[i]));
		let matrix_diag = core::array::from_fn(|i| Goldilocks::new(MATRIX_DIAG[i]));

		let initial_external_constants = core::array::from_fn(|r| {
			core::array::from_fn(|i| Goldilocks::new(INITIAL_EXTERNAL_CONSTANTS[r][i]))
		});

		let terminal_external_constants = core::array::from_fn(|r| {
			core::array::from_fn(|i| Goldilocks::new(TERMINAL_EXTERNAL_CONSTANTS[r][i]))
		});

		Self {
			internal_constants,
			matrix_diag,
			initial_external_constants,
			terminal_external_constants,
		}
	}

	/// Apply the Poseidon2 permutation to the state in-place.
	#[inline]
	pub fn permute_mut(&self, state: &mut [Goldilocks; SPONGE_WIDTH]) {
		// Initial external layer: first apply linear layer, then rounds
		external_linear_layer(state);
		for round in 0..HALF_EXTERNAL_ROUNDS {
			self.external_round(state, &self.initial_external_constants[round]);
		}

		// Internal rounds
		for round in 0..INTERNAL_ROUNDS {
			self.internal_round(state, self.internal_constants[round]);
		}

		// Terminal external rounds
		for round in 0..HALF_EXTERNAL_ROUNDS {
			self.external_round(state, &self.terminal_external_constants[round]);
		}
	}

	/// Apply a single external (full) round.
	#[inline]
	fn external_round(
		&self,
		state: &mut [Goldilocks; SPONGE_WIDTH],
		rc: &[Goldilocks; SPONGE_WIDTH],
	) {
		// Add round constants and apply S-box to all elements
		for i in 0..SPONGE_WIDTH {
			state[i] += rc[i];
			state[i] = state[i].exp7();
		}
		// Apply external linear layer
		external_linear_layer(state);
	}

	/// Apply a single internal (partial) round.
	#[inline]
	fn internal_round(&self, state: &mut [Goldilocks; SPONGE_WIDTH], rc: Goldilocks) {
		// Add round constant and apply S-box only to first element
		state[0] += rc;
		state[0] = state[0].exp7();
		// Apply internal linear layer
		internal_linear_layer(state, &self.matrix_diag);
	}
}

// ============================================================================
// Linear Layers
// ============================================================================

/// Apply the external linear layer (MDS light permutation).
///
/// This applies M_4 to each consecutive 4 elements, then adds sums.
#[inline]
fn external_linear_layer(state: &mut [Goldilocks; SPONGE_WIDTH]) {
	// Apply M_4 to each 4-element chunk
	for chunk in state.chunks_exact_mut(4) {
		apply_mat4(chunk.try_into().unwrap());
	}

	// Compute sums for the outer circulant
	let sums: [Goldilocks; 4] =
		core::array::from_fn(|k| (0..SPONGE_WIDTH).step_by(4).map(|j| state[j + k]).sum());

	// Add sums back
	for (i, elem) in state.iter_mut().enumerate() {
		*elem += sums[i % 4];
	}
}

/// Apply the 4x4 MDS matrix:
/// [ 2 3 1 1 ]
/// [ 1 2 3 1 ]
/// [ 1 1 2 3 ]
/// [ 3 1 1 2 ]
#[inline(always)]
fn apply_mat4(x: &mut [Goldilocks; 4]) {
	let t01 = x[0] + x[1];
	let t23 = x[2] + x[3];
	let t0123 = t01 + t23;
	let t01123 = t0123 + x[1];
	let t01233 = t0123 + x[3];
	// Order matters: overwrite x[0] and x[2] after using x[1] and x[3]
	x[3] = t01233 + x[0].double(); // 3*x[0] + x[1] + x[2] + 2*x[3]
	x[1] = t01123 + x[2].double(); // x[0] + 2*x[1] + 3*x[2] + x[3]
	x[0] = t01123 + t01; // 2*x[0] + 3*x[1] + x[2] + x[3]
	x[2] = t01233 + t23; // x[0] + x[1] + 2*x[2] + 3*x[3]
}

/// Apply the internal linear layer for WIDTH=12.
///
/// This computes: state[i] = sum + diag[i] * state[i].
#[inline]
fn internal_linear_layer(
	state: &mut [Goldilocks; SPONGE_WIDTH],
	matrix_diag: &[Goldilocks; SPONGE_WIDTH],
) {
	let sum: Goldilocks = state.iter().copied().sum();
	for i in 0..SPONGE_WIDTH {
		state[i] = sum + state[i] * matrix_diag[i];
	}
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;

	// Expected outputs from p3-goldilocks + qp-poseidon-constants (seed 0x3141592653589793)
	const P3_ZERO_RESULT: [u64; 12] = [
		0xc9bc9432e1686884,
		0x03ecbab0dcdd2189,
		0x5e7ac885b3dc1215,
		0x6ac07513801d191f,
		0xca5c593fb184dcfc,
		0x414dec5f3e455287,
		0x1a17df170127ae41,
		0xe7e592bd0af9b0a5,
		0xc71a9b27edc66a4c,
		0x2728671759ac43c2,
		0xb9969c20f7f672f9,
		0xc5140b586823b92f,
	];

	const P3_SEQ_RESULT: [u64; 12] = [
		0x7e9574e2a3d6c48b,
		0x9d7bc16d282d2f2b,
		0x798826626d94a498,
		0x0831011bb22304c7,
		0xbdccb5931fffd16c,
		0xe98687714dacbefc,
		0xc6a1ed29dd75e027,
		0x1aec96681d15f765,
		0xc74b2c710b170a23,
		0x5fb4aff45e9c24fb,
		0x1fb3d228db0127eb,
		0xe201a7e214b16e74,
	];

	#[test]
	fn test_first_few_ops_zero_state() {
		// Compare first few operations with zero state against p3
		// Expected from p3:
		// After initial MDS: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
		// After first RC + S-box: [5716687150516714629, ...]
		// After first round MDS: [15870188304392300026, ...]

		let poseidon = Poseidon2::new();
		let mut state = [Goldilocks::ZERO; SPONGE_WIDTH];

		// Step 1: Apply initial external linear layer
		external_linear_layer(&mut state);
		let expected_after_mds = [0u64; 12];
		for (i, (actual, exp)) in state.iter().zip(expected_after_mds.iter()).enumerate() {
			assert_eq!(
				actual.as_canonical_u64(),
				*exp,
				"After initial MDS mismatch at index {}: got {}, expected {}",
				i,
				actual.as_canonical_u64(),
				exp
			);
		}

		// Step 2: First external round - add RC and S-box
		let rc = &poseidon.initial_external_constants[0];
		for i in 0..SPONGE_WIDTH {
			state[i] += rc[i];
			state[i] = state[i].exp7();
		}
		let expected_after_sbox = [
			5716687150516714629u64,
			12606094110489894541,
			7176561780833472673,
			2787933693728327558,
			2372134002172061930,
			5020691920936401247,
			15687823912570289724,
			15071980520517301340,
			751173130886275522,
			17086029608447879298,
			4895459708442877360,
			10576769927437500691,
		];
		for (i, (actual, exp)) in state.iter().zip(expected_after_sbox.iter()).enumerate() {
			assert_eq!(
				actual.as_canonical_u64(),
				*exp,
				"After first RC + S-box mismatch at index {}: got {}, expected {}",
				i,
				actual.as_canonical_u64(),
				exp
			);
		}

		// Step 3: MDS after first round
		external_linear_layer(&mut state);
		let expected_after_round = [
			15870188304392300026u64,
			5420667415882104228,
			4061330223075420786,
			3907156211996553271,
			7220184397568305579,
			6276399041015305555,
			10112551490188661599,
			920706293309282174,
			6439956850909369582,
			10360554408705021829,
			3933312188334710888,
			6787120046090971660,
		];
		for (i, (actual, exp)) in state.iter().zip(expected_after_round.iter()).enumerate() {
			assert_eq!(
				actual.as_canonical_u64(),
				*exp,
				"After first round MDS mismatch at index {}: got {}, expected {}",
				i,
				actual.as_canonical_u64(),
				exp
			);
		}
	}

	#[test]
	fn test_sbox() {
		// Compare S-box (x^7) against p3
		// p3 output: S-box(0): 0, S-box(1): 1, S-box(2): 128, S-box(5): 78125, S-box(4294967295):
		// 4294967295
		let test_cases = [
			(0u64, 0u64),
			(1, 1),
			(2, 128),
			(5, 78125),
			(0xFFFFFFFF, 0xFFFFFFFF), // (2^32-1)^7 mod P = 2^32-1
		];

		for (input, expected) in test_cases {
			let x = Goldilocks::from_u64(input);
			let y = x.exp7();
			assert_eq!(
				y.as_canonical_u64(),
				expected,
				"S-box mismatch for input {}: got {}, expected {}",
				input,
				y.as_canonical_u64(),
				expected
			);
		}
	}

	#[test]
	fn test_first_external_round_zero_state() {
		// Compare first external round with zero state against p3
		// p3 output after RC + S-box: [5716687150516714629, 12606094110489894541,
		// 7176561780833472673, 2787933693728327558, 2372134002172061930, 5020691920936401247,
		// 15687823912570289724, 15071980520517301340, 751173130886275522, 17086029608447879298,
		// 4895459708442877360, 10576769927437500691]

		let poseidon = Poseidon2::new();
		let mut state = [Goldilocks::ZERO; SPONGE_WIDTH];

		// Add round constants and apply S-box (first external round, no linear layer yet)
		let rc = &poseidon.initial_external_constants[0];
		for i in 0..SPONGE_WIDTH {
			state[i] += rc[i];
			state[i] = state[i].exp7();
		}

		let expected = [
			5716687150516714629u64,
			12606094110489894541,
			7176561780833472673,
			2787933693728327558,
			2372134002172061930,
			5020691920936401247,
			15687823912570289724,
			15071980520517301340,
			751173130886275522,
			17086029608447879298,
			4895459708442877360,
			10576769927437500691,
		];

		for (i, (actual, exp)) in state.iter().zip(expected.iter()).enumerate() {
			assert_eq!(
				actual.as_canonical_u64(),
				*exp,
				"First external round (RC+S-box) mismatch at index {}: got 0x{:x}, expected 0x{:x}",
				i,
				actual.as_canonical_u64(),
				exp
			);
		}
	}

	#[test]
	fn test_internal_linear_layer() {
		// Compare against p3's output for internal linear layer
		let mut state: [Goldilocks; SPONGE_WIDTH] =
			core::array::from_fn(|i| Goldilocks::from_u64((i + 1) as u64));
		let poseidon = Poseidon2::new();

		internal_linear_layer(&mut state, &poseidon.matrix_diag);

		let expected = [
			14102670999874605902u64,
			12724564314584031161,
			2820561051427350843,
			16542800896675938601,
			15306463738286039492,
			7752500014678011478,
			6061018803481092188,
			7074894295206835361,
			12845226504185330854,
			9784840285965170449,
			9819782087245364719,
			15989125545469266117,
		];

		for (i, (actual, exp)) in state.iter().zip(expected.iter()).enumerate() {
			assert_eq!(
				actual.as_canonical_u64(),
				*exp,
				"Internal linear layer mismatch at index {}: got {}, expected {}",
				i,
				actual.as_canonical_u64(),
				exp
			);
		}
	}

	#[test]
	fn test_external_linear_layer() {
		// Compare against p3's output for external linear layer
		let mut state: [Goldilocks; SPONGE_WIDTH] =
			core::array::from_fn(|i| Goldilocks::from_u64((i + 1) as u64));

		external_linear_layer(&mut state);

		// Expected from p3: [144, 156, 168, 148, 172, 184, 196, 176, 200, 212, 224, 204]
		let expected = [144u64, 156, 168, 148, 172, 184, 196, 176, 200, 212, 224, 204];
		for (i, (actual, exp)) in state.iter().zip(expected.iter()).enumerate() {
			assert_eq!(
				actual.as_canonical_u64(),
				*exp,
				"External linear layer mismatch at index {}: got {}, expected {}",
				i,
				actual.as_canonical_u64(),
				exp
			);
		}
	}

	#[test]
	fn test_poseidon2_matches_p3_zero_input() {
		let poseidon = Poseidon2::new();

		let mut state = [Goldilocks::ZERO; SPONGE_WIDTH];
		poseidon.permute_mut(&mut state);

		for (i, (actual, expected)) in state.iter().zip(P3_ZERO_RESULT.iter()).enumerate() {
			assert_eq!(
				actual.as_canonical_u64(),
				*expected,
				"Mismatch at index {} for zero input: got 0x{:016x}, expected 0x{:016x}",
				i,
				actual.as_canonical_u64(),
				expected
			);
		}
	}

	#[test]
	fn test_poseidon2_matches_p3_sequential_input() {
		let poseidon = Poseidon2::new();

		let mut state: [Goldilocks; SPONGE_WIDTH] =
			core::array::from_fn(|i| Goldilocks::from_u64((i + 1) as u64));
		poseidon.permute_mut(&mut state);

		for (i, (actual, expected)) in state.iter().zip(P3_SEQ_RESULT.iter()).enumerate() {
			assert_eq!(
				actual.as_canonical_u64(),
				*expected,
				"Mismatch at index {} for sequential input: got 0x{:016x}, expected 0x{:016x}",
				i,
				actual.as_canonical_u64(),
				expected
			);
		}
	}

	#[test]
	fn test_poseidon2_deterministic() {
		let poseidon = Poseidon2::new();

		let mut state1 = [Goldilocks::ZERO; SPONGE_WIDTH];
		let mut state2 = [Goldilocks::ZERO; SPONGE_WIDTH];

		poseidon.permute_mut(&mut state1);
		poseidon.permute_mut(&mut state2);

		assert_eq!(state1, state2, "Permutation should be deterministic");
	}

	#[test]
	fn test_poseidon2_non_trivial() {
		let poseidon = Poseidon2::new();

		let mut state = [Goldilocks::ZERO; SPONGE_WIDTH];
		let original = state;

		poseidon.permute_mut(&mut state);

		assert_ne!(state, original, "Permutation should change state");
	}

	#[test]
	fn test_apply_mat4() {
		// Test that mat4 produces expected output
		let mut x =
			[Goldilocks::new(1), Goldilocks::new(2), Goldilocks::new(3), Goldilocks::new(4)];
		apply_mat4(&mut x);

		// Matrix multiplication:
		// [ 2 3 1 1 ] [ 1 ]   [ 2+6+3+4 ]   [ 15 ]
		// [ 1 2 3 1 ] [ 2 ] = [ 1+4+9+4 ] = [ 18 ]
		// [ 1 1 2 3 ] [ 3 ]   [ 1+2+6+12]   [ 21 ]
		// [ 3 1 1 2 ] [ 4 ]   [ 3+2+3+8 ]   [ 16 ]
		assert_eq!(x[0].as_canonical_u64(), 15);
		assert_eq!(x[1].as_canonical_u64(), 18);
		assert_eq!(x[2].as_canonical_u64(), 21);
		assert_eq!(x[3].as_canonical_u64(), 16);
	}
}
