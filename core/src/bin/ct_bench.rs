//! Constant-time testing for Poseidon2 implementation using dudect-bencher
//!
//! This module tests that cryptographic operations in the Poseidon2 hash function
//! execute in constant time, preventing timing side-channel attacks.
//!
//! Tests are organized by fixed input sizes with statistically distinguishable input classes:
//! - Class A: Fixed pattern (all 0x00 or all 0xFF)
//! - Class B: Random data
//!
//! This ensures the two classes are distinguishable before timing analysis begins.

#[cfg(feature = "dudect-bencher")]
use dudect_bencher::rand::{Rng, RngCore};
#[cfg(feature = "dudect-bencher")]
use dudect_bencher::{BenchRng, Class, CtRunner};
use p3_field::integers::QuotientMap;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_symmetric::Permutation;
use qp_poseidon_core::serialization::injective_bytes_to_felts;
use qp_poseidon_core::*;

const FIELD_ELEMENT_PREIMAGE_PADDING_LEN: usize = 189;

// Test sizes in bytes
const SMALL_INPUT_SIZE: usize = 32;
const MEDIUM_INPUT_SIZE: usize = 256;
const LARGE_INPUT_SIZE: usize = 1024;
const EXTRA_LARGE_INPUT_SIZE: usize = 4096;

// Field element test sizes
const SMALL_FELT_COUNT: usize = 4;
const MEDIUM_FELT_COUNT: usize = 32;
const LARGE_FELT_COUNT: usize = 128;

/// Generate a fixed input for Left class (same for all samples) and random input for Right class
fn generate_fixed_byte_input(size: usize) -> Vec<u8> {
	// Always use 0xFF for the fixed input
	vec![0xFFu8; size]
}

/// Generate a random byte input for Right class
fn generate_random_byte_input(size: usize, rng: &mut BenchRng) -> Vec<u8> {
	let mut random_input = vec![0u8; size];
	rng.fill_bytes(&mut random_input);
	random_input
}

/// Generate a fixed field element input for Left class (same for all samples)
fn generate_fixed_felt_input(count: usize) -> Vec<Goldilocks> {
	// Always use ZERO for the fixed input
	vec![Goldilocks::ZERO; count]
}

/// Generate a random field element input for Right class
fn generate_random_felt_input(count: usize, rng: &mut BenchRng) -> Vec<Goldilocks> {
	let mut random_input = Vec::with_capacity(count);
	for _ in 0..count {
		let val = rng.next_u64() % Goldilocks::ORDER_U64;
		random_input.push(Goldilocks::from_int(val));
	}
	random_input
}

/// Test hash_padded_bytes with small inputs (32 bytes)
#[cfg(feature = "dudect-bencher")]
fn test_hash_padded_bytes_small_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_input = generate_fixed_byte_input(SMALL_INPUT_SIZE);

	for _ in 0..100_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let input = match class {
			Class::Left => fixed_input.clone(),
			Class::Right => generate_random_byte_input(SMALL_INPUT_SIZE, rng),
		};

		runner.run_one(class, || {
			let _result = hash_padded_bytes::<FIELD_ELEMENT_PREIMAGE_PADDING_LEN>(&input);
		});
	}
}

/// Test hash_padded_bytes with medium inputs (256 bytes)
#[cfg(feature = "dudect-bencher")]
fn test_hash_padded_bytes_medium_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_input = generate_fixed_byte_input(MEDIUM_INPUT_SIZE);

	for _ in 0..100_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let input = match class {
			Class::Left => fixed_input.clone(),
			Class::Right => generate_random_byte_input(MEDIUM_INPUT_SIZE, rng),
		};

		runner.run_one(class, || {
			let _result = hash_padded_bytes::<FIELD_ELEMENT_PREIMAGE_PADDING_LEN>(&input);
		});
	}
}

/// Test hash_padded_bytes with large inputs (1KB)
#[cfg(feature = "dudect-bencher")]
fn test_hash_padded_bytes_large_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_input = generate_fixed_byte_input(LARGE_INPUT_SIZE);

	for _ in 0..50_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let input = match class {
			Class::Left => fixed_input.clone(),
			Class::Right => generate_random_byte_input(LARGE_INPUT_SIZE, rng),
		};

		runner.run_one(class, || {
			let _result = hash_padded_bytes::<FIELD_ELEMENT_PREIMAGE_PADDING_LEN>(&input);
		});
	}
}

/// Test hash_padded_bytes with extra large inputs (4KB)
#[cfg(feature = "dudect-bencher")]
fn test_hash_padded_bytes_xlarge_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_input = generate_fixed_byte_input(EXTRA_LARGE_INPUT_SIZE);

	for _ in 0..25_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let input = match class {
			Class::Left => fixed_input.clone(),
			Class::Right => generate_random_byte_input(EXTRA_LARGE_INPUT_SIZE, rng),
		};

		runner.run_one(class, || {
			let _result = hash_padded_bytes::<FIELD_ELEMENT_PREIMAGE_PADDING_LEN>(&input);
		});
	}
}

/// Test hash_variable_length_bytes with small inputs (32 bytes)
#[cfg(feature = "dudect-bencher")]
fn test_hash_variable_length_bytes_small_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_input = generate_fixed_byte_input(SMALL_INPUT_SIZE);

	for _ in 0..100_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let input = match class {
			Class::Left => fixed_input.clone(),
			Class::Right => generate_random_byte_input(SMALL_INPUT_SIZE, rng),
		};

		runner.run_one(class, || {
			let _result = hash_variable_length_bytes(&input);
		});
	}
}

/// Test hash_variable_length_bytes with medium inputs (256 bytes)
#[cfg(feature = "dudect-bencher")]
fn test_hash_variable_length_bytes_medium_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_input = generate_fixed_byte_input(MEDIUM_INPUT_SIZE);

	for _ in 0..100_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let input = match class {
			Class::Left => fixed_input.clone(),
			Class::Right => generate_random_byte_input(MEDIUM_INPUT_SIZE, rng),
		};

		runner.run_one(class, || {
			let _result = hash_variable_length_bytes(&input);
		});
	}
}

/// Test hash_variable_length_bytes with large inputs (1KB)
#[cfg(feature = "dudect-bencher")]
fn test_hash_variable_length_bytes_large_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_input = generate_fixed_byte_input(LARGE_INPUT_SIZE);

	for _ in 0..50_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let input = match class {
			Class::Left => fixed_input.clone(),
			Class::Right => generate_random_byte_input(LARGE_INPUT_SIZE, rng),
		};

		runner.run_one(class, || {
			let _result = hash_variable_length_bytes(&input);
		});
	}
}

/// Test the core Poseidon2 permutation with fixed state patterns
#[cfg(feature = "dudect-bencher")]
fn test_poseidon2_permutation_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	let poseidon = qp_poseidon_core::constants::create_poseidon();

	// Generate the fixed state once for all Left class samples
	let fixed_state = [Goldilocks::ZERO; 12];

	for _ in 0..100_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let state = match class {
			Class::Left => fixed_state,
			Class::Right => {
				let mut random_state = [Goldilocks::ZERO; 12];
				for i in 0..12 {
					let val = rng.next_u64() % Goldilocks::ORDER_U64;
					random_state[i] = Goldilocks::from_int(val);
				}
				random_state
			}
		};

		runner.run_one(class, || {
			let mut state_copy = state;
			poseidon.permute_mut(&mut state_copy);
		});
	}
}

/// Test hash_squeeze_twice with small inputs (32 bytes)
#[cfg(feature = "dudect-bencher")]
fn test_hash_squeeze_twice_small_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_input = generate_fixed_byte_input(SMALL_INPUT_SIZE);

	for _ in 0..100_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let input = match class {
			Class::Left => fixed_input.clone(),
			Class::Right => generate_random_byte_input(SMALL_INPUT_SIZE, rng),
		};

		runner.run_one(class, || {
			let _result = hash_squeeze_twice(&input);
		});
	}
}

/// Test hash_squeeze_twice with medium inputs (256 bytes)
#[cfg(feature = "dudect-bencher")]
fn test_hash_squeeze_twice_medium_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_input = generate_fixed_byte_input(MEDIUM_INPUT_SIZE);

	for _ in 0..100_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let input = match class {
			Class::Left => fixed_input.clone(),
			Class::Right => generate_random_byte_input(MEDIUM_INPUT_SIZE, rng),
		};

		runner.run_one(class, || {
			let _result = hash_squeeze_twice(&input);
		});
	}
}

/// Test hash_squeeze_twice with large inputs (1KB)
#[cfg(feature = "dudect-bencher")]
fn test_hash_squeeze_twice_large_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_input = generate_fixed_byte_input(LARGE_INPUT_SIZE);

	for _ in 0..50_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let input = match class {
			Class::Left => fixed_input.clone(),
			Class::Right => generate_random_byte_input(LARGE_INPUT_SIZE, rng),
		};

		runner.run_one(class, || {
			let _result = hash_squeeze_twice(&input);
		});
	}
}

/// Test field element absorption with small inputs
#[cfg(feature = "dudect-bencher")]
fn test_field_absorption_small_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_input = generate_fixed_byte_input(SMALL_INPUT_SIZE);

	for _ in 0..100_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let input = match class {
			Class::Left => fixed_input.clone(),
			Class::Right => generate_random_byte_input(SMALL_INPUT_SIZE, rng),
		};

		runner.run_one(class, || {
			let _felts: Vec<Goldilocks> = injective_bytes_to_felts(&input);
		});
	}
}

/// Test field element absorption with medium inputs
#[cfg(feature = "dudect-bencher")]
fn test_field_absorption_medium_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_input = generate_fixed_byte_input(MEDIUM_INPUT_SIZE);

	for _ in 0..100_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let input = match class {
			Class::Left => fixed_input.clone(),
			Class::Right => generate_random_byte_input(MEDIUM_INPUT_SIZE, rng),
		};

		runner.run_one(class, || {
			let _felts: Vec<Goldilocks> = injective_bytes_to_felts(&input);
		});
	}
}

/// Test double hashing with small field element inputs
#[cfg(feature = "dudect-bencher")]
fn test_double_hash_small_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_felts = generate_fixed_felt_input(SMALL_FELT_COUNT);

	for _ in 0..100_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let felts = match class {
			Class::Left => fixed_felts.clone(),
			Class::Right => generate_random_felt_input(SMALL_FELT_COUNT, rng),
		};

		runner.run_one(class, || {
			let _result = double_hash_variable_length(felts.clone());
		});
	}
}

/// Test double hashing with medium field element inputs
#[cfg(feature = "dudect-bencher")]
fn test_double_hash_medium_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_felts = generate_fixed_felt_input(MEDIUM_FELT_COUNT);

	for _ in 0..100_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let felts = match class {
			Class::Left => fixed_felts.clone(),
			Class::Right => generate_random_felt_input(MEDIUM_FELT_COUNT, rng),
		};

		runner.run_one(class, || {
			let _result = double_hash_variable_length(felts.clone());
		});
	}
}

/// Test hash_variable_length with small field element inputs
#[cfg(feature = "dudect-bencher")]
fn test_hash_variable_length_felts_small_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_felts = generate_fixed_felt_input(SMALL_FELT_COUNT);

	for _ in 0..100_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let felts = match class {
			Class::Left => fixed_felts.clone(),
			Class::Right => generate_random_felt_input(SMALL_FELT_COUNT, rng),
		};

		runner.run_one(class, || {
			let _result = hash_variable_length(felts.clone());
		});
	}
}

/// Test hash_variable_length with medium field element inputs
#[cfg(feature = "dudect-bencher")]
fn test_hash_variable_length_felts_medium_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_felts = generate_fixed_felt_input(MEDIUM_FELT_COUNT);

	for _ in 0..100_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let felts = match class {
			Class::Left => fixed_felts.clone(),
			Class::Right => generate_random_felt_input(MEDIUM_FELT_COUNT, rng),
		};

		runner.run_one(class, || {
			let _result = hash_variable_length(felts.clone());
		});
	}
}

/// Test hash_variable_length with large field element inputs
#[cfg(feature = "dudect-bencher")]
fn test_hash_variable_length_felts_large_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_felts = generate_fixed_felt_input(LARGE_FELT_COUNT);

	for _ in 0..50_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let felts = match class {
			Class::Left => fixed_felts.clone(),
			Class::Right => generate_random_felt_input(LARGE_FELT_COUNT, rng),
		};

		runner.run_one(class, || {
			let _result = hash_variable_length(felts.clone());
		});
	}
}

/// Test double hashing with large field element inputs
#[cfg(feature = "dudect-bencher")]
fn test_double_hash_large_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_felts = generate_fixed_felt_input(LARGE_FELT_COUNT);

	for _ in 0..50_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let felts = match class {
			Class::Left => fixed_felts.clone(),
			Class::Right => generate_random_felt_input(LARGE_FELT_COUNT, rng),
		};

		runner.run_one(class, || {
			let _result = double_hash_variable_length(felts.clone());
		});
	}
}

/// Test single byte edge cases with fixed vs random patterns
#[cfg(feature = "dudect-bencher")]
fn test_single_byte_edge_cases_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_input = vec![0xFFu8];

	for _ in 0..100_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let input = match class {
			Class::Left => fixed_input.clone(),
			Class::Right => {
				let random_byte = rng.next_u32() as u8;
				vec![random_byte]
			}
		};

		runner.run_one(class, || {
			let _result = hash_padded_bytes::<FIELD_ELEMENT_PREIMAGE_PADDING_LEN>(&input);
		});
	}
}

/// Integration test with medium-sized inputs combining multiple operations
#[cfg(feature = "dudect-bencher")]
fn test_integrated_operations_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_input = generate_fixed_byte_input(MEDIUM_INPUT_SIZE);

	for _ in 0..25_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let input = match class {
			Class::Left => fixed_input.clone(),
			Class::Right => generate_random_byte_input(MEDIUM_INPUT_SIZE, rng),
		};

		runner.run_one(class, || {
			// Test a sequence of operations that might be used together
			let _hash_padded = hash_padded_bytes::<FIELD_ELEMENT_PREIMAGE_PADDING_LEN>(&input);
			let _hash_variable = hash_variable_length_bytes(&input);
			let _squeeze = hash_squeeze_twice(&input);
		});
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_input_generation_distinguishable() {
		let mut rng = BenchRng::new();

		// Test byte input generation
		let fixed = generate_fixed_byte_input(32);
		let random = generate_random_byte_input(32, &mut rng);
		assert_eq!(fixed.len(), 32);
		assert_eq!(random.len(), 32);

		// Fixed should be all 0xFF
		assert!(fixed.iter().all(|&b| b == 0xFF));

		// Test felt input generation
		let fixed_felts = generate_fixed_felt_input(8);
		let random_felts = generate_random_felt_input(8, &mut rng);
		assert_eq!(fixed_felts.len(), 8);
		assert_eq!(random_felts.len(), 8);

		// Fixed should be all ZERO
		assert!(fixed_felts.iter().all(|&f| f == Goldilocks::ZERO));
	}

	#[test]
	fn test_ct_functions_compile() {
		// This test just ensures the hash functions compile and work
		let input = vec![0u8; 32];
		let _result = hash_padded_bytes::<FIELD_ELEMENT_PREIMAGE_PADDING_LEN>(&input);
		let _result2 = hash_variable_length_bytes(&input);
		let _result3 = hash_squeeze_twice(&input);

		// Test field operations
		let felts = injective_bytes_to_felts(&input);
		let _result4 = hash_variable_length(felts.clone());
		let _result5 = double_hash_variable_length(felts);
	}
}

// This creates a main function when compiled as a binary
#[cfg(all(not(test), feature = "dudect-bencher"))]
dudect_bencher::ctbench_main!(
	// hash_padded_bytes tests for different input sizes
	test_hash_padded_bytes_small_ct,
	test_hash_padded_bytes_medium_ct,
	test_hash_padded_bytes_large_ct,
	test_hash_padded_bytes_xlarge_ct,
	// hash_variable_length_bytes tests for different input sizes
	test_hash_variable_length_bytes_small_ct,
	test_hash_variable_length_bytes_medium_ct,
	test_hash_variable_length_bytes_large_ct,
	// Core permutation test
	test_poseidon2_permutation_ct,
	// hash_squeeze_twice tests for different input sizes
	test_hash_squeeze_twice_small_ct,
	test_hash_squeeze_twice_medium_ct,
	test_hash_squeeze_twice_large_ct,
	// Field element absorption tests
	test_field_absorption_small_ct,
	test_field_absorption_medium_ct,
	// Double hash tests for different felt counts
	test_double_hash_small_ct,
	test_double_hash_medium_ct,
	test_double_hash_large_ct,
	// hash_variable_length with felts for different sizes
	test_hash_variable_length_felts_small_ct,
	test_hash_variable_length_felts_medium_ct,
	test_hash_variable_length_felts_large_ct,
	// Edge cases and integration tests
	test_single_byte_edge_cases_ct,
	test_integrated_operations_ct
);
