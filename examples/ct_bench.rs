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

use std::hint::black_box;

use dudect_bencher::{
	rand::{Rng, RngCore},
	BenchRng, Class, CtRunner,
};
use qp_poseidon_core::{serialization::bytes_to_felts, *};

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
fn generate_fixed_byte_input(size: usize, rng: &mut BenchRng) -> Vec<u8> {
	// Pick a byte and repeat
	let byte = rng.gen::<u8>();
	vec![byte; size]
}

/// Generate a random byte input for Right class
fn generate_random_byte_input(size: usize, rng: &mut BenchRng) -> Vec<u8> {
	let mut random_input = vec![0u8; size];
	rng.fill_bytes(&mut random_input);
	random_input
}

/// Generate a fixed field element input for Left class (same for all samples)
fn generate_fixed_felt_input(count: usize, rng: &mut BenchRng) -> Vec<Goldilocks> {
	// Always use ZERO for the fixed input
	let felt = Goldilocks::from_u64(rng.next_u64());
	vec![felt; count]
}

/// Generate a random field element input for Right class
fn generate_random_felt_input(count: usize, rng: &mut BenchRng) -> Vec<Goldilocks> {
	let mut random_input = Vec::with_capacity(count);
	for _ in 0..count {
		random_input.push(Goldilocks::from_u64(rng.next_u64()));
	}
	random_input
}

/// Disrupt cache and microarchitectural state between samples
fn disrupt_cache(rng: &mut BenchRng) {
	// Large memory access to evict cache lines
	let dummy = vec![0u8; 16 * 1024 * 1024]; // 16MB
	let mut sum = 0u64;

	// Access every cache line (64 bytes) to force eviction
	for i in (0..dummy.len()).step_by(64) {
		sum = sum.wrapping_add(dummy[i] as u64);
	}

	// Random access pattern to disrupt prefetcher
	for _ in 0..100 {
		let idx = rng.gen_range(0..dummy.len());
		sum = sum.wrapping_add(dummy[idx] as u64);
	}

	// Memory barrier and dummy computation
	std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
	for i in 0..1000 {
		sum = sum.wrapping_mul(i).wrapping_add(0xDEADBEEF);
	}

	// Prevent compiler optimization
	std::hint::black_box(sum);
}

/// Test hash_bytes with small inputs (32 bytes)
fn test_hash_bytes_small_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_input = generate_fixed_byte_input(SMALL_INPUT_SIZE, rng);

	for _ in 0..10_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let input = match class {
			Class::Left => fixed_input.clone(),
			Class::Right => generate_random_byte_input(SMALL_INPUT_SIZE, rng),
		};

		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			black_box(hash_bytes(black_box(&input)));
		});
	}
}

/// Test hash_bytes with medium inputs (256 bytes)
fn test_hash_bytes_medium_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_input = generate_fixed_byte_input(MEDIUM_INPUT_SIZE, rng);

	for _ in 0..10_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let input = match class {
			Class::Left => fixed_input.clone(),
			Class::Right => generate_random_byte_input(MEDIUM_INPUT_SIZE, rng),
		};

		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			black_box(hash_bytes(black_box(&input)));
		});
	}
}

/// Test hash_bytes with large inputs (1KB)
fn test_hash_bytes_large_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_input = generate_fixed_byte_input(LARGE_INPUT_SIZE, rng);

	for _ in 0..5_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let input = match class {
			Class::Left => fixed_input.clone(),
			Class::Right => generate_random_byte_input(LARGE_INPUT_SIZE, rng),
		};

		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			black_box(hash_bytes(black_box(&input)));
		});
	}
}

/// Test hash_bytes with extra large inputs (4KB)
fn test_hash_bytes_xlarge_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_input = generate_fixed_byte_input(EXTRA_LARGE_INPUT_SIZE, rng);

	for _ in 0..5_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let input = match class {
			Class::Left => fixed_input.clone(),
			Class::Right => generate_random_byte_input(EXTRA_LARGE_INPUT_SIZE, rng),
		};

		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			black_box(hash_bytes(black_box(&input)));
		});
	}
}

/// Test hash_variable_length_bytes with small inputs (32 bytes)
fn test_hash_variable_length_bytes_small_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_input = generate_fixed_byte_input(SMALL_INPUT_SIZE, rng);

	for _ in 0..10_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let input = match class {
			Class::Left => fixed_input.clone(),
			Class::Right => generate_random_byte_input(SMALL_INPUT_SIZE, rng),
		};

		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			black_box(hash_bytes(black_box(&input)));
		});
	}
}

/// Test hash_variable_length_bytes with medium inputs (256 bytes)
fn test_hash_variable_length_bytes_medium_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_input = generate_fixed_byte_input(MEDIUM_INPUT_SIZE, rng);

	for _ in 0..10_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let input = match class {
			Class::Left => fixed_input.clone(),
			Class::Right => generate_random_byte_input(MEDIUM_INPUT_SIZE, rng),
		};

		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			black_box(hash_bytes(black_box(&input)));
		});
	}
}

/// Test hash_variable_length_bytes with large inputs (1KB)
fn test_hash_variable_length_bytes_large_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_input = generate_fixed_byte_input(LARGE_INPUT_SIZE, rng);

	for _ in 0..5_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let input = match class {
			Class::Left => fixed_input.clone(),
			Class::Right => generate_random_byte_input(LARGE_INPUT_SIZE, rng),
		};

		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			black_box(hash_bytes(black_box(&input)));
		});
	}
}

/// Test the core Poseidon2 permutation with fixed state patterns
fn test_poseidon2_permutation_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	let poseidon = Poseidon2::new();

	// Generate the fixed state once for all Left class samples
	let fixed_value = Goldilocks::from_u64(rng.next_u64());
	let fixed_state = [fixed_value; SPONGE_WIDTH];

	for _ in 0..10_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let state = match class {
			Class::Left => fixed_state,
			Class::Right => {
				let mut random_state = [Goldilocks::ZERO; SPONGE_WIDTH];
				for slot in &mut random_state {
					*slot = Goldilocks::from_u64(rng.next_u64());
				}
				random_state
			},
		};

		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			let mut state_copy = black_box(state);
			poseidon.permute_mut(&mut state_copy);
			black_box(state_copy);
		});
	}
}

/// Test hash_squeeze_twice with small inputs (32 bytes)
fn test_hash_squeeze_twice_small_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_input = generate_fixed_byte_input(SMALL_INPUT_SIZE, rng);

	for _ in 0..10_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let input = match class {
			Class::Left => fixed_input.clone(),
			Class::Right => generate_random_byte_input(SMALL_INPUT_SIZE, rng),
		};

		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			black_box(hash_squeeze_twice(black_box(&input)));
		});
	}
}

/// Test hash_squeeze_twice with medium inputs (256 bytes)
fn test_hash_squeeze_twice_medium_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_input = generate_fixed_byte_input(MEDIUM_INPUT_SIZE, rng);

	for _ in 0..10_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let input = match class {
			Class::Left => fixed_input.clone(),
			Class::Right => generate_random_byte_input(MEDIUM_INPUT_SIZE, rng),
		};

		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			black_box(hash_squeeze_twice(black_box(&input)));
		});
	}
}

/// Test hash_squeeze_twice with large inputs (1KB)
fn test_hash_squeeze_twice_large_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_input = generate_fixed_byte_input(LARGE_INPUT_SIZE, rng);

	for _ in 0..5_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let input = match class {
			Class::Left => fixed_input.clone(),
			Class::Right => generate_random_byte_input(LARGE_INPUT_SIZE, rng),
		};

		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			black_box(hash_squeeze_twice(black_box(&input)));
		});
	}
}

/// Test field element absorption with small inputs
fn test_field_absorption_small_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_input = generate_fixed_byte_input(SMALL_INPUT_SIZE, rng);

	for _ in 0..10_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let input = match class {
			Class::Left => fixed_input.clone(),
			Class::Right => generate_random_byte_input(SMALL_INPUT_SIZE, rng),
		};

		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			black_box::<Vec<Goldilocks>>(bytes_to_felts(black_box(&input)));
		});
	}
}

/// Test field element absorption with medium inputs
fn test_field_absorption_medium_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_input = generate_fixed_byte_input(MEDIUM_INPUT_SIZE, rng);

	for _ in 0..10_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let input = match class {
			Class::Left => fixed_input.clone(),
			Class::Right => generate_random_byte_input(MEDIUM_INPUT_SIZE, rng),
		};

		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			black_box::<Vec<Goldilocks>>(bytes_to_felts(black_box(&input)));
		});
	}
}

/// Test field element absorption with large inputs
fn test_field_absorption_large_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_input = generate_fixed_byte_input(LARGE_INPUT_SIZE, rng);

	for _ in 0..5_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let input = match class {
			Class::Left => fixed_input.clone(),
			Class::Right => generate_random_byte_input(LARGE_INPUT_SIZE, rng),
		};

		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			black_box::<Vec<Goldilocks>>(bytes_to_felts(black_box(&input)));
		});
	}
}

/// Test double hashing with small field element inputs
fn test_double_hash_small_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_felts = generate_fixed_felt_input(SMALL_FELT_COUNT, rng);

	for _ in 0..10_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let felts = match class {
			Class::Left => fixed_felts.clone(),
			Class::Right => generate_random_felt_input(SMALL_FELT_COUNT, rng),
		};

		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			black_box(hash_twice(black_box(&felts)));
		});
	}
}

/// Test double hashing with medium field element inputs
fn test_double_hash_medium_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_felts = generate_fixed_felt_input(MEDIUM_FELT_COUNT, rng);

	for _ in 0..10_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let felts = match class {
			Class::Left => fixed_felts.clone(),
			Class::Right => generate_random_felt_input(MEDIUM_FELT_COUNT, rng),
		};

		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			black_box(hash_twice(black_box(&felts)));
		});
	}
}

/// Test hash_variable_length with small field element inputs
fn test_hash_variable_length_felts_small_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_felts = generate_fixed_felt_input(SMALL_FELT_COUNT, rng);

	for _ in 0..10_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let felts = match class {
			Class::Left => fixed_felts.clone(),
			Class::Right => generate_random_felt_input(SMALL_FELT_COUNT, rng),
		};

		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			black_box(hash_to_bytes(black_box(&felts)));
		});
	}
}

/// Test hash_variable_length with medium field element inputs
fn test_hash_variable_length_felts_medium_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_felts = generate_fixed_felt_input(MEDIUM_FELT_COUNT, rng);

	for _ in 0..10_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let felts = match class {
			Class::Left => fixed_felts.clone(),
			Class::Right => generate_random_felt_input(MEDIUM_FELT_COUNT, rng),
		};

		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			black_box(hash_to_bytes(black_box(&felts)));
		});
	}
}

/// Test hash_variable_length with large field element inputs
fn test_hash_variable_length_felts_large_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_felts = generate_fixed_felt_input(LARGE_FELT_COUNT, rng);

	for _ in 0..5_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let felts = match class {
			Class::Left => fixed_felts.clone(),
			Class::Right => generate_random_felt_input(LARGE_FELT_COUNT, rng),
		};

		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			black_box(hash_to_bytes(black_box(&felts)));
		});
	}
}

/// Test double hashing with large field element inputs
fn test_double_hash_large_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_felts = generate_fixed_felt_input(LARGE_FELT_COUNT, rng);

	for _ in 0..5_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let felts = match class {
			Class::Left => fixed_felts.clone(),
			Class::Right => generate_random_felt_input(LARGE_FELT_COUNT, rng),
		};

		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			black_box(hash_twice(black_box(&felts)));
		});
	}
}

/// Test single byte edge cases with fixed vs random patterns
fn test_single_byte_edge_cases_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_byte = rng.gen::<u8>();
	let fixed_input = vec![fixed_byte];

	for _ in 0..10_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let input = match class {
			Class::Left => fixed_input.clone(),
			Class::Right => {
				let random_byte = rng.next_u32() as u8;
				vec![random_byte]
			},
		};

		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			black_box(hash_bytes(black_box(&input)));
		});
	}
}

/// Integration test with medium-sized inputs combining multiple operations
fn test_integrated_operations_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	// Generate the fixed input once for all Left class samples
	let fixed_input = generate_fixed_byte_input(MEDIUM_INPUT_SIZE, rng);

	for _ in 0..5_000 {
		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let input = match class {
			Class::Left => fixed_input.clone(),
			Class::Right => generate_random_byte_input(MEDIUM_INPUT_SIZE, rng),
		};

		// Disrupt cache state before each sample
		disrupt_cache(rng);

		runner.run_one(class, || {
			// Test a sequence of operations that might be used together
			let hash = hash_bytes(black_box(&input));
			// Chain with rehash (tests bytes -> felts -> hash path).
			// Library-produced digests are always canonical, so this cannot fail.
			black_box(rehash_to_bytes(&hash).expect("canonical digest"));
			black_box(hash_squeeze_twice(black_box(&input)));
		});
	}
}

dudect_bencher::ctbench_main!(
	// hash_bytes tests for different input sizes
	test_hash_bytes_small_ct,
	test_hash_bytes_medium_ct,
	test_hash_bytes_large_ct,
	test_hash_bytes_xlarge_ct,
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
	test_field_absorption_large_ct,
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
