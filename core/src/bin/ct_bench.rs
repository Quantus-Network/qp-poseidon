//! Constant-time testing for Poseidon2 implementation using dudect-bencher
//!
//! This module tests that cryptographic operations in the Poseidon2 hash function
//! execute in constant time, preventing timing side-channel attacks.

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

/// Test that hash_padded_bytes executes in constant time for inputs of the same length
#[cfg(feature = "dudect-bencher")]
fn test_hash_padded_bytes_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	let mut inputs: Vec<(Vec<u8>, Class)> = Vec::new();

	// Generate test inputs with variable lengths
	for _ in 0..100_000 {
		// Use variable lengths between 16 and 5120 bytes (5KB)
		let len1 = 16 + (rng.next_u32() % 5105) as usize; // 16-5120 bytes
		let len2 = 16 + (rng.next_u32() % 5105) as usize; // 16-5120 bytes

		let mut input1 = vec![0u8; len1];
		let mut input2 = vec![0u8; len2];

		rng.fill_bytes(&mut input1);
		rng.fill_bytes(&mut input2);

		// Ensure inputs are different to test worst case
		input1[0] = 0xAA;
		input2[0] = 0x55;

		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let input = match class {
			Class::Left => input1,
			Class::Right => input2,
		};

		inputs.push((input, class));
	}

	for (input, class) in inputs {
		runner.run_one(class, || {
			let _result = hash_padded_bytes::<FIELD_ELEMENT_PREIMAGE_PADDING_LEN>(&input);
		});
	}
}

/// Test that hash_variable_length_bytes executes in constant time for inputs of the same length
#[cfg(feature = "dudect-bencher")]
fn test_hash_variable_length_bytes_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	let mut inputs: Vec<(Vec<u8>, Class)> = Vec::new();

	// Generate test inputs with variable lengths
	for _ in 0..100_000 {
		// Use variable lengths between 8 and 5000 bytes
		let len1 = 8 + (rng.next_u32() % 4993) as usize; // 8-5000 bytes
		let len2 = 8 + (rng.next_u32() % 4993) as usize; // 8-5000 bytes

		let mut input1 = vec![0u8; len1];
		let mut input2 = vec![0u8; len2];

		rng.fill_bytes(&mut input1);
		rng.fill_bytes(&mut input2);

		// Ensure inputs are different
		input1[0] = 0xAA;
		input2[0] = 0x55;

		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let input = match class {
			Class::Left => input1,
			Class::Right => input2,
		};

		inputs.push((input, class));
	}

	for (input, class) in inputs {
		runner.run_one(class, || {
			let _result = hash_variable_length_bytes(&input);
		});
	}
}

/// Test that the core Poseidon2 permutation executes in constant time
#[cfg(feature = "dudect-bencher")]
fn test_poseidon2_permutation_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	let poseidon = qp_poseidon_core::constants::create_poseidon();
	let mut inputs: Vec<([Goldilocks; 12], Class)> = Vec::new();

	// Generate test inputs
	for _ in 0..100_000 {
		let mut state1 = [Goldilocks::ZERO; 12];
		let mut state2 = [Goldilocks::ZERO; 12];

		for i in 0..12 {
			let val1 = rng.next_u64() % Goldilocks::ORDER_U64;
			let val2 = rng.next_u64() % Goldilocks::ORDER_U64;
			state1[i] = Goldilocks::from_int(val1);
			state2[i] = Goldilocks::from_int(val2);
		}

		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let state = match class {
			Class::Left => state1,
			Class::Right => state2,
		};

		inputs.push((state, class));
	}

	for (state, class) in inputs {
		runner.run_one(class, || {
			let mut state_copy = state;
			poseidon.permute_mut(&mut state_copy);
		});
	}
}

/// Test that hash_squeeze_twice executes in constant time
#[cfg(feature = "dudect-bencher")]
fn test_hash_squeeze_twice_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	let mut inputs: Vec<(Vec<u8>, Class)> = Vec::new();

	// Generate test inputs with variable lengths
	for _ in 0..100_000 {
		// Use variable lengths between 12 and 4096 bytes (4KB)
		let len1 = 12 + (rng.next_u32() % 4085) as usize; // 12-4096 bytes
		let len2 = 12 + (rng.next_u32() % 4085) as usize; // 12-4096 bytes

		let mut input1 = vec![0u8; len1];
		let mut input2 = vec![0u8; len2];

		rng.fill_bytes(&mut input1);
		rng.fill_bytes(&mut input2);

		// Ensure inputs are different
		input1[0] = 0xAA;
		input2[0] = 0x55;

		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let input = match class {
			Class::Left => input1,
			Class::Right => input2,
		};

		inputs.push((input, class));
	}

	for (input, class) in inputs {
		runner.run_one(class, || {
			let _result = hash_squeeze_twice(&input);
		});
	}
}

/// Test that field element absorption is constant time
#[cfg(feature = "dudect-bencher")]
fn test_field_absorption_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	let mut inputs: Vec<(Vec<u8>, Class)> = Vec::new();

	// Generate test inputs with variable lengths
	for _ in 0..100_000 {
		// Use variable lengths between 4 and 2048 bytes (2KB)
		let len1 = 4 + (rng.next_u32() % 2045) as usize; // 4-2048 bytes
		let len2 = 4 + (rng.next_u32() % 2045) as usize; // 4-2048 bytes

		let mut bytes1 = vec![0u8; len1];
		let mut bytes2 = vec![0u8; len2];

		rng.fill_bytes(&mut bytes1);
		rng.fill_bytes(&mut bytes2);

		// Ensure different inputs
		bytes1[0] = 0xAA;
		bytes2[0] = 0x55;

		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let bytes = match class {
			Class::Left => bytes1,
			Class::Right => bytes2,
		};

		inputs.push((bytes, class));
	}

	for (bytes, class) in inputs {
		runner.run_one(class, || {
			let _felts: Vec<Goldilocks> = injective_bytes_to_felts(&bytes);
		});
	}
}

/// Test that double hashing executes in constant time
#[cfg(feature = "dudect-bencher")]
fn test_double_hash_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	let mut inputs: Vec<(Vec<Goldilocks>, Class)> = Vec::new();

	// Generate test inputs with variable lengths
	for _ in 0..100_000 {
		// Use variable lengths between 8 and 3072 bytes (3KB)
		let len1 = 8 + (rng.next_u32() % 3065) as usize; // 8-3072 bytes
		let len2 = 8 + (rng.next_u32() % 3065) as usize; // 8-3072 bytes

		let mut bytes1 = vec![0u8; len1];
		let mut bytes2 = vec![0u8; len2];

		rng.fill_bytes(&mut bytes1);
		rng.fill_bytes(&mut bytes2);

		// Ensure different inputs
		bytes1[0] = 0xAA;
		bytes2[0] = 0x55;

		let felts1 = injective_bytes_to_felts(&bytes1);
		let felts2 = injective_bytes_to_felts(&bytes2);

		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let felts = match class {
			Class::Left => felts1,
			Class::Right => felts2,
		};

		inputs.push((felts, class));
	}

	for (felts, class) in inputs {
		runner.run_one(class, || {
			let _result = double_hash_variable_length(felts.clone());
		});
	}
}

/// Test edge cases: different single bytes should be constant time
#[cfg(feature = "dudect-bencher")]
fn test_edge_cases_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	let mut inputs: Vec<(Vec<u8>, Class)> = Vec::new();

	// Generate test inputs
	for _ in 0..100_000 {
		let byte1 = rng.next_u32() as u8;
		let mut byte2 = rng.next_u32() as u8;

		// Ensure different
		if byte1 == byte2 {
			byte2 = byte2.wrapping_add(1);
		}

		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let byte_vec = match class {
			Class::Left => vec![byte1],
			Class::Right => vec![byte2],
		};

		inputs.push((byte_vec, class));
	}

	for (input, class) in inputs {
		runner.run_one(class, || {
			let _result = hash_padded_bytes::<FIELD_ELEMENT_PREIMAGE_PADDING_LEN>(&input);
		});
	}
}

/// Integration test combining multiple operations
#[cfg(feature = "dudect-bencher")]
fn test_integrated_operations_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	let mut inputs: Vec<(Vec<u8>, Class)> = Vec::new();

	// Generate test inputs with variable lengths
	for _ in 0..50_000 {
		// Fewer iterations since this does more work
		// Use variable lengths between 32 and 5120 bytes (5KB)
		let len1 = 32 + (rng.next_u32() % 5089) as usize; // 32-5120 bytes
		let len2 = 32 + (rng.next_u32() % 5089) as usize; // 32-5120 bytes

		let mut input1 = vec![0u8; len1];
		let mut input2 = vec![0u8; len2];

		rng.fill_bytes(&mut input1);
		rng.fill_bytes(&mut input2);

		// Ensure different inputs
		input1[0] = 0xAA;
		input2[0] = 0x55;

		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let input = match class {
			Class::Left => input1,
			Class::Right => input2,
		};

		inputs.push((input, class));
	}

	for (input, class) in inputs {
		runner.run_one(class, || {
			// Test a sequence of operations that might be used together
			let _hash_padded = hash_padded_bytes::<FIELD_ELEMENT_PREIMAGE_PADDING_LEN>(&input);
			let _hash_variable = hash_variable_length_bytes(&input);
			let _squeeze = hash_squeeze_twice(&input);
		});
	}
}

/// Test that variable length hashing is constant time for same-length inputs
#[cfg(feature = "dudect-bencher")]
fn test_hash_variable_length_felts_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
	let mut inputs: Vec<(Vec<Goldilocks>, Class)> = Vec::new();

	// Generate test inputs with variable lengths
	for _ in 0..100_000 {
		// Use variable lengths between 5 and 650 field elements (~5KB worth)
		let len1 = 5 + (rng.next_u32() % 646) as usize; // 5-650 elements
		let len2 = 5 + (rng.next_u32() % 646) as usize; // 5-650 elements

		let mut felts1 = Vec::with_capacity(len1);
		let mut felts2 = Vec::with_capacity(len2);

		for _ in 0..len1 {
			let val = rng.next_u64() % Goldilocks::ORDER_U64;
			felts1.push(Goldilocks::from_int(val));
		}

		for _ in 0..len2 {
			let val = rng.next_u64() % Goldilocks::ORDER_U64;
			felts2.push(Goldilocks::from_int(val));
		}

		let class = if rng.gen::<bool>() { Class::Left } else { Class::Right };
		let felts = match class {
			Class::Left => felts1,
			Class::Right => felts2,
		};

		inputs.push((felts, class));
	}

	for (felts, class) in inputs {
		runner.run_one(class, || {
			let _result = hash_variable_length(felts.clone());
		});
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	// Simple unit tests to ensure functions compile and run
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
	test_hash_padded_bytes_ct,
	test_hash_variable_length_bytes_ct,
	test_poseidon2_permutation_ct,
	test_hash_squeeze_twice_ct,
	test_field_absorption_ct,
	test_double_hash_ct,
	test_edge_cases_ct,
	test_integrated_operations_ct,
	test_hash_variable_length_felts_ct
);
