//! Utility to extract Poseidon2 constants for hardcoding to avoid re-derivation

use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;
use p3_poseidon2::ExternalLayerConstants;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

/// The same seed used in the main library
const POSEIDON2_SEED: u64 = 0x3141592653589793;

fn main() {
	// Generate the constants using the same method as the library
	let mut rng = ChaCha20Rng::seed_from_u64(POSEIDON2_SEED);

	// Get the round numbers for width 12
	let round_numbers = p3_poseidon2::poseidon2_round_numbers_128::<Goldilocks>(12, 7).unwrap();
	let (rounds_f, rounds_p) = round_numbers;

	println!("// Auto-generated Poseidon2 constants for WIDTH=12");
	println!("// Generated with seed: 0x{:016x}", POSEIDON2_SEED);
	println!("// External rounds: {}, Internal rounds: {}", rounds_f, rounds_p);
	println!();

	// Generate external constants
	let external_constants =
		ExternalLayerConstants::<Goldilocks, 12>::new_from_rng(rounds_f, &mut rng);
	let initial_constants = external_constants.get_initial_constants();
	let terminal_constants = external_constants.get_terminal_constants();

	// Generate internal constants
	use rand::Rng;
	let internal_constants: Vec<Goldilocks> = (0..rounds_p).map(|_| rng.random()).collect();

	// Print imports and setup
	println!("extern crate alloc;");
	println!();
	println!("use alloc::vec;");
	println!("use alloc::vec::Vec;");
	println!("use once_cell::sync::Lazy;");
	println!("use p3_field::integers::QuotientMap;");
	println!("use p3_goldilocks::{{Goldilocks, Poseidon2Goldilocks}};");
	println!("use p3_poseidon2::{{ExternalLayerConstants, Poseidon2}};");
	println!();

	// Print internal constants as static Lazy<Vec<Goldilocks>>
	println!("/// Pre-computed internal round constants for Poseidon2 with WIDTH=12");
	println!("static POSEIDON2_INTERNAL_CONSTANTS_12: Lazy<Vec<Goldilocks>> = Lazy::new(|| {{");
	println!("\tvec![");
	for constant in internal_constants.iter() {
		println!("\t\tGoldilocks::from_int(0x{:016x}u64),", constant.as_canonical_u64());
	}
	println!("\t]");
	println!("}});");
	println!();

	// Print initial external constants as static Lazy<Vec<[Goldilocks; 12]>>
	println!("/// Pre-computed initial external round constants for Poseidon2 with WIDTH=12");
	println!("static POSEIDON2_INITIAL_EXTERNAL_CONSTANTS_12: Lazy<Vec<[Goldilocks; 12]>> = Lazy::new(|| {{");
	println!("\tvec![");
	for round_constants in initial_constants.iter() {
		println!("\t\t[");
		for constant in round_constants.iter() {
			println!("\t\t\tGoldilocks::from_int(0x{:016x}u64),", constant.as_canonical_u64());
		}
		println!("\t\t],");
	}
	println!("\t]");
	println!("}});");
	println!();

	// Print terminal external constants as static Lazy<Vec<[Goldilocks; 12]>>
	println!("/// Pre-computed terminal external round constants for Poseidon2 with WIDTH=12");
	println!("static POSEIDON2_TERMINAL_EXTERNAL_CONSTANTS_12: Lazy<Vec<[Goldilocks; 12]>> = Lazy::new(|| {{");
	println!("\tvec![");
	for round_constants in terminal_constants.iter() {
		println!("\t\t[");
		for constant in round_constants.iter() {
			println!("\t\t\tGoldilocks::from_int(0x{:016x}u64),", constant.as_canonical_u64());
		}
		println!("\t\t],");
	}
	println!("\t]");
	println!("}});");
	println!();

	// Print helper function to create the optimized Poseidon2
	println!("/// Create a Poseidon2 instance using precomputed constants");
	println!("///");
	println!("/// This is significantly faster than `Poseidon2Core::new()` since it avoids");
	println!("/// the expensive constant derivation process and runtime conversions.");
	println!("/// The constants are computed only once and stored in the exact format needed.");
	println!("pub fn create_optimized_poseidon2() -> Poseidon2Goldilocks<12> {{");
	println!("\tlet internal_constants = POSEIDON2_INTERNAL_CONSTANTS_12.clone();");
	println!("\tlet initial_constants = POSEIDON2_INITIAL_EXTERNAL_CONSTANTS_12.clone();");
	println!("\tlet terminal_constants = POSEIDON2_TERMINAL_EXTERNAL_CONSTANTS_12.clone();");
	println!();
	println!("\tlet external_constants = ExternalLayerConstants::new(initial_constants, terminal_constants);");
	println!("\tPoseidon2::new(external_constants, internal_constants)");
	println!("}}");
	println!();

	// Print validation test
	println!("#[cfg(test)]");
	println!("mod tests {{");
	println!("\tuse super::*;");
	println!("\tuse p3_field::PrimeCharacteristicRing;");
	println!("\tuse p3_symmetric::Permutation;");
	println!("\tuse rand_chacha::{{rand_core::SeedableRng, ChaCha20Rng}};");
	println!();
	println!("\tconst POSEIDON2_SEED: u64 = 0x{:016x};", POSEIDON2_SEED);
	println!();
	println!("\t#[test]");
	println!("\tfn test_hardcoded_matches_derived() {{");
	println!("\t\tlet mut rng = ChaCha20Rng::seed_from_u64(POSEIDON2_SEED);");
	println!("\t\tlet original = Poseidon2Goldilocks::<12>::new_from_rng_128(&mut rng);");
	println!("\t\tlet optimized = create_optimized_poseidon2();");
	println!();
	println!("\t\t// Test with zero input");
	println!("\t\tlet mut state1 = [Goldilocks::ZERO; 12];");
	println!("\t\tlet mut state2 = [Goldilocks::ZERO; 12];");
	println!();
	println!("\t\toriginal.permute_mut(&mut state1);");
	println!("\t\toptimized.permute_mut(&mut state2);");
	println!();
	println!("\t\tassert_eq!(state1, state2, \"Zero input test failed\");");
	println!();
	println!("\t\t// Test with sequential input");
	println!("\t\tlet test_input: [Goldilocks; 12] =");
	println!("\t\t\tcore::array::from_fn(|i| Goldilocks::from_int(i as u64 + 1));");
	println!();
	println!("\t\tlet mut state1 = test_input;");
	println!("\t\tlet mut state2 = test_input;");
	println!();
	println!("\t\toriginal.permute_mut(&mut state1);");
	println!("\t\toptimized.permute_mut(&mut state2);");
	println!();
	println!("\t\tassert_eq!(state1, state2, \"Sequential input test failed\");");
	println!("\t}}");
	println!();
	println!("\t#[test]");
	println!("\tfn test_multiple_permutations() {{");
	println!("\t\tlet optimized = create_optimized_poseidon2();");
	println!();
	println!("\t\t// Test multiple permutations to ensure consistency");
	println!("\t\tlet test_inputs = [");
	println!("\t\t\t[Goldilocks::ZERO; 12],");
	println!("\t\t\tcore::array::from_fn(|i| Goldilocks::from_int(i as u64)),");
	println!("\t\t\tcore::array::from_fn(|i| Goldilocks::from_int((i * i) as u64)),");
	println!("\t\t];");
	println!();
	println!("\t\tfor input in test_inputs {{");
	println!("\t\t\tlet mut state1 = input;");
	println!("\t\t\tlet mut state2 = input;");
	println!();
	println!("\t\t\t// Apply the same permutation twice - should be deterministic");
	println!("\t\t\toptimized.permute_mut(&mut state1);");
	println!("\t\t\toptimized.permute_mut(&mut state2);");
	println!();
	println!("\t\t\tassert_eq!(state1, state2, \"Permutation should be deterministic\");");
	println!("\t\t}}");
	println!("\t}}");
	println!("}}");
}
