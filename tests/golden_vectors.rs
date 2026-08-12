//! Golden value tests for the Poseidon2 hash (mining path).
//!
//! Captured from qp-poseidon-core v3.1.0 (commit f885ad5, pre-optimization).
//! Any performance work must reproduce these byte-for-byte.
//!
//! Input layout mirrors CPU mining: 32-byte header || 64-byte big-endian U512
//! nonce = 96 bytes, hashed with `hash_squeeze_twice` (as `get_nonce_hash` does).

use qp_poseidon_core::hash_squeeze_twice;

fn mining_input(header_seed: u8, nonce: u64) -> [u8; 96] {
	let mut input = [0u8; 96];
	for b in input[..32].iter_mut() {
		*b = header_seed;
	}
	// U512 big-endian nonce occupies the last 64 bytes; value sits in the low 8.
	input[88..96].copy_from_slice(&nonce.to_be_bytes());
	input
}

const GOLDEN: &[(&str, u8, u64, &str)] = &[
	(
		"zero header, nonce 0",
		0x00,
		0,
		"8e64e3d8e0f38f882e8501f9e525df0a95d2e91e9cfc32c9248d756fb07780e2f8fdca2c5a54441e6fcd8d774a5f6aae72f36d1c76bc19f691a0d4f6c607e8cc",
	),
	(
		"zero header, nonce 1",
		0x00,
		1,
		"9a18eabb9d910135a553a511209963dfafd2dc62989e2e013c18d626fa17c66fd3899fc3fe2bcc88be8ce416a4bd15e9f157cc5b251112f93938b38617548f6c",
	),
	(
		"0x01 header, nonce 123",
		0x01,
		123,
		"0c580156318afca56700b7a2cafa4f44277a6c7ea668717984ed26b8169d277521951b73329d898590e953c35d036726becb74bc29d765112ec99b14d0dc5189",
	),
	(
		"0xff header, nonce u64::MAX",
		0xff,
		u64::MAX,
		"822f70999ee517f610b51bbb79ba88bfbb19cb77b316df25d8aeb4c2682673555e9fc6a588ee96dcce4ff0d2b8d97f4aa89d0f46c97f9027b386d42b14be5100",
	),
	(
		"0x2a header, nonce 0xdeadbeef",
		0x2a,
		0xdeadbeef,
		"f974a312ffd7b21ba3e71c499cf178e39d19d178b4483da321da23c48c02e7c874561d93d6e590656905c21a0142a512fe1ebbf69babc904fe1c359f72e5420c",
	),
];

#[test]
fn test_mining_golden_vectors() {
	for (name, seed, nonce, expected_hex) in GOLDEN {
		let input = mining_input(*seed, *nonce);
		let out = hash_squeeze_twice(&input);
		assert_eq!(hex::encode(out), *expected_hex, "golden mismatch for {name}");
	}
}
