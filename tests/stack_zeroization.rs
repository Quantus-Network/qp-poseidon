//! Regression test (security review): hash inputs and outputs must not
//! survive in dead stack memory after the hash call returns — consumers hash
//! secrets (e.g. Quantus wormhole secrets are `hash_bytes` outputs). The old
//! `self`-consuming finalize chain moved the sponge by value, leaving dead
//! unwipeable copies; the fixed pipeline finalizes in place and wipes.
//!
//! Technique: run the hash on a freshly painted stack buffer (`psm`), then
//! scan the buffer for the known pattern. The assertion is about codegen, so
//! it is only compiled for optimized builds (`cargo test --release`).
#![cfg(not(debug_assertions))]

use std::alloc::{alloc, dealloc, Layout};

use qp_poseidon_core::{hash_bytes, hash_twice, serialization::bytes_to_digest_lossy};

const PAINT: u8 = 0xAA;
// Poseidon2 hashing is shallow; 1 MiB is ample.
const STACK_BYTES: usize = 1024 * 1024;
const ALIGN: usize = 4096;

/// Run `f` on a freshly painted stack buffer, then scan the buffer for
/// `pattern` and return whether it was found.
fn probe_stack_for<F: FnOnce()>(pattern: &[u8], f: F) -> bool {
	let layout = Layout::from_size_align(STACK_BYTES, ALIGN).unwrap();
	unsafe {
		let base = alloc(layout);
		assert!(!base.is_null(), "probe stack allocation failed");
		std::ptr::write_bytes(base, PAINT, STACK_BYTES);

		psm::on_stack(base, STACK_BYTES, f);

		let region = std::slice::from_raw_parts(base, STACK_BYTES);
		let offsets: Vec<usize> = region
			.windows(pattern.len())
			.enumerate()
			.filter(|(_, w)| w == &pattern)
			.map(|(i, _)| i)
			.collect();
		eprintln!("probe: {} match(es) at offsets {:?}", offsets.len(), offsets);
		let found = !offsets.is_empty();
		dealloc(base, layout);
		found
	}
}

/// Distinctive ASCII input so matches can only come from verbatim copies.
const INPUT: [u8; 32] = *b"poseidon-probe-input-0123456789A";

#[test]
fn hash_bytes_output_never_survives_on_stack() {
	// Reference output, computed outside the probed region.
	let output = hash_bytes(&INPUT);

	// Sanity: the technique detects an unwiped copy.
	assert!(
		probe_stack_for(&output, || {
			let leaked: [u8; 32] = output;
			core::hint::black_box(&leaked);
		}),
		"probe self-check: a deliberately leaked output copy was not detected"
	);

	let leaked = probe_stack_for(&output, || {
		let mut out = hash_bytes(&INPUT);
		core::hint::black_box(&out);
		// Wipe the caller-owned copy (as a secret-holding caller would) so
		// the scan only sees copies the library left behind.
		out.fill(0);
		core::hint::black_box(&mut out);
	});
	assert!(
		!leaked,
		"hash_bytes left a copy of its output in dead stack memory; callers \
		 hashing secrets (e.g. wormhole secret derivation) cannot wipe it"
	);
}

#[test]
fn hash_twice_input_never_survives_on_stack() {
	// hash_twice is used for wormhole address derivation, where the *input*
	// felts encode the secret (8 bytes/felt, byte-identical to the secret for
	// canonical limbs). The input slice itself belongs to the caller; this
	// probes for sponge-internal copies of it.
	let felts = bytes_to_digest_lossy(&INPUT);
	let output = hash_twice(&felts);

	// The input pattern as it appears in felt form (LE u64 limbs).
	let mut input_pattern = [0u8; 32];
	for (chunk, felt) in input_pattern.chunks_exact_mut(8).zip(felts.iter()) {
		chunk.copy_from_slice(&felt.as_canonical_u64().to_le_bytes());
	}

	let leaked = probe_stack_for(&input_pattern, || {
		// `mut` from the start: rebinding later would move `felts`, leaving
		// the original slot as dead residue — the bug class this probe hunts.
		let mut felts = bytes_to_digest_lossy(&INPUT);
		let out = hash_twice(&felts);
		core::hint::black_box(&out);
		// Wipe the caller-owned copy so the scan only sees sponge-internal ones.
		felts.fill(qp_poseidon_core::Goldilocks::ZERO);
		core::hint::black_box(&mut felts);
	});
	assert!(
		!leaked,
		"hash_twice left a sponge-internal copy of its input in dead stack \
		 memory; wormhole secrets are absorbed through this path"
	);
	core::hint::black_box(&output);
}
