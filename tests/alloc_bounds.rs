//! Regression tests for audit finding #96388 "Unbounded byte-hash allocation".
//!
//! The public byte-hashing entrypoints (`hash_bytes`, `hash_squeeze_twice`) must not
//! materialize heap buffers proportional to the input size before absorbing: the
//! sponge can absorb incrementally, so byte hashing should use O(1) extra heap.

use qp_poseidon_core::{hash_bytes, hash_squeeze_twice, hash_to_bytes};
use qp_poseidon_core::serialization::bytes_to_felts;
use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::Mutex;

struct TrackingAllocator;

static CURRENT_ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static PEAK_ALLOCATED: AtomicUsize = AtomicUsize::new(0);

#[global_allocator]
static GLOBAL_ALLOCATOR: TrackingAllocator = TrackingAllocator;

// Serializes entire test bodies: allocations from a concurrently running test would
// otherwise pollute the peak counter.
static MEASURE_LOCK: Mutex<()> = Mutex::new(());

#[inline]
fn record_alloc(size: usize) {
	let new_total = CURRENT_ALLOCATED.fetch_add(size, SeqCst) + size;
	PEAK_ALLOCATED.fetch_max(new_total, SeqCst);
}

#[inline]
fn record_dealloc(size: usize) {
	CURRENT_ALLOCATED.fetch_sub(size, SeqCst);
}

unsafe impl GlobalAlloc for TrackingAllocator {
	unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
		let ptr = System.alloc(layout);
		if !ptr.is_null() {
			record_alloc(layout.size());
		}
		ptr
	}

	unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
		let ptr = System.alloc_zeroed(layout);
		if !ptr.is_null() {
			record_alloc(layout.size());
		}
		ptr
	}

	unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
		record_dealloc(layout.size());
		System.dealloc(ptr, layout);
	}

	unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
		let new_ptr = System.realloc(ptr, layout, new_size);
		if !new_ptr.is_null() {
			if new_size >= layout.size() {
				record_alloc(new_size - layout.size());
			} else {
				record_dealloc(layout.size() - new_size);
			}
		}
		new_ptr
	}
}

/// Runs `f` and returns its result plus the peak heap growth (in bytes) observed while it ran.
/// Caller must hold `MEASURE_LOCK`.
fn measure_peak_delta<T>(f: impl FnOnce() -> T) -> (T, usize) {
	let baseline = CURRENT_ALLOCATED.load(SeqCst);
	PEAK_ALLOCATED.store(baseline, SeqCst);
	let result = f();
	let peak = PEAK_ALLOCATED.load(SeqCst);
	(result, peak.saturating_sub(baseline))
}

const INPUT_LEN: usize = 256 * 1024;

/// Generous O(1) budget: streaming absorption needs no proportional heap at all,
/// but allow a small constant for incidental allocations.
const CONSTANT_HEAP_BUDGET: usize = 4096;

#[test]
fn hash_bytes_uses_constant_heap() {
	let _guard = MEASURE_LOCK.lock().unwrap();
	let input = vec![0x41u8; INPUT_LEN];

	// The digest must stay identical to the felt-path reference.
	let expected_digest = hash_to_bytes(&bytes_to_felts(&input));

	let (digest, peak) = measure_peak_delta(|| hash_bytes(black_box(&input)));

	assert_eq!(digest, expected_digest, "hash_bytes digest must not change");
	assert!(
		peak <= CONSTANT_HEAP_BUDGET,
		"hash_bytes should absorb bytes incrementally without materializing the \
		 serialized preimage; input was {INPUT_LEN} bytes but peak heap growth was {peak} bytes"
	);
}

#[test]
fn hash_squeeze_twice_uses_constant_heap() {
	let _guard = MEASURE_LOCK.lock().unwrap();
	let input = vec![0x24u8; INPUT_LEN];

	let (digest64, peak) = measure_peak_delta(|| hash_squeeze_twice(black_box(&input)));

	assert_eq!(digest64.len(), 64);
	assert!(
		peak <= CONSTANT_HEAP_BUDGET,
		"hash_squeeze_twice should absorb bytes incrementally without materializing the \
		 serialized preimage; input was {INPUT_LEN} bytes but peak heap growth was {peak} bytes"
	);
}
