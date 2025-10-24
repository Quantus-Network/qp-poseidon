use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use p3_field::integers::QuotientMap;
use p3_goldilocks::Goldilocks;
use qp_poseidon_core::{serialization::injective_bytes_to_felts, Poseidon2Core};

/// Generate test data of varying sizes for benchmarking
fn generate_test_data(size: usize) -> Vec<u8> {
	(0..size).map(|i| (i * 123 % 256) as u8).collect()
}

/// Generate test field elements for benchmarking
fn generate_test_felts(count: usize) -> Vec<Goldilocks> {
	(0..count)
		.map(|i| Goldilocks::from_int((i * 456) as u64 % (1u64 << 32)))
		.collect()
}

/// Benchmark just the hashing performance with a pre-initialized Poseidon2Core
fn bench_hash_only(c: &mut Criterion) {
	let mut group = c.benchmark_group("hash_only");

	// Pre-initialize the hasher once
	let hasher = Poseidon2Core::new();

	// Test different input sizes (in bytes)
	let sizes = [32, 64, 128, 256, 512, 1024, 2048, 4096, 8192];

	for &size in &sizes {
		let data = generate_test_data(size);

		group.throughput(Throughput::Bytes(size as u64));
		group.bench_with_input(BenchmarkId::new("hash_padded_bytes", size), &data, |b, data| {
			b.iter(|| {
				let result = hasher.hash_padded_bytes::<189>(black_box(data));
				black_box(result)
			})
		});

		group.bench_with_input(
			BenchmarkId::new("hash_variable_length_bytes", size),
			&data,
			|b, data| {
				b.iter(|| {
					let result = hasher.hash_variable_length_bytes(black_box(data));
					black_box(result)
				})
			},
		);
	}

	// Test hashing field elements directly
	let felt_counts = [4, 8, 16, 32, 64, 128, 256];
	for &count in &felt_counts {
		let felts = generate_test_felts(count);

		group.throughput(Throughput::Elements(count as u64));
		group.bench_with_input(BenchmarkId::new("hash_padded_felts", count), &felts, |b, felts| {
			b.iter(|| {
				let result = hasher.hash_variable_length(black_box(felts.clone()));
				black_box(result)
			})
		});

		group.bench_with_input(
			BenchmarkId::new("hash_variable_length_felts", count),
			&felts,
			|b, felts| {
				b.iter(|| {
					let result = hasher.hash_variable_length(black_box(felts.clone()));
					black_box(result)
				})
			},
		);
	}

	group.finish();
}

/// Benchmark the complete workflow: create new Poseidon2Core + hash data
fn bench_create_and_hash(c: &mut Criterion) {
	let mut group = c.benchmark_group("create_and_hash");

	// Test different input sizes (in bytes)
	let sizes = [32, 64, 128, 256, 512, 1024, 2048, 4096];

	for &size in &sizes {
		let data = generate_test_data(size);

		group.throughput(Throughput::Bytes(size as u64));
		group.bench_with_input(
			BenchmarkId::new("new_and_hash_padded_bytes", size),
			&data,
			|b, data| {
				b.iter(|| {
					let hasher = Poseidon2Core::new();
					let result = hasher.hash_padded_bytes::<189>(black_box(data));
					black_box(result)
				})
			},
		);

		group.bench_with_input(
			BenchmarkId::new("new_and_hash_variable_length_bytes", size),
			&data,
			|b, data| {
				b.iter(|| {
					let hasher = Poseidon2Core::new();
					let result = hasher.hash_variable_length_bytes(black_box(data));
					black_box(result)
				})
			},
		);
	}

	// Test with field elements
	let felt_counts = [4, 8, 16, 32, 64, 128];
	for &count in &felt_counts {
		let felts = generate_test_felts(count);

		group.throughput(Throughput::Elements(count as u64));
		group.bench_with_input(
			BenchmarkId::new("new_and_hash_padded_felts", count),
			&felts,
			|b, felts| {
				b.iter(|| {
					let hasher = Poseidon2Core::new();
					let result = hasher.hash_variable_length(black_box(felts.clone()));
					black_box(result)
				})
			},
		);

		group.bench_with_input(
			BenchmarkId::new("new_and_hash_variable_length_felts", count),
			&felts,
			|b, felts| {
				b.iter(|| {
					let hasher = Poseidon2Core::new();
					let result = hasher.hash_variable_length(black_box(felts.clone()));
					black_box(result)
				})
			},
		);
	}

	group.finish();
}

/// Benchmark just the initialization cost
fn bench_initialization(c: &mut Criterion) {
	let mut group = c.benchmark_group("initialization");

	group.bench_function("new_poseidon2core", |b| {
		b.iter(|| {
			let hasher = Poseidon2Core::new();
			black_box(hasher)
		})
	});

	group.bench_function("new_with_seed", |b| {
		b.iter(|| {
			let hasher = Poseidon2Core::with_seed(black_box(12345));
			black_box(hasher)
		})
	});

	group.bench_function("new_unoptimized", |b| {
		b.iter(|| {
			let hasher = Poseidon2Core::new_unoptimized();
			black_box(hasher)
		})
	});

	group.finish();
}

/// Benchmark 512-bit hash functions
fn bench_hash_squeeze_twice(c: &mut Criterion) {
	let mut group = c.benchmark_group("hash_squeeze_twice");
	let hasher = Poseidon2Core::new();

	let sizes = [32, 64, 128, 256, 512, 1024];

	for &size in &sizes {
		let data = generate_test_data(size);

		group.throughput(Throughput::Bytes(size as u64));
		group.bench_with_input(BenchmarkId::new("hash_squeeze_twice", size), &data, |b, data| {
			b.iter(|| {
				let result = hasher.hash_squeeze_twice(black_box(data));
				black_box(result)
			})
		});
	}

	group.finish();
}

/// Benchmark utility functions
fn bench_utility_functions(c: &mut Criterion) {
	let mut group = c.benchmark_group("utility_functions");

	// Benchmark byte to field element conversion
	let sizes = [32, 64, 128, 256, 512, 1024];

	for &size in &sizes {
		let data = generate_test_data(size);

		group.throughput(Throughput::Bytes(size as u64));
		group.bench_with_input(
			BenchmarkId::new("injective_bytes_to_felts", size),
			&data,
			|b, data| {
				b.iter(|| {
					let result = injective_bytes_to_felts::<Goldilocks>(black_box(data));
					black_box(result)
				})
			},
		);
	}

	group.finish();
}

/// Comparative benchmark showing initialization overhead
fn bench_initialization_overhead(c: &mut Criterion) {
	let mut group = c.benchmark_group("initialization_overhead");

	// Use a medium-sized input for comparison
	let data = generate_test_data(256);
	let pre_initialized = Poseidon2Core::new();

	group.bench_function("hash_with_existing_instance", |b| {
		b.iter(|| {
			let result = pre_initialized.hash_padded_bytes::<189>(black_box(&data));
			black_box(result)
		})
	});

	group.bench_function("hash_with_new_unoptimized_instance", |b| {
		b.iter(|| {
			let hasher = Poseidon2Core::new_unoptimized();
			let result = hasher.hash_padded_bytes::<189>(black_box(&data));
			black_box(result)
		})
	});

	group.bench_function("hash_with_new_optimized_instance", |b| {
		b.iter(|| {
			let hasher = Poseidon2Core::new();
			let result = hasher.hash_padded_bytes::<189>(black_box(&data));
			black_box(result)
		})
	});

	group.finish();
}

/// Benchmark comparing optimized vs original initialization
fn bench_optimized_vs_original(c: &mut Criterion) {
	let mut group = c.benchmark_group("optimized_vs_original");

	// Benchmark initialization only
	group.bench_function("init_original", |b| {
		b.iter(|| {
			let hasher = Poseidon2Core::new_unoptimized();
			black_box(hasher)
		})
	});

	group.bench_function("init_optimized", |b| {
		b.iter(|| {
			let hasher = Poseidon2Core::new();
			black_box(hasher)
		})
	});

	// Benchmark init + hash for small data (where init cost matters most)
	let small_data = generate_test_data(32);

	group.bench_function("init_and_hash_original_32b", |b| {
		b.iter(|| {
			let hasher = Poseidon2Core::new_unoptimized();
			let result = hasher.hash_padded_bytes::<189>(black_box(&small_data));
			black_box(result)
		})
	});

	group.bench_function("init_and_hash_optimized_32b", |b| {
		b.iter(|| {
			let hasher = Poseidon2Core::new();
			let result = hasher.hash_padded_bytes::<189>(black_box(&small_data));
			black_box(result)
		})
	});

	// Benchmark with medium data
	let medium_data = generate_test_data(256);

	group.bench_function("init_and_hash_original_256b", |b| {
		b.iter(|| {
			let hasher = Poseidon2Core::new_unoptimized();
			let result = hasher.hash_padded_bytes::<189>(black_box(&medium_data));
			black_box(result)
		})
	});

	group.bench_function("init_and_hash_optimized_256b", |b| {
		b.iter(|| {
			let hasher = Poseidon2Core::new();
			let result = hasher.hash_padded_bytes::<189>(black_box(&medium_data));
			black_box(result)
		})
	});

	group.finish();
}

criterion_group!(
	benches,
	bench_hash_only,
	bench_create_and_hash,
	bench_initialization,
	bench_hash_squeeze_twice,
	bench_utility_functions,
	bench_initialization_overhead,
	bench_optimized_vs_original
);

criterion_main!(benches);
