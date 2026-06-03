use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use qp_poseidon_core::{
	hash_bytes, hash_squeeze_twice, hash_to_bytes, serialization::bytes_to_felts, Goldilocks,
	Poseidon2,
};

/// Generate test data of varying sizes for benchmarking
fn generate_test_data(size: usize) -> Vec<u8> {
	(0..size).map(|i| (i * 123 % 256) as u8).collect()
}

/// Generate test field elements for benchmarking
fn generate_test_felts(count: usize) -> Vec<Goldilocks> {
	(0..count)
		.map(|i| Goldilocks::from_u64((i * 456) as u64 % (1u64 << 32)))
		.collect()
}

/// Benchmark just the hashing performance with a pre-initialized Poseidon2Core
fn bench_hash_only(c: &mut Criterion) {
	let mut group = c.benchmark_group("hash_only");

	// Test different input sizes (in bytes)
	let sizes = [32, 64, 128, 256, 512, 1024, 2048, 4096, 8192];

	for &size in &sizes {
		let data = generate_test_data(size);

		group.throughput(Throughput::Bytes(size as u64));

		group.bench_with_input(BenchmarkId::new("hash_bytes", size), &data, |b, data| {
			b.iter(|| {
				let result = hash_bytes(black_box(data));
				black_box(result)
			})
		});
	}

	// Test hashing field elements directly
	let felt_counts = [4, 8, 16, 32, 64, 128, 256];
	for &count in &felt_counts {
		let felts = generate_test_felts(count);

		group.throughput(Throughput::Elements(count as u64));
		group.bench_with_input(
			BenchmarkId::new("hash_to_bytes_felts", count),
			&felts,
			|b, felts| {
				b.iter(|| {
					let result = hash_to_bytes(black_box(felts));
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

		group.bench_with_input(BenchmarkId::new("new_and_hash_bytes", size), &data, |b, data| {
			b.iter(|| {
				let result = hash_bytes(black_box(data));
				black_box(result)
			})
		});
	}

	// Test with field elements
	let felt_counts = [4, 8, 16, 32, 64, 128];
	for &count in &felt_counts {
		let felts = generate_test_felts(count);

		group.throughput(Throughput::Elements(count as u64));
		group.bench_with_input(
			BenchmarkId::new("new_and_hash_to_bytes_felts", count),
			&felts,
			|b, felts| {
				b.iter(|| {
					let result = hash_to_bytes(black_box(felts));
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

	group.bench_function("create_poseidon", |b| {
		b.iter(|| {
			let hasher = Poseidon2::new();
			black_box(hasher)
		})
	});

	group.finish();
}

/// Benchmark 512-bit hash functions
fn bench_hash_squeeze_twice(c: &mut Criterion) {
	let mut group = c.benchmark_group("hash_squeeze_twice");

	let sizes = [32, 64, 128, 256, 512, 1024];

	for &size in &sizes {
		let data = generate_test_data(size);

		group.throughput(Throughput::Bytes(size as u64));
		group.bench_with_input(BenchmarkId::new("hash_squeeze_twice", size), &data, |b, data| {
			b.iter(|| {
				let result = hash_squeeze_twice(black_box(data));
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
		group.bench_with_input(BenchmarkId::new("bytes_to_felts", size), &data, |b, data| {
			b.iter(|| {
				let result = bytes_to_felts(black_box(data));
				black_box(result)
			})
		});
	}

	group.finish();
}

criterion_group!(
	benches,
	bench_hash_only,
	bench_create_and_hash,
	bench_initialization,
	bench_hash_squeeze_twice,
	bench_utility_functions,
);

criterion_main!(benches);
