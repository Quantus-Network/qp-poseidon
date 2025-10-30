# Constant-Time Testing for qp-poseidon

This project uses [dudect-bencher](https://github.com/rozbb/dudect-bencher) to test whether the Poseidon2 hash functions execute in constant time, preventing timing side-channel attacks.

## Quick Start

Run all constant-time tests:

```bash
cd core
cargo run --release --features ct-testing --bin ct_bench
```

## Understanding Results

Each test shows output like:
```
bench test_hash_padded_bytes_ct ... : n == +0.001M, max t = +2.26642, max tau = +0.09339, (5/tau)^2 = 2866
```

- **max t** is the raw t-statistic
- **max tau** is the t-statistic adjusted for sample size (more reliable for large `n`)
- **(5/tau)^2**: Higher numbers are BETTER - shows how many measurements needed to reach danger threshold

## Tests Included

- `test_hash_padded_bytes_ct` - Padded hashing with 16 bytes to 5KB inputs
- `test_hash_variable_length_bytes_ct` - Variable-length byte hashing (8 bytes to 5KB)
- `test_poseidon2_permutation_ct` - Core Poseidon2 permutation
- `test_hash_squeeze_twice_ct` - 512-bit output hashing (12 bytes to 4KB)
- `test_field_absorption_ct` - Byte to field element conversion (4 bytes to 2KB)
- `test_double_hash_ct` - Double hashing operations (8 bytes to 3KB)
- `test_edge_cases_ct` - Single-byte edge cases
- `test_integrated_operations_ct` - Multiple operations combined (32 bytes to 5KB)
- `test_hash_variable_length_felts_ct` - Field element hashing (5-650 elements)

## Tips

- Always use `--release` for accurate timing
- Close other applications during testing
- Variable-length inputs (up to 5KB) help detect length-dependent timing issues
- max tau more useful stat for many runs
