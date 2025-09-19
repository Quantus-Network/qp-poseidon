# qp-poseidon-core

A pure Rust implementation of the Poseidon hash function using plonky2 field arithmetic. This crate provides the core cryptographic functionality without any external dependencies beyond plonky2.

## Features

- **No-std compatible**: Works in embedded and constrained environments
- **Pure cryptography**: No blockchain or external dependencies
- **Circuit-compatible**: Padding behavior matches zero-knowledge circuit implementations
- **Flexible**: Support for both padded and unpadded hashing
- **Field arithmetic**: Built on battle-tested plonky2 Goldilocks field

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
qp-poseidon-core = { path = "path/to/qp-poseidon/crates/core" }
```

### Basic Usage

```rust
use qp_poseidon_core::PoseidonCore;

// Hash some bytes with padding (recommended for circuit compatibility)
let data = b"hello world";
let hash = PoseidonCore::hash_padded(data);
println!("Hash: {:?}", hash);

// Hash without padding
let hash_no_pad = PoseidonCore::hash_no_pad_bytes(data);
```

### Working with Field Elements

```rust
use qp_poseidon_core::{PoseidonCore, injective_bytes_to_felts};
use plonky2::field::goldilocks_field::GoldilocksField;

// Convert bytes to field elements
let data = b"test data";
let felts = injective_bytes_to_felts(data);

// Hash field elements directly
let hash = PoseidonCore::hash_padded_felts(felts);
```

### Utility Functions

The crate provides several utility functions for converting between different data types and field elements:

```rust
use qp_poseidon_core::{u64_to_felts, u128_to_felts, injective_string_to_felts};

// Convert numbers to field elements
let num_felts = u64_to_felts(12345);
let large_num_felts = u128_to_felts(123456789012345);

// Convert strings to field elements (max 8 bytes)
let string_felts = injective_string_to_felts("hello");
```

## API Reference

### Core Functions

- `PoseidonCore::hash_padded(data: &[u8]) -> Vec<u8>` - Hash bytes with circuit-compatible padding
- `PoseidonCore::hash_padded_felts(felts: Vec<GoldilocksField>) -> Vec<u8>` - Hash field elements with padding
- `PoseidonCore::hash_no_pad(felts: Vec<GoldilocksField>) -> Vec<u8>` - Hash field elements without padding
- `PoseidonCore::hash_no_pad_bytes(data: &[u8]) -> Vec<u8>` - Hash bytes without padding

### Utility Functions

- `injective_bytes_to_felts(input: &[u8]) -> Vec<GoldilocksField>` - Convert bytes to field elements (4 bytes per element)
- `injective_felts_to_bytes(input: &[GoldilocksField]) -> Vec<u8>` - Convert field elements back to bytes
- `digest_bytes_to_felts(input: &[u8]) -> Vec<GoldilocksField>` - Convert bytes to field elements (8 bytes per element)
- `digest_felts_to_bytes(input: &[GoldilocksField]) -> Vec<u8>` - Convert digest field elements to bytes
- `u64_to_felts(num: u64) -> Vec<GoldilocksField>` - Convert u64 to field elements using 32-bit limbs
- `u128_to_felts(num: u128) -> Vec<GoldilocksField>` - Convert u128 to field elements using 32-bit limbs
- `injective_string_to_felts(input: &str) -> Vec<GoldilocksField>` - Convert string to field elements (up to 8 bytes)

### Constants

- `MIN_FIELD_ELEMENT_PREIMAGE_LEN: usize = 188` - Minimum field elements for circuit-compatible padding

## No-std Support

This crate is `no_std` compatible and uses `alloc` for dynamic allocations. To use in a no-std environment:

```toml
[dependencies]
qp-poseidon-core = { path = "path/to/crate", default-features = false }
```

## Circuit Compatibility

The padded hash functions are designed to match the behavior of zero-knowledge circuit implementations. The minimum field element preimage length is 188 elements to ensure consistent hashes between native and circuit code.

### Padding Behavior

- **Padded functions**: Automatically pad input to `MIN_FIELD_ELEMENT_PREIMAGE_LEN` field elements
- **Unpadded functions**: Hash input as-is without modification
- **Field element conversion**: Uses injective mapping to preserve input uniqueness

## Performance

- Optimized for deterministic behavior across platforms
- Memory efficient for constrained environments  
- Uses plonky2's optimized field arithmetic
- No heap allocations in core hashing (only in utility functions)

## Security

- Built on battle-tested plonky2 field arithmetic
- Implements standard Poseidon permutation
- Circuit-compatible padding prevents length extension attacks
- Extensive test coverage with known test vectors

## Testing

```bash
# Run tests
cargo test

# Test with no-std
cargo test --no-default-features
```

## Features

- `default`: Includes `std` feature
- `std`: Enables standard library features (mainly for testing)

## Examples

### Round-trip Conversion

```rust
use qp_poseidon_core::{injective_bytes_to_felts, injective_felts_to_bytes};

let original = b"test data";
let felts = injective_bytes_to_felts(original);
let recovered = injective_felts_to_bytes(&felts);

assert_eq!(&recovered[..original.len()], original);
```

### Comparing Padded vs Unpadded

```rust
use qp_poseidon_core::PoseidonCore;

let data = b"test";
let padded_hash = PoseidonCore::hash_padded(data);
let unpadded_hash = PoseidonCore::hash_no_pad_bytes(data);

// These will be different due to padding
assert_ne!(padded_hash, unpadded_hash);
```

## License

MIT-0

## Contributing

Contributions are welcome! Please ensure all tests pass and follow the existing code style.

## Related Crates

- [`qp-poseidon`](../substrate) - Substrate-compatible wrapper around this core implementation
- [`plonky2`](https://github.com/0xPolygonZero/plonky2) - The underlying field arithmetic and Poseidon implementation