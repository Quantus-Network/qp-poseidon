# qp-poseidon-core

A pure Rust implementation of the Poseidon hash function using plonky3 field arithmetic. This crate provides the core cryptographic functionality without any external dependencies beyond plonky3.

## Features

- **No-std compatible**: Works in embedded and constrained environments
- **Pure cryptography**: No blockchain or external dependencies
- **Circuit-compatible**: Padding behavior matches zero-knowledge circuit implementations
- **Field arithmetic**: Built on battle-tested plonky3 Goldilocks field

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
use plonky3::field::goldilocks_field::GoldilocksField;

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

### Constants

- `MIN_FIELD_ELEMENT_PREIMAGE_LEN: usize = 190` - Minimum field elements for circuit-compatible padding

### Padding Behavior

- **Padded functions**: Automatically pad input to `MIN_FIELD_ELEMENT_PREIMAGE_LEN` field elements
- **Unpadded functions**: Hash input as-is without modification
- **Field element conversion**: Uses injective mapping to preserve input uniqueness

## Performance

- Optimized for deterministic behavior across platforms
- Memory efficient for constrained environments
- Uses plonky3's optimized field arithmetic
- No heap allocations in core hashing (only in utility functions)

## Security

- Built on battle-tested plonky3 field arithmetic
- Implements standard Poseidon permutation
- Circuit-compatible padding prevents length extension attacks
- Extensive test coverage with known test vectors

## Related Crates

- [`qp-poseidon`](../substrate) - Substrate-compatible wrapper around this core implementation
- [`plonky3`](https://github.com/0xPolygonZero/plonky3) - The underlying field arithmetic and Poseidon implementation
