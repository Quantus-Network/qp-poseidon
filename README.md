# qp-poseidon

A Poseidon hash implementation for the Substrate/Polkadot ecosystem using plonky2 field arithmetic.

## Overview

This crate provides a Poseidon hash function implementation that integrates with Substrate's hashing traits and storage systems. It uses Goldilocks field arithmetic from plonky2 for efficient cryptographic operations.

## Features

- **Substrate Integration**: Implements `sp_core::Hasher` and `sp_runtime::traits::Hash` traits
- **Efficient Field Arithmetic**: Uses plonky2's Goldilocks field for optimal performance
- **Trie Support**: Compatible with Substrate's trie storage systems (V0 and V1 layouts)
- **No-std Support**: Can be used in no-std environments
- **Serde Support**: Optional serialization support

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
qp-poseidon = "0.0.1"
```

### Basic Hashing

```rust
use qp_poseidon::PoseidonHasher;
use sp_core::Hasher;

let data = b"hello world";
let hash = PoseidonHasher::hash(data);
println!("Hash: {:?}", hash);
```

### As Substrate Hash Function

```rust
use qp_poseidon::PoseidonHasher;
use sp_runtime::traits::Hash;

let data = b"substrate data";
let hash = PoseidonHasher::hash(data);
```

### Field Element Operations

```rust
use qp_poseidon::{injective_bytes_to_felts, PoseidonHasher};

let data = b"some data";
let field_elements = injective_bytes_to_felts(data);
let hash = PoseidonHasher::hash_no_pad(field_elements);
```

## Features

- `std` (default): Enables standard library support
- `serde`: Enables serialization support for types

## License

This project is licensed under the MIT-0 License.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
