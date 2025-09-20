# qp-poseidon

A workspace containing Poseidon hash implementations for different use cases, built on top of plonky2 field arithmetic.

## 📁 Workspace Structure

This workspace contains two crates:

### `qp-poseidon-core` (`crates/core`)
Pure Rust implementation of the Poseidon hash function without any external dependencies beyond plonky2.

- **No-std compatible**: Works in embedded and constrained environments
- **Pure cryptography**: No blockchain or Substrate-specific dependencies
- **Circuit-compatible**: Padding behavior matches zero-knowledge circuit implementations
- **Flexible**: Support for both padded and unpadded hashing

### `qp-poseidon` (`crates/substrate`) 
Substrate-compatible wrapper that adds codec traits and blockchain-specific functionality.

- **Substrate integration**: Implements required traits for use in Substrate/Polkadot projects
- **Codec support**: Implements `Encode`, `Decode`, and `TypeInfo` traits
- **Serde support**: Optional serialization support
- **Storage hashing**: Specialized functions for Quantus storage operations

## 🚀 Quick Start

### For Pure Cryptographic Use (No Substrate)

Add to your `Cargo.toml`:

```toml
[dependencies]
qp-poseidon-core = { path = "crates/core" }
```

Example usage:

```rust
use qp_poseidon_core::PoseidonCore;

// Hash some bytes with circuit-compatible padding
let data = b"hello world";
let hash = PoseidonCore::hash_padded(data);
println!("Hash: {:?}", hash);

// Hash without padding
let hash_no_pad = PoseidonCore::hash_no_pad_bytes(data);
```

### For Substrate/Polkadot Projects

Add to your `Cargo.toml`:

```toml
[dependencies]
qp-poseidon = { path = "crates/substrate" }
```

Example usage:

```rust
use qp_poseidon::PoseidonHasher;
use codec::{Encode, Decode};

// Hash with Substrate compatibility
let data = b"hello world";
let hash = PoseidonHasher::hash_padded(data);

// The hasher implements all required Substrate traits
#[derive(Encode, Decode)]
struct MyData {
    value: u32,
}

let my_data = MyData { value: 42 };
let encoded = my_data.encode();
let hash = PoseidonHasher::hash_padded(&encoded);
```

## 🔧 Features

### Core Features
- **Padded hashing**: Ensures compatibility with zero-knowledge circuits
- **Field element conversion**: Utilities for converting between bytes and Goldilocks field elements
- **Multiple data types**: Support for u64, u128, strings, and arbitrary byte arrays
- **Deterministic**: Same input always produces the same output

### Substrate Features
- **Codec integration**: Implements `Encode`/`Decode` traits
- **Type information**: Provides `TypeInfo` for metadata
- **Optional serde**: Enable with `serde` feature
- **Storage hashing**: Specialized functions for blockchain storage

## 🧪 Testing

Run tests for all crates:

```bash
cargo test
```

Run tests for specific crate:

```bash
cargo test -p qp-poseidon-core
cargo test -p qp-poseidon
```

## 📊 Performance

The implementation is optimized for:
- Circuit compatibility (consistent padding)
- No-std environments
- Deterministic behavior across platforms
- Memory efficiency in constrained environments

## 🔒 Security

- Uses battle-tested plonky2 field arithmetic
- Implements the standard Poseidon permutation
- Circuit-compatible padding prevents length extension attacks
- Extensive test coverage with known test vectors

## 🏗️ Development

### Building

```bash
# Check all crates
cargo check

# Build with all features
cargo build --all-features

# Build for no-std
cargo build --no-default-features
```

### Features

#### Core Crate Features
- `default`: Includes `std` feature
- `std`: Enables standard library features

#### Substrate Crate Features
- `default`: Includes `std` feature  
- `std`: Enables standard library features
- `serde`: Enables serde serialization support

## 📄 License

MIT-0

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Ensure all tests pass
6. Submit a pull request

## 🔗 Related Projects

- [plonky2](https://github.com/0xPolygonZero/plonky2) - The underlying field arithmetic library
- [Substrate](https://substrate.io/) - Framework for building blockchains

## 📚 Examples

### Working with Field Elements

```rust
use qp_poseidon_core::{u64_to_felts, u128_to_felts, PoseidonCore};

// Convert numbers to field elements
let felts_64 = u64_to_felts(12345);
let felts_128 = u128_to_felts(123456789012345);

// Hash field elements directly
let hash = PoseidonCore::hash_padded_felts(felts_64);
```

### String Hashing

```rust
use qp_poseidon_core::{injective_string_to_felts, PoseidonCore};

// Convert string to field elements (max 8 bytes)
let string_felts = injective_string_to_felts("hello");
let hash = PoseidonCore::hash_padded_felts(string_felts);
```

### Substrate Storage Hashing

```rust
use qp_poseidon::PoseidonHasher;
use codec::{Encode, Decode};

// Specialized storage hashing for transfer proofs
// Note: This is specific to Quantus Network's use case
let storage_data = vec![0u8; 32]; // Your encoded storage data
// let hash = PoseidonHasher::hash_storage::<AccountId>(&storage_data);
```

## 📈 Changelog

### Version 0.9.1
- Restructured as workspace with separate core and substrate crates
- Added no-std support for core crate
- Improved documentation and examples
- Enhanced test coverage