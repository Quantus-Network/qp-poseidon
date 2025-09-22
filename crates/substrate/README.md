# qp-poseidon

Substrate-compatible Poseidon hash implementation for the Polkadot ecosystem. This crate wraps `qp-poseidon-core` and adds Substrate-specific functionality including codec traits and specialized storage operations.

## Features

- **Substrate integration**: Implements required traits for use in Substrate/Polkadot projects
- **Codec support**: Implements `Encode`, `Decode`, and `TypeInfo` traits from `parity-scale-codec`
- **Serde support**: Optional serialization support via the `serde` feature
- **Storage hashing**: Specialized functions for Quantus Network storage operations
- **Circuit compatibility**: Maintains compatibility with zero-knowledge circuit implementations
- **No-std support**: Works in constrained environments

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
qp-poseidon = { path = "path/to/qp-poseidon/crates/substrate" }
```

### Basic Hashing

```rust
use qp_poseidon::PoseidonHasher;

// Hash bytes with circuit-compatible padding
let data = b"hello world";
let hash = PoseidonHasher::hash_padded(data);
println!("Hash: {:?}", hash);
```

## Performance

- Optimized for Substrate's encoding/decoding patterns
- Maintains deterministic behavior across different platforms
- Memory efficient for blockchain storage operations
- Circuit-compatible padding ensures consistency with ZK proofs

## Security

- Built on `qp-poseidon-core`'s security guarantees
- Uses standard Substrate codec patterns
- Specialized storage hashing prevents collision attacks
- Extensive test coverage with known vectors

## Integration

```rust
use qp_poseidon::PoseidonHasher;
use frame_support::pallet_prelude::*;

#[pallet::config]
pub trait Config: frame_system::Config {
    type Hasher: sp_runtime::traits::Hash<Output = sp_core::H256>;
}

// Use PoseidonHasher as the pallet's hasher
impl pallet::Config for Runtime {
    type Hasher = PoseidonHasher;
}
```

## Related Crates

- [`qp-poseidon-core`](../core) - The underlying pure cryptographic implementation
- [`parity-scale-codec`](https://github.com/paritytech/parity-scale-codec) - Substrate's encoding library
- [`plonky3`](https://github.com/0xPolygonZero/plonky3) - The underlying field arithmetic library
