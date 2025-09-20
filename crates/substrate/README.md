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

### With Substrate Types

```rust
use qp_poseidon::PoseidonHasher;
use codec::{Encode, Decode};

#[derive(Encode, Decode)]
struct MyData {
    id: u32,
    name: String,
}

let data = MyData {
    id: 42,
    name: "example".to_string(),
};

// Hash encoded data
let encoded = data.encode();
let hash = PoseidonHasher::hash_padded(&encoded);
```

### Storage Hashing (Quantus Specific)

```rust
use qp_poseidon::PoseidonHasher;
use codec::{Encode, Decode};

// For Quantus transfer proof storage keys
// Note: Requires properly encoded transfer data
#[derive(Encode, Decode)]
struct AccountId(u32);

let storage_data = vec![0u8; 32]; // Your encoded transfer data
// let hash = PoseidonHasher::hash_storage::<AccountId>(&storage_data);
```

### Working with Field Elements

```rust
use qp_poseidon::{PoseidonHasher, u64_to_felts, u128_to_felts};

// Convert numbers to field elements
let transfer_count = u64_to_felts(12345);
let amount = u128_to_felts(1000000000);

// Hash field elements directly
let combined_felts = [transfer_count, amount].concat();
let hash = PoseidonHasher::hash_no_pad(combined_felts);
```

## API Reference

### Main Hasher

`PoseidonHasher` - The main hasher struct implementing Substrate traits.

#### Methods

- `hash_padded(data: &[u8]) -> Vec<u8>` - Hash bytes with circuit-compatible padding
- `hash_padded_felts(felts: Vec<GoldilocksField>) -> Vec<u8>` - Hash field elements with padding  
- `hash_no_pad(felts: Vec<GoldilocksField>) -> Vec<u8>` - Hash field elements without padding
- `hash_storage<AccountId: Decode + Encode>(data: &[u8]) -> [u8; 32]` - Specialized storage hashing

### Re-exported Utilities

All utility functions from `qp-poseidon-core` are re-exported for convenience:

- `u64_to_felts(num: u64) -> Vec<GoldilocksField>`
- `u128_to_felts(num: u128) -> Vec<GoldilocksField>`
- `injective_bytes_to_felts(input: &[u8]) -> Vec<GoldilocksField>`
- `injective_felts_to_bytes(input: &[GoldilocksField]) -> Vec<u8>`
- `digest_bytes_to_felts(input: &[u8]) -> Vec<GoldilocksField>`
- `digest_felts_to_bytes(input: &[GoldilocksField]) -> Vec<u8>`
- `injective_string_to_felts(input: &str) -> Vec<GoldilocksField>`

### Constants

- `MIN_FIELD_ELEMENT_PREIMAGE_LEN: usize` - Minimum field elements for padding

## Substrate Traits

The `PoseidonHasher` struct implements the following Substrate traits:

- `Encode` / `Decode` - For storage and network serialization
- `TypeInfo` - For metadata and introspection
- `PartialEq` / `Eq` - For comparisons
- `Clone` / `Debug` - For development and debugging

## Features

- `default`: Includes `std` feature
- `std`: Enables standard library features and `core::hash::Hasher` for `PoseidonStdHasher`
- `serde`: Enables serde serialization support

Enable features in your `Cargo.toml`:

```toml
[dependencies]
qp-poseidon = { path = "path/to/crate", features = ["serde"] }
```

## No-std Usage

For no-std environments:

```toml
[dependencies]
qp-poseidon = { path = "path/to/crate", default-features = false }
```

## Storage Hash Format

The `hash_storage` function expects a specific 32-byte format containing:
1. Transfer count (u64)
2. From account (AccountId)
3. To account (AccountId)  
4. Amount (u128)

This function is specialized for Quantus Network's transfer proof system.

## Testing

```bash
# Run all tests
cargo test

# Test with no-std
cargo test --no-default-features

# Test with serde feature
cargo test --features serde
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

## Integration Examples

### In a Pallet

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

### Custom Storage Keys

```rust
use qp_poseidon::PoseidonHasher;
use sp_std::vec::Vec;

fn create_storage_key(module: &str, item: &str, key: &[u8]) -> Vec<u8> {
    let mut full_key = Vec::new();
    full_key.extend_from_slice(module.as_bytes());
    full_key.extend_from_slice(item.as_bytes());
    full_key.extend_from_slice(key);
    
    PoseidonHasher::hash_padded(&full_key)
}
```

## License

MIT-0

## Contributing

Contributions are welcome! Please ensure:
- All tests pass
- Code follows Rust best practices
- Substrate compatibility is maintained
- Documentation is updated

## Related Crates

- [`qp-poseidon-core`](../core) - The underlying pure cryptographic implementation
- [`parity-scale-codec`](https://github.com/paritytech/parity-scale-codec) - Substrate's encoding library
- [`plonky2`](https://github.com/0xPolygonZero/plonky2) - The underlying field arithmetic library