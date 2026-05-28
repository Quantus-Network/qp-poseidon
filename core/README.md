# qp-poseidon-core

Pure Rust implementation of Poseidon2 hashing over the Goldilocks field (p = 2^64 - 2^32 + 1).

## Features

- **No-std compatible**: Works in embedded, WASM, and constrained environments
- **Circuit-compatible**: Encoding matches ZK circuit implementations
- **Collision-resistant**: Injective encoding prevents length-extension and padding attacks
- **Goldilocks field**: Built on plonky3's optimized 64-bit prime field arithmetic

## Usage

### Hash Arbitrary Bytes

```rust
use qp_poseidon_core::hash_bytes;

// Injective encoding - safe for any input length
let hash: [u8; 32] = hash_bytes(b"hello world");
```

### Hash Field Elements

```rust
use qp_poseidon_core::{hash_to_bytes, hash_to_felts};
use qp_poseidon_core::serialization::bytes_to_felts;

let felts = bytes_to_felts(b"data");

// Get 32-byte hash
let hash: [u8; 32] = hash_to_bytes(&felts);

// Get 4 field elements (for chaining)
let hash_felts = hash_to_felts(&felts);
```

### Double Hashing (Wormhole Addresses)

```rust
use qp_poseidon_core::{hash_twice, rehash_to_bytes};
use qp_poseidon_core::serialization::bytes_to_felts;

let felts = bytes_to_felts(b"secret");

// hash(hash(input)) - used for wormhole address derivation
let address: [u8; 32] = hash_twice(&felts);

// Re-hash an existing 32-byte digest
let first_hash = hash_to_bytes(&felts);
let second_hash: [u8; 32] = rehash_to_bytes(&first_hash);
```

### Mining (64-byte Output)

```rust
use qp_poseidon_core::hash_squeeze_twice;

// Two sponge squeezes for 64-byte output
let hash_512: [u8; 64] = hash_squeeze_twice(b"block data");
```

## Encoding Modes

### Injective Encoding (Default)

Used by `hash_bytes` and `bytes_to_felts`. Safe for variable-length inputs.

- 4 bytes per field element
- Terminator byte (0x01) marks end of input
- Guarantees different inputs produce different field element sequences

### Compact Encoding

Used by `bytes_to_felts_compact`. Only safe for fixed-size inputs.

- 8 bytes per field element (full capacity)
- No length marker - trailing zeros collide
- Use only when input size is enforced externally (e.g., ZK circuits)

## Security Notes

1. **Always use `hash_bytes` for arbitrary input** - it's collision-resistant
2. **Compact encoding is for circuits only** - where input size is constrained by the circuit
3. **No padding functions** - legacy padded hashing was removed due to audit findings
4. **Timing resistance** - core hashing has no input-dependent branches

## Related Crates

- [`qp-poseidon-constants`](https://crates.io/crates/qp-poseidon-constants) - Round constants
- [`plonky3`](https://github.com/0xPolygonZero/plonky3) - Field arithmetic
