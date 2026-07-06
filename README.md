# qp-poseidon

Poseidon2 hash implementation for the Quantus Network, built on plonky3 field arithmetic over the Goldilocks field.

## Crate

### `qp-poseidon-core` (`core/`)

Pure Rust implementation of Poseidon2 hashing with two encoding modes:

- **Injective encoding** (`hash_bytes`): Safe for variable-length inputs. Uses 4 bytes per field element with a terminator byte to ensure collision resistance.
- **Compact encoding** (`bytes_to_felts_compact`): Uses 8 bytes per field element. Only safe for fixed-size inputs where length is enforced externally.

Features:
- **No-std compatible**: Works in embedded and WASM environments
- **Circuit-compatible**: Matches ZK circuit implementations
- **Goldilocks field**: 64-bit prime field (p = 2^64 - 2^32 + 1)

## Usage

```rust
use qp_poseidon_core::{hash_bytes, hash_to_bytes, hash_twice, rehash_to_bytes};

// Hash arbitrary bytes (injective encoding - collision resistant)
let hash = hash_bytes(b"hello world");

// Hash field elements directly
use qp_poseidon_core::serialization::bytes_to_felts;
let felts = bytes_to_felts(b"data");
let hash = hash_to_bytes(&felts);

// Double hash for address derivation
let address = hash_twice(&felts);

// Re-hash a 32-byte digest (errors on non-canonical digest bytes)
let chained = rehash_to_bytes(&hash).unwrap();
```

## Public API

| Function | Description |
|----------|-------------|
| `hash_bytes(&[u8])` | Hash bytes using injective encoding (4 bytes/felt + terminator) |
| `hash_to_bytes(&[Goldilocks])` | Hash field elements, return 32 bytes |
| `hash_to_felts(&[Goldilocks])` | Hash field elements, return 4 field elements |
| `hash_twice(&[Goldilocks])` | Double hash: `hash(hash(input))` for wormhole addresses |
| `rehash_to_bytes(&[u8; 32])` | Re-hash a 32-byte digest (errors on non-canonical input) |
| `hash_squeeze_twice(&[u8])` | 64-byte output (two squeezes) for mining PoW |

### Serialization (`serialization` module)

| Function | Description |
|----------|-------------|
| `bytes_to_felts(&[u8])` | Injective encoding: 4 bytes/felt + terminator |
| `bytes_to_felts_compact(&[u8])` | Compact encoding: 8 bytes/felt (fixed-size inputs only; errors on non-canonical limbs) |
| `bytes_to_digest(&[u8; 32])` | Decode 32 bytes as 4 field elements (errors on non-canonical limbs) |
| `digest_to_bytes(&[Goldilocks; 4])` | Encode 4 field elements as 32 bytes |
| `string_to_felts(&str)` | Encode string as field elements |

## Security

- **Injective encoding**: `hash_bytes` is collision-resistant for any input length
- **Compact encoding**: Only use `bytes_to_felts_compact` for fixed-size inputs (e.g., in ZK circuits where input size is constrained)
- **Canonical decoding**: `bytes_to_digest`, `rehash_to_bytes`, and `bytes_to_felts_compact` reject 8-byte limbs that encode values `>= P`, preventing byte-distinct inputs from aliasing to the same field elements
- **Timing behavior**: Empirical dudect timing tests show no measurable input-dependent timing (t-scores < 5); see `CONSTANT_TIME_TESTING.md`. Note that the field arithmetic is not strictly branch-free: `Goldilocks` add/sub/reduce take rare carry/borrow correction branches (inherited from the standard optimized Goldilocks implementation) that fire only for values near the modulus. Do not rely on this crate for hard constant-time guarantees on secret inputs.
- **No padding vulnerabilities**: Removed legacy padded hashing functions that had audit issues

## License

MIT-0
