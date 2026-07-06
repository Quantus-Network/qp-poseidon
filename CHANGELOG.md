## 📈 Changelog

### Unreleased
- **Breaking**: `bytes_to_digest`, `bytes_to_felts_compact`, and `rehash_to_bytes` now return `Result`, rejecting 8-byte limbs that encode values `>= P` (non-canonical field encodings that alias with canonical elements and enabled hash collisions)
- **Breaking**: `u128_to_quantized_felt` replaced by `try_u128_to_quantized_felt`, which returns `Result` instead of panicking on amounts whose quantized value exceeds 32 bits
- `hash_bytes` and `hash_squeeze_twice` now absorb input incrementally instead of materializing the serialized preimage on the heap (fixes unbounded allocation on attacker-sized inputs)
- Added `bytes_to_felts_iter` / `bytes_to_u64s_iter` for allocation-free streaming of the injective encoding

### Version 0.9.1
- Restructured as workspace with separate core and substrate crates
- Added no-std support for core crate
- Improved documentation and examples
- Enhanced test coverage
