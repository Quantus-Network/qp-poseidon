# qp-poseidon

A workspace containing Poseidon hash implementations for different use cases, built on top of plonky3 field arithmetic.

## 📁 Workspace Structure

This workspace contains two crates:

### `qp-poseidon-core` (`crates/core`)
Pure Rust implementation of the Poseidon hash function without any external dependencies beyond plonky3.

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

See respective [README.md](crates/core/README.md) and [README.md](crates/substrate/README.md) for more details.

## 📊 Performance

The implementation is optimized for:
- Circuit compatibility (consistent padding)
- No-std environments
- Deterministic behavior across platforms
- Memory efficiency in constrained environments

## 🔒 Security

- Uses battle-tested plonky3 field arithmetic
- Implements the standard Poseidon permutation
- Circuit-compatible padding prevents length extension attacks
- Extensive test coverage with known test vectors

## 📄 License

MIT-0

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Ensure all tests pass
6. Submit a pull request

## Related Crates

- [`qp-poseidon-core`](../core) - The underlying pure cryptographic implementation
- [`parity-scale-codec`](https://github.com/paritytech/parity-scale-codec) - Substrate's encoding library
- [`plonky3`](https://github.com/0xPolygonZero/plonky3) - The underlying field arithmetic library
