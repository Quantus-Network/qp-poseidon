# qp-poseidon-constants

Precomputed Poseidon2 constants for the Goldilocks field with a binary located at `build_helpers/extract_constants.rs` for extracting the constants and a library for creating a new poseidon2 instance using plonky3 with them.

## Basic Usage

```rust
use p3_goldilocks::Goldilocks;
use p3_field::integers::QuotientMap;
use qp_poseidon_constants::create_poseidon;

// Create a Poseidon2 instance with precomputed constants
let poseidon = create_poseidon();

// Initialize state with width of 12 field element 
let mut state = [Goldilocks::ZERO; 12];

// Permute the state using Poseidon2
poseidon.permute_mut(&mut state);
``` 