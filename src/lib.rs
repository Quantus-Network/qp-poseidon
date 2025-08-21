#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode, MaxEncodedLen};
use core::hash::Hasher as StdHasher;
use log;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::{GenericHashOut, Hasher as PlonkyHasher};
use scale_info::TypeInfo;
use sp_core::Hasher;
use sp_core::H256;
use sp_runtime::traits::Hash;
#[cfg(feature = "serde")]
use sp_runtime::{Deserialize, Serialize};
use sp_runtime::{RuntimeDebug, Vec};
use sp_storage::StateVersion;
use sp_trie::{LayoutV0, LayoutV1, TrieConfiguration};

/// The minimum number of field elements to allocate for the preimage.
pub const MIN_FIELD_ELEMENT_PREIMAGE_LEN: usize = 188;
pub const BIT_32_LIMB_MASK: u64 = 0xFFFF_FFFF;

#[derive(Default)]
pub struct PoseidonStdHasher(Vec<u8>);

impl StdHasher for PoseidonStdHasher {
    fn finish(&self) -> u64 {
        let hash = PoseidonHasher::hash_padded(self.0.as_slice());
        u64::from_le_bytes(hash[0..8].try_into().unwrap())
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes)
    }
}

#[derive(PartialEq, Eq, Clone, RuntimeDebug, TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PoseidonHasher;

impl Hasher for PoseidonHasher {
    type Out = H256;
    type StdHasher = PoseidonStdHasher;
    const LENGTH: usize = 32;

    fn hash(x: &[u8]) -> H256 {
        H256::from_slice(&Self::hash_padded(x))
    }
}

impl PoseidonHasher {
    pub fn hash_padded_felts(mut x: Vec<GoldilocksField>) -> Vec<u8> {
        log::debug!(target: "poseidon", "poseidon_hash_felts x: {x:?}");

        // Workaround to support variable-length input in circuit. We need to pad the preimage in
        // the same way as the circuit to ensure consistent hashes.
        if x.len() < MIN_FIELD_ELEMENT_PREIMAGE_LEN {
            x.resize(MIN_FIELD_ELEMENT_PREIMAGE_LEN, GoldilocksField::ZERO);
        }

        PoseidonHash::hash_no_pad(&x).to_bytes()
    }

    pub fn hash_padded(x: &[u8]) -> Vec<u8> {
        log::debug!(target: "poseidon", "poseidon_hash x: {x:?}");
        Self::hash_padded_felts(injective_bytes_to_felts(x))
    }

    pub fn hash_no_pad(x: Vec<GoldilocksField>) -> Vec<u8> {
        PoseidonHash::hash_no_pad(&x).to_bytes()
    }

    // This function should only be used to compute the quantus storage key for Transfer Proofs
    // It breaks up the bytes input in a specific way that mimics how our zk-circuit does it
    pub fn hash_storage<AccountId: Decode + Encode + MaxEncodedLen>(x: &[u8]) -> [u8; 32] {
        let expected_storage_len = u64::max_encoded_len()
            + AccountId::max_encoded_len()
            + AccountId::max_encoded_len()
            + u128::max_encoded_len();
        debug_assert!(
            x.len() == expected_storage_len,
            "Input must be exactly {} bytes, but was {}",
            expected_storage_len,
            x.len()
        );
        let mut felts = Vec::with_capacity(expected_storage_len);
        let mut y = x;
        let (transfer_count, from_account, to_account, amount): (u64, AccountId, AccountId, u128) =
            Decode::decode(&mut y).expect("already asserted input length. qed");
        felts.extend(u64_to_felts(transfer_count));
        felts.extend(digest_bytes_to_felts(&from_account.encode()));
        felts.extend(digest_bytes_to_felts(&to_account.encode()));
        felts.extend(u128_to_felts(amount));
        let hash = PoseidonHasher::hash_no_pad(felts);
        hash.as_slice()[0..32]
            .try_into()
            .expect("already asserted input length. qed")
    }
}

impl Hash for PoseidonHasher {
    type Output = H256;

    fn hash(s: &[u8]) -> Self::Output {
        H256::from_slice(&Self::hash_padded(s))
    }

    /// Produce the hash of some codec-encodable value.
    fn hash_of<S: Encode>(s: &S) -> Self::Output {
        Encode::using_encoded(s, <Self as Hasher>::hash)
    }

    fn ordered_trie_root(input: Vec<Vec<u8>>, state_version: StateVersion) -> Self::Output {
        log::debug!(target: "poseidon",
            "PoseidonHasher::ordered_trie_root input={input:?} version={state_version:?}",
        );
        let res = match state_version {
            StateVersion::V0 => LayoutV0::<PoseidonHasher>::ordered_trie_root(input),
            StateVersion::V1 => LayoutV1::<PoseidonHasher>::ordered_trie_root(input),
        };
        log::debug!(target: "poseidon", "PoseidonHasher::ordered_trie_root res={res:?}");
        res
    }

    fn trie_root(input: Vec<(Vec<u8>, Vec<u8>)>, version: StateVersion) -> Self::Output {
        log::debug!(target: "poseidon",
            "PoseidonHasher::trie_root input={input:?} version={version:?}"
        );
        let res = match version {
            StateVersion::V0 => LayoutV0::<PoseidonHasher>::trie_root(input),
            StateVersion::V1 => LayoutV1::<PoseidonHasher>::trie_root(input),
        };
        log::debug!(target: "poseidon", "PoseidonHasher::trie_root res={res:?}");
        res
    }
}

pub fn u128_to_felts(num: u128) -> Vec<GoldilocksField> {
    const FELTS_PER_U128: usize = 4;
    (0..FELTS_PER_U128)
        .map(|i| {
            let shift = 96 - 32 * i;
            let limb = ((num >> shift) & BIT_32_LIMB_MASK as u128) as u64;
            GoldilocksField::from_canonical_u64(limb)
        })
        .collect::<Vec<_>>()
}

pub fn u64_to_felts(num: u64) -> Vec<GoldilocksField> {
    [
        GoldilocksField::from_noncanonical_u64((num >> 32) & BIT_32_LIMB_MASK),
        GoldilocksField::from_noncanonical_u64(num & BIT_32_LIMB_MASK),
    ]
    .to_vec()
}

pub fn injective_bytes_to_felts(input: &[u8]) -> Vec<GoldilocksField> {
    log::debug!(target: "poseidon", "bytes_to_felts input: {input:?}");

    const BYTES_PER_ELEMENT: usize = 4;

    let mut field_elements: Vec<GoldilocksField> = Vec::new();
    for chunk in input.chunks(BYTES_PER_ELEMENT) {
        let mut bytes = [0u8; BYTES_PER_ELEMENT];
        bytes[..chunk.len()].copy_from_slice(chunk);
        // Convert the chunk to a field element.
        let value = u32::from_le_bytes(bytes);
        let field_element = GoldilocksField::from_noncanonical_u64(value as u64);
        field_elements.push(field_element);
    }

    field_elements
}

pub fn digest_bytes_to_felts(input: &[u8]) -> Vec<GoldilocksField> {
    log::debug!(target: "poseidon", "bytes_to_felts input: {input:?}");

    const BYTES_PER_ELEMENT: usize = 8;

    let mut field_elements: Vec<GoldilocksField> = Vec::new();
    for chunk in input.chunks(BYTES_PER_ELEMENT) {
        let mut bytes = [0u8; BYTES_PER_ELEMENT];
        bytes[..chunk.len()].copy_from_slice(chunk);
        // Convert the chunk to a field element.
        let value = u64::from_le_bytes(bytes);
        let field_element = GoldilocksField::from_noncanonical_u64(value);
        field_elements.push(field_element);
    }

    field_elements
}

pub fn string_to_felt(input: &str) -> GoldilocksField {
    // Convert string to UTF-8 bytes
    let bytes = input.as_bytes();

    let mut arr = [0u8; 8];
    arr[..bytes.len()].copy_from_slice(bytes);

    let num = u64::from_le_bytes(arr);
    GoldilocksField::from_noncanonical_u64(num)
}

#[cfg(test)]
mod tests {
    use super::*;
    use env_logger;
    use hex;
    use plonky2::field::types::Field64;

    #[ctor::ctor]
    fn init_logger_global() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn test_empty_input() {
        let result = <PoseidonHasher as Hasher>::hash(&[]);
        assert_eq!(result.0.len(), 32);
    }

    #[test]
    fn test_single_byte() {
        let input = vec![42u8];
        let result = <PoseidonHasher as Hasher>::hash(&input);
        assert_eq!(result.0.len(), 32);
    }

    #[test]
    fn test_exactly_32_bytes() {
        let input = [1u8; 32];
        let result = <PoseidonHasher as Hasher>::hash(&input);
        assert_eq!(result.0.len(), 32);
    }

    #[test]
    fn test_multiple_chunks() {
        let input = [2u8; 64]; // Two chunks
        let result = <PoseidonHasher as Hasher>::hash(&input);
        assert_eq!(result.0.len(), 32);
    }

    #[test]
    fn test_partial_chunk() {
        let input = [3u8; 40]; // One full chunk plus 8 bytes
        let result = <PoseidonHasher as Hasher>::hash(&input);
        assert_eq!(result.0.len(), 32);
    }

    // #[test]
    // fn test_known_value() {
    //     // Replace these with actual known input/output pairs for your implementation
    //     let input = decode("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20").unwrap();
    //     let result = <PoseidonHasher as Hasher>::hash(&input);
    //     assert_eq!(result.0.len(), 32);
    // }

    #[test]
    fn test_consistency() {
        let input = [4u8; 50];
        let iterations = 100;
        let current_hash = <PoseidonHasher as Hasher>::hash(&input); // Compute the first hash

        for _ in 0..iterations {
            let hash1 = <PoseidonHasher as Hasher>::hash((&current_hash).as_ref());
            let current_hash = <PoseidonHasher as Hasher>::hash((&current_hash).as_ref());
            assert_eq!(hash1, current_hash, "Hash function should be deterministic");
        }
    }

    #[test]
    fn test_different_inputs() {
        let input1 = [5u8; 32];
        let input2 = [6u8; 32];
        let hash1 = <PoseidonHasher as Hasher>::hash(&input1);
        let hash2 = <PoseidonHasher as Hasher>::hash(&input2);
        assert_ne!(
            hash1, hash2,
            "Different inputs should produce different hashes"
        );
    }

    #[test]
    fn test_poseidon_hash_input_sizes() {
        // Test inputs from 1 to 128 bytes
        for size in 1..=128 {
            // Create a predictable input: repeating byte value based on size
            let input: Vec<u8> = (0..size).map(|i| (i * i % 256) as u8).collect();
            let hash = <PoseidonHasher as Hasher>::hash(&input);
            println!("Size {}: {:?}", size, hash);

            // Assertions
            assert_eq!(
                hash.as_bytes().len(),
                32,
                "Input size {} should produce 32-byte H256",
                size
            );
        }
    }

    #[test]
    fn test_big_preimage() {
        for overflow in 1..=200 {
            let preimage = GoldilocksField::ORDER + overflow;
            let _hash = <PoseidonHasher as Hasher>::hash(preimage.to_le_bytes().as_ref());
        }
    }

    #[test]
    fn test_circuit_preimage() {
        let preimage =
            hex::decode("afd8e7530b95ee5ebab950c9a0c62fae1e80463687b3982233028e914f8ec7cc");
        let hash = <PoseidonHasher as Hasher>::hash(&*preimage.unwrap());
        let _hash = <PoseidonHasher as Hasher>::hash(hash.as_bytes());
    }

    #[test]
    fn test_random_inputs() {
        let hex_strings = [
            "a3f8",
            "1b7e9d",
            "4c2a6f81",
            "e5d30b9a",
            "1a4f7c2e9b0d8356",
            "3e8d2a7f5c1b09e4d6f7a2c8",
            "7b3e9a1f4c8d2e6b0a5f9d3c",
            "1a4f7c2e9b0d83561a4f7c2e9b0d83561a4f7c2e9b0d83561a4f7c2e9b0d8356",
            "e5d30b9a4c2a6f81e5d30b9a4c2a6f81e5d30b9a4c2a6f81e5d30b9a4c2a6f81",
        ];

        for hex_string in hex_strings.iter() {
            let preimage = hex::decode(hex_string).unwrap();
            println!("input: {}", hex_string);
            let hash = <PoseidonHasher as Hasher>::hash(&preimage);
            let _hash2 = <PoseidonHasher as Hasher>::hash(&hash.as_bytes());
        }
    }

    #[test]
    fn test_known_value_hashes() {
        let vectors = [
            (
                vec![],
                "fdf0715f178bfb2381d3804961bda8c679990d6318ff53f7a6475e1bef1982ca",
            ),
            (
                vec![0u8],
                "fdf0715f178bfb2381d3804961bda8c679990d6318ff53f7a6475e1bef1982ca",
            ),
            (
                vec![1u8, 2, 3, 4, 5, 6, 7, 8],
                "4e7207e51d9c4fda0e05c7e34efa9defea76df8e0c79a240608bca5c1a587038",
            ),
            (
                vec![255u8; 32],
                "f17b88e7eb676dff0fcc3f282cec9190e78706b5300918983dd91a11baa5e819",
            ),
            (
                b"hello world".to_vec(),
                "4b9a9943e8f02150f5527d66c34a0d2ec8c2b421e94408f8aa917104143b2bd1",
            ),
            (
                (0u8..32).collect::<Vec<u8>>(),
                "2303d1a7c96b8eb1ef24d845a2bf4445365f47f839e7d486a58bd4666329b4e2",
            ),
        ];
        for (input, expected_hex) in vectors.iter() {
            let hash = <PoseidonHasher as Hasher>::hash(input);
            assert_eq!(
                hex::encode(hash.as_bytes()),
                *expected_hex,
                "input: 0x{}",
                hex::encode(input)
            );
        }
    }

    // #[test]
    // fn test_empty_blake2() {
    //     let result = <BlakeTwo256 as Hasher>::hash(&[]);
    //     println!("hash output: {:?}", result);
    //     assert_eq!(result.0.len(), 32);
    // }
}
