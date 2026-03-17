use crate::{
	hash_variable_length,
	serialization::{
		digest_felts_to_bytes, injective_bytes_to_felts, try_injective_felts_to_bytes,
		unsafe_digest_bytes_to_felts,
	},
};
use alloc::vec::Vec;
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;

const DIGEST_BYTES: usize = 32;
const HEADER_BYTES: usize = 8;
const BITMAP_BYTES: usize = 8;
const MAX_BRANCH_CHILDREN: usize = 16;
const WORMHOLE_STORAGE_KEY_BYTES: usize = 64;
const MAX_INLINE_VALUE_BYTES: usize = 31;
pub const ZKTRIE_NODE_FIELD_ELEMENT_PREIMAGE_PADDING_LEN: usize =
	max_hybrid_node_felts_for_wormhole_storage_proof();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParsedZkTrieNodeKind {
	Null,
	Branch { has_value: bool, hashed_value: bool, nibble_count: usize, child_count: usize },
	Leaf { hashed_value: bool, nibble_count: usize },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedZkTrieNode<'a> {
	pub raw_node_bytes: &'a [u8],
	pub kind: ParsedZkTrieNodeKind,
	pub prefix_bytes_len: usize,
	pub child_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HybridEncodedNode {
	pub raw_node_bytes: Vec<u8>,
	pub prefix_bytes_len: usize,
	pub prefix_felts_len: usize,
	pub total_felts_len: usize,
	pub felts: Vec<Goldilocks>,
	pub child_digest_offsets_f: Vec<usize>,
}

impl HybridEncodedNode {
	pub fn reconstruct_node_bytes(&self) -> Result<Vec<u8>, &'static str> {
		let mut raw = try_injective_felts_to_bytes(&self.felts[..self.prefix_felts_len])?;
		let mut digest_offset = self.prefix_felts_len;
		while digest_offset < self.total_felts_len {
			let digest_felts: [Goldilocks; 4] = self.felts[digest_offset..digest_offset + 4]
				.try_into()
				.map_err(|_| "malformed digest tail")?;
			raw.extend_from_slice(&digest_felts_to_bytes(&digest_felts));
			digest_offset += 4;
		}
		Ok(raw)
	}
}

pub const fn max_hybrid_node_felts_for_wormhole_storage_proof() -> usize {
	let prefix_bytes = max_branch_prefix_bytes_for_wormhole_storage_proof();
	injective_felt_len(prefix_bytes) + (MAX_BRANCH_CHILDREN * 4)
}

pub const fn max_branch_prefix_bytes_for_wormhole_storage_proof() -> usize {
	let max_branch_partial_nibbles =
		max_branch_partial_nibbles_for_key_bytes(WORMHOLE_STORAGE_KEY_BYTES);
	HEADER_BYTES +
		felt_aligned_branch_partial_bytes(max_branch_partial_nibbles) +
		BITMAP_BYTES +
		HEADER_BYTES +
		(MAX_INLINE_VALUE_BYTES.div_ceil(8) * 8)
}

pub fn hash_zktrie_node_hybrid_padded<const C: usize>(node_bytes: &[u8]) -> Option<[u8; 32]> {
	let encoded = encode_zktrie_node_hybrid(node_bytes).ok()?;
	let mut felts = encoded.felts;
	if felts.len() > C {
		return None;
	}
	felts.resize(C, Goldilocks::ZERO);
	Some(hash_variable_length(felts))
}

pub fn try_hash_zktrie_node_hybrid(node_bytes: &[u8]) -> Option<[u8; 32]> {
	hash_zktrie_node_hybrid_padded::<ZKTRIE_NODE_FIELD_ELEMENT_PREIMAGE_PADDING_LEN>(node_bytes)
}

pub fn parse_zktrie_node(node_bytes: &[u8]) -> Result<ParsedZkTrieNode<'_>, &'static str> {
	if node_bytes.len() < HEADER_BYTES {
		return Err("node too short");
	}

	let header = u64::from_le_bytes(node_bytes[..HEADER_BYTES].try_into().unwrap());
	let type_code = (header >> 60) & 0xF;
	let nibble_count = (header & 0xFFFF_FFFF) as usize;
	let mut offset = HEADER_BYTES;

	let parsed = match type_code {
		0 => {
			if node_bytes.len() != HEADER_BYTES {
				return Err("null node has trailing bytes");
			}
			ParsedZkTrieNode {
				raw_node_bytes: node_bytes,
				kind: ParsedZkTrieNodeKind::Null,
				prefix_bytes_len: HEADER_BYTES,
				child_count: 0,
			}
		},
		1 | 2 | 4 => {
			let has_value = type_code != 2;
			let hashed_value = type_code == 4;
			let nibble_bytes = nibble_count.div_ceil(2);
			let partial_aligned_bytes = felt_aligned_branch_partial_bytes(nibble_count);
			ensure_available(node_bytes, offset, partial_aligned_bytes)?;
			if nibble_count % 2 == 1 && (node_bytes[offset] & 0xF0) != 0 {
				return Err("branch partial nibble padding is non-zero");
			}
			offset += partial_aligned_bytes;

			ensure_available(node_bytes, offset, BITMAP_BYTES)?;
			let bitmap =
				u64::from_le_bytes(node_bytes[offset..offset + BITMAP_BYTES].try_into().unwrap());
			if bitmap == 0 {
				return Err("branch bitmap has no children");
			}
			let child_count = bitmap.count_ones() as usize;
			if child_count > MAX_BRANCH_CHILDREN {
				return Err("branch has too many children");
			}
			offset += BITMAP_BYTES;

			if has_value {
				if hashed_value {
					ensure_available(node_bytes, offset, DIGEST_BYTES)?;
					offset += DIGEST_BYTES;
				} else {
					let (value_len, value_offset) =
						decode_length_prefixed_aligned_section(node_bytes, offset)?;
					let _ = value_len;
					offset = value_offset;
				}
			}

			let prefix_bytes_len = offset;
			let child_bytes_len = child_count * DIGEST_BYTES;
			ensure_available(node_bytes, offset, child_bytes_len)?;
			offset += child_bytes_len;

			if offset != node_bytes.len() {
				return Err("branch node has trailing bytes");
			}

			let _ = nibble_bytes;
			ParsedZkTrieNode {
				raw_node_bytes: node_bytes,
				kind: ParsedZkTrieNodeKind::Branch {
					has_value,
					hashed_value,
					nibble_count,
					child_count,
				},
				prefix_bytes_len,
				child_count,
			}
		},
		3 | 5 => {
			let hashed_value = type_code == 5;
			let nibble_bytes = nibble_count.div_ceil(2);
			let partial_section_bytes = felt_aligned_leaf_partial_bytes(nibble_count);
			let prefix_padding = leaf_prefix_padding_bytes(nibble_count);
			ensure_available(node_bytes, offset, partial_section_bytes)?;
			let nibble_start = offset + prefix_padding;
			if nibble_count % 2 == 1 && (node_bytes[nibble_start] & 0xF0) != 0 {
				return Err("leaf partial nibble padding is non-zero");
			}
			offset += partial_section_bytes;

			if hashed_value {
				ensure_available(node_bytes, offset, DIGEST_BYTES)?;
				offset += DIGEST_BYTES;
			} else {
				let (value_len, value_offset) =
					decode_length_prefixed_aligned_section(node_bytes, offset)?;
				let _ = value_len;
				offset = value_offset;
			}

			if offset != node_bytes.len() {
				return Err("leaf node has trailing bytes");
			}

			let _ = nibble_bytes;
			ParsedZkTrieNode {
				raw_node_bytes: node_bytes,
				kind: ParsedZkTrieNodeKind::Leaf { hashed_value, nibble_count },
				prefix_bytes_len: node_bytes.len(),
				child_count: 0,
			}
		},
		_ => return Err("invalid trie node type"),
	};

	Ok(parsed)
}

pub fn encode_zktrie_node_hybrid(node_bytes: &[u8]) -> Result<HybridEncodedNode, &'static str> {
	let parsed = parse_zktrie_node(node_bytes)?;
	let prefix_bytes = &node_bytes[..parsed.prefix_bytes_len];
	let mut felts = injective_bytes_to_felts(prefix_bytes);
	let prefix_felts_len = felts.len();
	let mut child_digest_offsets_f = Vec::with_capacity(parsed.child_count);

	for child_index in 0..parsed.child_count {
		let start = parsed.prefix_bytes_len + child_index * DIGEST_BYTES;
		let end = start + DIGEST_BYTES;
		let digest: [u8; DIGEST_BYTES] =
			node_bytes[start..end].try_into().map_err(|_| "malformed child digest")?;
		child_digest_offsets_f.push(felts.len());
		felts.extend_from_slice(&unsafe_digest_bytes_to_felts(&digest));
	}

	let total_felts_len = felts.len();
	Ok(HybridEncodedNode {
		raw_node_bytes: node_bytes.to_vec(),
		prefix_bytes_len: parsed.prefix_bytes_len,
		prefix_felts_len,
		total_felts_len,
		felts,
		child_digest_offsets_f,
	})
}

const fn max_branch_partial_nibbles_for_key_bytes(key_bytes: usize) -> usize {
	(key_bytes * 2).saturating_sub(1)
}

const fn leaf_prefix_padding_bytes(nibble_count: usize) -> usize {
	let nibble_bytes = nibble_count.div_ceil(2);
	let misalignment = nibble_bytes % 8;
	if misalignment == 0 {
		0
	} else {
		8 - misalignment
	}
}

const fn felt_aligned_branch_partial_bytes(nibble_count: usize) -> usize {
	let nibble_bytes = nibble_count.div_ceil(2);
	nibble_bytes.div_ceil(8) * 8
}

const fn felt_aligned_leaf_partial_bytes(nibble_count: usize) -> usize {
	let nibble_bytes = nibble_count.div_ceil(2);
	let prefix_padding = leaf_prefix_padding_bytes(nibble_count);
	(prefix_padding + nibble_bytes).div_ceil(8) * 8
}

const fn injective_felt_len(bytes_len: usize) -> usize {
	(bytes_len + 4) / 4
}

fn ensure_available(data: &[u8], offset: usize, count: usize) -> Result<(), &'static str> {
	if offset.checked_add(count).is_none_or(|end| end > data.len()) {
		return Err("node truncated");
	}
	Ok(())
}

fn decode_length_prefixed_aligned_section(
	data: &[u8],
	offset: usize,
) -> Result<(usize, usize), &'static str> {
	ensure_available(data, offset, HEADER_BYTES)?;
	let count =
		u64::from_le_bytes(data[offset..offset + HEADER_BYTES].try_into().unwrap()) as usize;
	let aligned = count.div_ceil(8) * 8;
	let next_offset = offset + HEADER_BYTES + aligned;
	ensure_available(data, offset + HEADER_BYTES, aligned)?;
	Ok((count, next_offset))
}

#[cfg(test)]
mod tests {
	use super::{
		encode_zktrie_node_hybrid, hash_zktrie_node_hybrid_padded,
		max_branch_prefix_bytes_for_wormhole_storage_proof,
		max_hybrid_node_felts_for_wormhole_storage_proof, ParsedZkTrieNodeKind,
		ZKTRIE_NODE_FIELD_ELEMENT_PREIMAGE_PADDING_LEN,
	};
	use alloc::vec::Vec;

	fn branch_node_with_hashed_value_and_children(child_count: usize) -> Vec<u8> {
		let nibble_count = 127u64;
		let header = ((1u64 << 60) | nibble_count).to_le_bytes();
		let mut node = Vec::new();
		node.extend_from_slice(&header);
		node.push(0x01);
		node.extend([0x11; 63]);
		node.extend_from_slice(&(u16::MAX as u64).to_le_bytes());
		node.extend_from_slice(&31u64.to_le_bytes());
		node.extend([0x22; 31]);
		node.push(0);
		for i in 0..child_count {
			node.extend([i as u8; 32]);
		}
		node
	}

	#[test]
	fn wormhole_storage_bound_is_mechanical_and_exact() {
		assert_eq!(max_branch_prefix_bytes_for_wormhole_storage_proof(), 120);
		assert_eq!(max_hybrid_node_felts_for_wormhole_storage_proof(), 95);
		assert_eq!(ZKTRIE_NODE_FIELD_ELEMENT_PREIMAGE_PADDING_LEN, 95);
	}

	#[test]
	fn hybrid_round_trip_reconstructs_branch_node_bytes() {
		let node = branch_node_with_hashed_value_and_children(16);
		let encoded = encode_zktrie_node_hybrid(&node).expect("branch should parse");
		assert_eq!(encoded.prefix_bytes_len, 120);
		assert_eq!(encoded.prefix_felts_len, 31);
		assert_eq!(encoded.total_felts_len, 95);
		assert_eq!(encoded.child_digest_offsets_f, (0..16).map(|i| 31 + i * 4).collect::<Vec<_>>());
		assert_eq!(encoded.reconstruct_node_bytes().unwrap(), node);
	}

	#[test]
	fn parser_rejects_old_length_prefixed_child_refs() {
		let mut node = branch_node_with_hashed_value_and_children(0);
		node.extend_from_slice(&32u64.to_le_bytes());
		node.extend([0x44; 32]);
		assert!(encode_zktrie_node_hybrid(&node).is_err());
	}

	#[test]
	fn hash_helper_accepts_valid_node() {
		let node = branch_node_with_hashed_value_and_children(16);
		assert!(hash_zktrie_node_hybrid_padded::<95>(&node).is_some());
		assert!(hash_zktrie_node_hybrid_padded::<94>(&node).is_none());
	}

	#[test]
	fn leaf_nodes_stay_pure_injective_prefixes() {
		let header = ((3u64 << 60) | 4u64).to_le_bytes();
		let mut leaf = Vec::new();
		leaf.extend_from_slice(&header);
		leaf.extend([0u8; 8]);
		leaf.extend_from_slice(&1u64.to_le_bytes());
		leaf.push(7u8);
		leaf.extend([0u8; 7]);

		let parsed = super::parse_zktrie_node(&leaf).unwrap();
		assert_eq!(
			parsed.kind,
			ParsedZkTrieNodeKind::Leaf { hashed_value: false, nibble_count: 4 }
		);
		let encoded = encode_zktrie_node_hybrid(&leaf).unwrap();
		assert_eq!(encoded.prefix_bytes_len, leaf.len());
		assert_eq!(encoded.total_felts_len, encoded.prefix_felts_len);
		assert_eq!(encoded.reconstruct_node_bytes().unwrap(), leaf);
	}
}
