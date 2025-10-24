use crate::RATE;
use alloc::vec::Vec;

const BIT_32_LIMB_MASK: u64 = 0xFFFF_FFFF;

/// Unify just what we need from a Goldilocks field element.
pub trait GoldiCompat: Copy + Clone + core::ops::AddAssign + 'static {
	const ORDER_U64: u64;

	fn from_u64(x: u64) -> Self;
	fn to_u64(self) -> u64;
}

// --- Plonky3 Goldilocks ---------------------------------------------------------
#[cfg(feature = "p3")]
pub mod p3_backend {
	use super::GoldiCompat;
	use p3_field::{integers::QuotientMap, PrimeField64};
	use p3_goldilocks::Goldilocks as P3G;

	impl GoldiCompat for P3G {
		// And the trait constant via a fully-qualified path
		const ORDER_U64: u64 = <P3G as PrimeField64>::ORDER_U64;

		#[inline]
		fn from_u64(x: u64) -> Self {
			Self::from_int(x)
		}
		#[inline]
		fn to_u64(self) -> u64 {
			self.as_canonical_u64()
		}
	}

	pub type GF = P3G;
}

// --- Plonky2 Goldilocks ----------------------------------------------------------
#[cfg(feature = "p2")]
pub mod p2_backend {
	use super::GoldiCompat;
	use plonky2::field::{
		goldilocks_field::GoldilocksField as P2G,
		types::{Field, Field64, PrimeField64},
	};

	impl GoldiCompat for P2G {
		const ORDER_U64: u64 = Self::ORDER;

		#[inline]
		fn from_u64(x: u64) -> Self {
			Self::from_noncanonical_u64(x)
		}
		#[inline]
		fn to_u64(self) -> u64 {
			self.to_canonical_u64()
		}
	}

	pub type GF = P2G;
}

pub fn u128_to_felts<G: GoldiCompat>(num: u128) -> Vec<G> {
	const FELTS_PER_U128: usize = 4;
	(0..FELTS_PER_U128)
		.map(|i| {
			let shift = 96 - 32 * i;
			let limb = ((num >> shift) & BIT_32_LIMB_MASK as u128) as u64;
			G::from_u64(limb)
		})
		.collect()
}

pub fn u64_to_felts<G: GoldiCompat>(num: u64) -> Vec<G> {
	alloc::vec![G::from_u64((num >> 32) & BIT_32_LIMB_MASK), G::from_u64(num & BIT_32_LIMB_MASK),]
}

/// Injective, 4 bytes → 1 felt, input is variable-length padded with 1, 0... to align with u32 size
/// NOTE: we do 32 bit limbs to achieve injectivity. We could use a larger size up to 63 bits but
/// chose to do 32 bits for simplicity.
pub fn injective_bytes_to_felts<G: GoldiCompat>(input: &[u8]) -> Vec<G> {
	const BYTES_PER_ELEMENT: usize = 4;
	let mut out = Vec::new();

	let mut padded_input = input.to_vec();
	// Mark end with 1u8
	padded_input.push(1u8);
	let mod_len = padded_input.len() % BYTES_PER_ELEMENT;
	if mod_len != 0 {
		// Fill to BYTES_PER_ELEMENT alignment with 0u8s
		padded_input.resize(padded_input.len() + BYTES_PER_ELEMENT - mod_len, 0u8);
	}

	let chunks = padded_input.chunks(BYTES_PER_ELEMENT);
	assert!(padded_input.chunks_exact(BYTES_PER_ELEMENT).remainder().len() == 0);

	for chunk in chunks {
		let mut bytes = [0u8; BYTES_PER_ELEMENT];
		bytes[..chunk.len()].copy_from_slice(chunk);
		out.push(G::from_u64(u32::from_le_bytes(bytes) as u64));
	}

	out
}

/// 8 bytes → 1 felt, for digest paths, with bounds check.
pub fn try_digest_bytes_to_felts<G: GoldiCompat>(
	input: &[u8],
) -> Result<Vec<G>, alloc::string::String> {
	const BYTES_PER_ELEMENT: usize = 8;
	let mut out = Vec::new();

	for (i, chunk) in input.chunks(BYTES_PER_ELEMENT).enumerate() {
		let mut bytes = [0u8; BYTES_PER_ELEMENT];
		bytes[..chunk.len()].copy_from_slice(chunk);
		let v = u64::from_le_bytes(bytes);
		if v >= G::ORDER_U64 {
			return Err(alloc::format!(
				"Byte chunk value exceeds field order at chunk {} (bytes: {:?})",
				i,
				chunk
			));
		}
		out.push(G::from_u64(v));
	}
	Ok(out)
}

pub fn digest_felts_to_bytes<G: GoldiCompat>(input: &[G; RATE]) -> [u8; 32] {
	// Convert exactly RATE felts to 32 bytes: RATE felts × 8 bytes/felt = 32 bytes
	let mut bytes = [0u8; 32];
	for i in 0..RATE {
		let start = i * 8;
		let end = start + 8;
		bytes[start..end].copy_from_slice(&G::to_u64(input[i]).to_le_bytes());
	}
	bytes
}

/// Inverse of `injective_bytes_to_felts`.
pub fn try_injective_felts_to_bytes<G: GoldiCompat>(input: &[G]) -> Result<Vec<u8>, &'static str> {
	if input.is_empty() {
		return Err("Expected non-empty input");
	}

	const BYTES_PER_ELEMENT: usize = 4;
	let mut words: Vec<[u8; BYTES_PER_ELEMENT]> = Vec::with_capacity(input.len());
	for felt in input {
		words.push((G::to_u64(*felt) as u32).to_le_bytes());
	}

	let mut out = Vec::new();

	// If original input was u32 aligned, drop the last word
	if words.last() == Some(&[1, 0, 0, 0]) {
		for w in &words[..words.len() - 1] {
			out.extend_from_slice(w);
		}
		return Ok(out);
	}

	// The first n-1 words are normal
	for w in &words[..words.len() - 1] {
		out.extend_from_slice(w);
	}

	// The last word must remove the inline terminator
	let last = words.last().unwrap();
	let mut marker_idx = None;
	for j in 0..BYTES_PER_ELEMENT {
		if last[j] == 1 && last[j + 1..].iter().all(|&b| b == 0) {
			marker_idx = Some(j);
			break;
		}
	}
	match marker_idx {
		Some(j) => {
			out.extend_from_slice(&last[..j]);
			Ok(out)
		},
		None => Err("Malformed input: missing inline terminator in last felt"),
	}
}

/// Convert a string to field elements
pub fn injective_string_to_felts<G: GoldiCompat>(input: &str) -> Vec<G> {
	// Convert string to UTF-8 bytes
	let bytes = input.as_bytes();
	injective_bytes_to_felts::<G>(bytes)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::Goldilocks;
	use alloc::vec;
	use p3_field::integers::QuotientMap;

	#[test]
	fn test_utility_functions() {
		// Test u64_to_felts
		let num = 0x1234567890ABCDEF;
		let felts = u64_to_felts::<Goldilocks>(num);
		assert_eq!(felts.len(), 2);

		// Test u128_to_felts
		let large_num = 0x123456789ABCDEF0123456789ABCDEF0u128;
		let felts = u128_to_felts::<Goldilocks>(large_num);
		assert_eq!(felts.len(), 4);

		// Test string conversion
		let text = "hello";
		let felts = injective_string_to_felts::<Goldilocks>(text);
		assert_eq!(felts.len(), 2);

		// Test round-trip conversion
		let original_bytes = b"test data";
		let felts = injective_bytes_to_felts::<Goldilocks>(original_bytes);
		let recovered_bytes = try_injective_felts_to_bytes(&felts).unwrap();
		// Should match the original
		assert_eq!(&recovered_bytes, original_bytes);
		// try injective felts to bytes should fail for malformed input
		let malformed_felts =
			vec![Goldilocks::from_int(0xFFFFFFFF as i64), Goldilocks::from_int(0xFFFFFFFF as i64)];
		let result = try_injective_felts_to_bytes(&malformed_felts);
		assert!(result.is_err(), "Malformed input should return an error");
	}
}
