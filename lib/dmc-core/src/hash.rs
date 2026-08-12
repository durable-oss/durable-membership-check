//! Keyed hashing shared by every filter implementation.
//!
//! Filters need a fast, well-distributed 64-bit hash of arbitrary byte keys,
//! plus a cheap way to derive further independent-looking values from one
//! hash. Keeping that here means implementations do not each carry their own
//! copy, and a fix to the mixer applies everywhere at once.
//!
//! This is not a cryptographic hash. An adversary who can choose keys can
//! force collisions and drive a filter's false positive rate up. Filters
//! exposed to untrusted key sets should use a secret, per-process
//! [`Params::seed`](crate::Params::seed).

/// Hashes `key` to a 64-bit value under `seed`.
///
/// Uses a FNV-1a pass over the bytes followed by a strong finalizer, which is
/// enough to spread structured keys (sequential integers, shared prefixes)
/// across the output range.
///
/// # Examples
///
/// ```
/// use dmc_core::hash::hash64;
///
/// // Distinct keys hash differently.
/// assert_ne!(hash64(b"alice", 0), hash64(b"bob", 0));
///
/// // The same key under different seeds hashes differently.
/// assert_ne!(hash64(b"alice", 0), hash64(b"alice", 1));
///
/// // Hashing is deterministic.
/// assert_eq!(hash64(b"alice", 7), hash64(b"alice", 7));
/// ```
#[must_use]
pub fn hash64(key: &[u8], seed: u64) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut h = FNV_OFFSET ^ seed.wrapping_mul(FNV_PRIME);

    // Consume eight bytes at a time; the tail falls through to the byte loop.
    let mut chunks = key.chunks_exact(8);
    for chunk in &mut chunks {
        let word = u64::from_le_bytes(chunk.try_into().unwrap_or([0; 8]));
        h ^= word;
        h = h.wrapping_mul(FNV_PRIME);
        h = mix(h);
    }

    for &byte in chunks.remainder() {
        h ^= u64::from(byte);
        h = h.wrapping_mul(FNV_PRIME);
    }

    // Length is folded in so that keys differing only by trailing zero bytes
    // do not collide.
    h ^= key.len() as u64;
    mix(h)
}

/// Finalizer from `SplitMix64`, which passes the usual avalanche tests.
///
/// Used both to finish [`hash64`] and to derive additional values from an
/// existing hash in [`mix_seed`].
#[must_use]
#[inline]
pub fn mix(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// Derives a fresh seed from `seed` and an attempt counter.
///
/// Peeling filters retry construction with new seeds when a hypergraph fails
/// to peel. Deriving each attempt's seed from the caller's seed keeps
/// construction deterministic: the same input seed always produces the same
/// sequence of attempts, and therefore the same filter.
///
/// # Examples
///
/// ```
/// use dmc_core::hash::mix_seed;
///
/// // Different attempts give different seeds.
/// assert_ne!(mix_seed(42, 0), mix_seed(42, 1));
///
/// // But the sequence is reproducible from the same base seed.
/// assert_eq!(mix_seed(42, 3), mix_seed(42, 3));
/// ```
#[must_use]
#[inline]
pub fn mix_seed(seed: u64, attempt: u32) -> u64 {
    mix(seed ^ (u64::from(attempt).wrapping_mul(0x9e37_79b9_7f4a_7c15)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn hash_is_deterministic_across_calls() {
        assert_eq!(hash64(b"durable", 99), hash64(b"durable", 99));
    }

    #[test]
    fn hash_distinguishes_keys_differing_only_in_trailing_zeros() {
        assert_ne!(hash64(b"key", 0), hash64(b"key\0", 0));
    }

    #[test]
    fn hash_distinguishes_long_keys_crossing_chunk_boundary() {
        let a = b"aaaaaaaaaaaaaaaaaaaaaaaaa";
        let b = b"aaaaaaaaaaaaaaaaaaaaaaaab";
        assert_ne!(hash64(a, 0), hash64(b, 0));
    }

    #[test]
    fn sequential_integer_keys_do_not_collide() {
        // Sequential keys are the realistic worst case for a weak mixer.
        let hashes: HashSet<u64> = (0u64..10_000)
            .map(|i| hash64(&i.to_le_bytes(), 0))
            .collect();
        assert_eq!(hashes.len(), 10_000, "sequential keys collided");
    }

    #[test]
    fn top_and_bottom_bits_both_vary() {
        // Filters slice both ends of the hash, so neither end may be constant.
        let mut top_bits = HashSet::new();
        let mut bottom_bits = HashSet::new();
        for i in 0u64..512 {
            let h = hash64(&i.to_le_bytes(), 0);
            top_bits.insert(h >> 58);
            bottom_bits.insert(h & 0x3f);
        }
        assert!(top_bits.len() > 32, "top bits poorly distributed");
        assert!(bottom_bits.len() > 32, "bottom bits poorly distributed");
    }

    #[test]
    fn empty_key_hashes_without_panicking() {
        assert_ne!(hash64(b"", 0), hash64(b"", 1));
    }
}
