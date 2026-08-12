//! `bloom_001`: classic Bloom filter with Kirsch-Mitzenmacher double hashing.
//!
//! # Stability
//!
//! This implementation is frozen. Which keys it reports as present will not
//! change; a change to that behavior ships as `bloom_002`. Performance and
//! memory fixes may land here in place.

// Bloom sizing is statistical: bit counts and key counts convert to f64 for the
// standard `m = -n ln(p) / (ln 2)^2` formula. Beyond 2^53 an f64 stops being
// exact, but MAX_BITS caps the array well below that, and a one-ulp difference
// in a false-positive estimate has no consequence.
#![allow(clippy::cast_precision_loss)]

use dmc_core::hash::{hash64, mix};
use dmc_core::header::Header;
use dmc_core::{Error, Filter, Params, Result};

/// Bits per word in the backing store.
const BITS_PER_WORD: usize = 64;

/// Upper bound on hash functions.
///
/// Past this point each additional probe costs more time than it saves in
/// false positives, and a caller asking for it has usually mis-specified the
/// false positive rate rather than genuinely wanting 65 probes per lookup.
const MAX_HASHES: u32 = 64;

/// Upper bound on the bit array, at 1 GiB of backing store.
///
/// A false positive rate near zero drives the computed bit count arbitrarily
/// high. Without a ceiling, the allocation would abort the process instead of
/// returning; clamping degrades the achieved false positive rate instead,
/// which callers can read back from
/// [`false_positive_rate`](Filter::false_positive_rate).
const MAX_BITS: usize = 8 * 1024 * 1024 * 1024;

/// Format version for the encoded payload, distinct from the implementation
/// version. Lets the decoder reject bytes from a future payload layout.
const PAYLOAD_VERSION: u8 = 1;

/// Family name this implementation registers under.
const FAMILY: &str = "bloom";

/// Implementation version within the family; the `001` in `bloom_001`.
const VERSION: u32 = 1;

/// Numeric family written into every encoding's header.
///
/// Resolved from [`FAMILY`] through the same table
/// [`register_filter!`](dmc_core::register_filter) uses, so the constant and
/// the registration cannot name different families.
const FAMILY_CODE: u32 = match dmc_core::family::code_for(FAMILY) {
    Some(code) => code,
    None => panic!("bloom is not in dmc_core::family::KNOWN"),
};

/// A classic Bloom filter.
///
/// Sized from the expected key count and target false positive rate using the
/// standard optimum: `m = -n ln(p) / (ln 2)^2` bits and `k = (m/n) ln 2` hash
/// functions.
///
/// # Duplicate keys
///
/// Duplicates in the input are harmless; setting an already-set bit is a
/// no-op. [`len`](Filter::len) reports the number of keys supplied, not the
/// number of distinct keys.
///
/// # Examples
///
/// ```
/// use dmc_bloom::Bloom001;
/// use dmc_core::{Filter, Params};
///
/// let keys: Vec<&[u8]> = vec![b"alice", b"bob", b"carol"];
/// let filter = Bloom001::build(&keys, &Params::new(3, 0.01))?;
///
/// assert!(filter.contains(b"alice"));
/// assert!(!filter.contains(b"nobody-put-this-in"));
/// # Ok::<(), dmc_core::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bloom001 {
    /// Bit array, packed into 64-bit words.
    bits: Vec<u64>,

    /// Number of bits actually in use; `bits.len() * 64` may exceed this.
    bit_count: usize,

    /// Number of hash functions probed per key.
    hash_count: u32,

    /// Seed for the base hash.
    seed: u64,

    /// How many keys the filter was built from.
    len: usize,
}

impl Bloom001 {
    /// Custom header slot carrying the hash count.
    ///
    /// The shared [`Header`] has no field for it: how many probes a filter
    /// makes per key is a Bloom concept, not one every implementation has.
    /// Named rather than written as `0` at both ends so the encoder and decoder
    /// cannot disagree.
    ///
    /// Public because it is part of the encoding: a reader inspecting
    /// `bloom_001` bytes needs to know which slot to look in.
    pub const HASH_COUNT_SLOT: usize = 0;

    /// Builds a Bloom filter over `keys`.
    ///
    /// The filter is sized from `params.expected_items` or the actual key
    /// count, whichever is larger, so that passing more keys than expected
    /// degrades the false positive rate gracefully instead of catastrophically.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidParameter`] if `params.false_positive_rate` is
    /// outside the open range `0.0..1.0`.
    ///
    /// # Examples
    ///
    /// ```
    /// use dmc_bloom::Bloom001;
    /// use dmc_core::{Filter, Params};
    ///
    /// let keys: Vec<&[u8]> = vec![b"key"];
    /// let filter = Bloom001::build(&keys, &Params::new(1, 0.01))?;
    /// assert_eq!(filter.len(), 1);
    /// # Ok::<(), dmc_core::Error>(())
    /// ```
    pub fn build(keys: &[&[u8]], params: &Params) -> Result<Self> {
        params.validate()?;

        let n = params.expected_items.max(keys.len());
        let (bit_count, hash_count) = optimal_sizing(n, params.false_positive_rate);

        let word_count = bit_count.div_ceil(BITS_PER_WORD);
        let mut filter = Self {
            bits: vec![0; word_count],
            bit_count,
            hash_count,
            seed: params.seed,
            len: keys.len(),
        };

        for key in keys {
            filter.insert(key);
        }

        Ok(filter)
    }

    /// Sets the bits for `key`.
    ///
    /// Private because the public API builds from a complete key set; a filter
    /// that grows after construction cannot keep `len` honest without also
    /// tracking distinctness.
    fn insert(&mut self, key: &[u8]) {
        // Read the shape into locals first: holding a borrow of `self` through
        // the loop would conflict with mutating `self.bits` inside it.
        let (bit_count, hash_count, seed) = (self.bit_count, self.hash_count, self.seed);

        for bit in probes(key, seed, hash_count, bit_count) {
            self.bits[bit / BITS_PER_WORD] |= 1u64 << (bit % BITS_PER_WORD);
        }
    }

    /// Yields the bit positions that `key` maps to under this filter's shape.
    fn probes_for(&self, key: &[u8]) -> impl Iterator<Item = usize> {
        probes(key, self.seed, self.hash_count, self.bit_count)
    }

    /// Returns how many bits the filter addresses.
    ///
    /// Part of the filter's shape: two filters combine under a set operation
    /// only if this matches. See [`is_compatible_with`](Bloom001::is_compatible_with).
    ///
    /// # Examples
    ///
    /// ```
    /// use dmc_bloom::Bloom001;
    /// use dmc_core::Params;
    ///
    /// let filter = Bloom001::build(&[b"key"], &Params::new(1_000, 0.01))?;
    /// assert!(filter.bit_count() > 0);
    /// # Ok::<(), dmc_core::Error>(())
    /// ```
    #[must_use]
    pub const fn bit_count(&self) -> usize {
        self.bit_count
    }

    /// Returns how many hash functions each key is probed through.
    ///
    /// Part of the filter's shape; see [`bit_count`](Bloom001::bit_count).
    ///
    /// # Examples
    ///
    /// ```
    /// use dmc_bloom::Bloom001;
    /// use dmc_core::Params;
    ///
    /// let filter = Bloom001::build(&[b"key"], &Params::new(1_000, 0.01))?;
    /// assert!(filter.hash_count() >= 1);
    /// # Ok::<(), dmc_core::Error>(())
    /// ```
    #[must_use]
    pub const fn hash_count(&self) -> u32 {
        self.hash_count
    }

    /// Returns the seed the filter hashes with.
    ///
    /// Part of the filter's shape, and the easiest of the three to get wrong:
    /// two filters can agree on size and hash count while a differing seed
    /// sends every key to different bits.
    ///
    /// # Examples
    ///
    /// ```
    /// use dmc_bloom::Bloom001;
    /// use dmc_core::Params;
    ///
    /// let filter = Bloom001::build(&[b"key"], &Params::new(10, 0.01).with_seed(7))?;
    /// assert_eq!(filter.seed(), 7);
    /// # Ok::<(), dmc_core::Error>(())
    /// ```
    #[must_use]
    pub const fn seed(&self) -> u64 {
        self.seed
    }

    /// Borrows the backing store as 64-bit words.
    ///
    /// Crate-internal: the set operations in [`ops`](crate::ops) work word-wise
    /// over this, and exposing a raw bit array publicly would invite callers to
    /// combine filters without the shape check that makes the result sound.
    pub(crate) fn words(&self) -> &[u64] {
        &self.bits
    }

    /// Mutably borrows the backing store as 64-bit words.
    ///
    /// Crate-internal for the reason given on [`words`](Bloom001::words), and
    /// more so here: writing arbitrary bits into a filter can only introduce
    /// false positives or, worse, clear a member's bits.
    pub(crate) fn words_mut(&mut self) -> &mut [u64] {
        &mut self.bits
    }

    /// Overwrites the recorded key count.
    ///
    /// Crate-internal, used by the set operations to replace the count
    /// inherited from the left-hand input with an estimate that describes what
    /// the combined filter actually holds.
    pub(crate) fn set_len(&mut self, len: usize) {
        self.len = len;
    }

    /// Builds a filter and boxes it for the registry.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`Bloom001::build`].
    pub fn build_boxed(keys: &[&[u8]], params: &Params) -> Result<Box<dyn Filter>> {
        Ok(Box::new(Self::build(keys, params)?))
    }

    /// Decodes a filter from a complete encoding and boxes it.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`Bloom001::decode`].
    pub fn decode_boxed(bytes: &[u8]) -> Result<Box<dyn Filter>> {
        Ok(Box::new(Self::decode(bytes)?))
    }

    /// Decodes a filter from a complete encoding, [`Header`] included.
    ///
    /// The shared header carries the seed, the key count, and the bit count as
    /// its capacity; the hash count rides in custom slot
    /// [`HASH_COUNT_SLOT`](Bloom001::HASH_COUNT_SLOT). Everything after the
    /// header is the bit array, little-endian, one `u64` per word.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Corrupt`] if the header is malformed (see
    /// [`Header::decode`]), if the encoding does not name `bloom_001`, if the
    /// declared bit or hash count is out of range, or if the words present
    /// disagree with the declared bit count.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (header, word_bytes) = Header::decode(bytes)?;

        // The registry routes on these before calling here, but `decode` is
        // also public: a caller reaching it directly must not be able to load
        // another family's bytes into a Bloom filter.
        if header.family_code != FAMILY_CODE || header.version != VERSION {
            return Err(Error::Corrupt {
                expected: "an encoding produced by bloom_001",
            });
        }

        if header.payload_version != PAYLOAD_VERSION {
            return Err(Error::Corrupt {
                expected: "bloom_001 payload version 1",
            });
        }

        // `Header::decode` rejects a zero capacity and bounds `len` by it. The
        // ceiling is this implementation's own, so it is checked here: a bit
        // count near u64::MAX would overflow the div_ceil below.
        if header.capacity > MAX_BITS as u64 {
            return Err(Error::Corrupt {
                expected: "a bit count no larger than MAX_BITS",
            });
        }

        let hash_count =
            u32::try_from(header.custom[Self::HASH_COUNT_SLOT]).map_err(|_| Error::Corrupt {
                expected: "a hash count between 1 and MAX_HASHES",
            })?;

        if hash_count == 0 || hash_count > MAX_HASHES {
            return Err(Error::Corrupt {
                expected: "a hash count between 1 and MAX_HASHES",
            });
        }

        // Bounded by MAX_BITS above, so this cast cannot truncate.
        #[allow(clippy::cast_possible_truncation)]
        let bit_count = header.capacity as usize;

        if word_bytes.len() % 8 != 0 {
            return Err(Error::Corrupt {
                expected: "a whole number of 64-bit words",
            });
        }

        if word_bytes.len() / 8 != bit_count.div_ceil(BITS_PER_WORD) {
            return Err(Error::Corrupt {
                expected: "a word count matching the declared bit count",
            });
        }

        let words: Vec<u64> = word_bytes
            .chunks_exact(8)
            .map(|c| u64::from_le_bytes(read_array::<8>(c).unwrap_or([0; 8])))
            .collect();

        // `Header::decode` has already bounded this by the capacity, which is
        // the bit count, so the only failure left is a 32-bit target where a
        // legitimately-built count cannot be represented.
        let len = usize::try_from(header.len).map_err(|_| Error::Corrupt {
            expected: "a key count representable on this target",
        })?;

        Ok(Self {
            bits: words,
            bit_count,
            hash_count,
            seed: header.seed,
            len,
        })
    }

    /// Builds the header for this filter's current state.
    ///
    /// Shared by [`encode`](Filter::encode) and the round-trip tests, so that a
    /// field added to the header cannot be written by one and forgotten by the
    /// other.
    fn header(&self) -> Header {
        Header::new(
            FAMILY_CODE,
            VERSION,
            PAYLOAD_VERSION,
            self.seed,
            self.len as u64,
            self.bit_count as u64,
        )
        .with_custom(Self::HASH_COUNT_SLOT, u64::from(self.hash_count))
    }
}

/// Yields the `hash_count` bit positions that `key` maps to.
///
/// Uses Kirsch-Mitzenmacher double hashing: two hashes generate `k` positions
/// as `h1 + i*h2`, which performs as well as `k` independent hashes while
/// costing two. `h2` is forced odd so that it shares no factor with a
/// power-of-two `bit_count`, which would otherwise let the probe sequence fall
/// into a short cycle and revisit the same handful of bits.
fn probes(key: &[u8], seed: u64, hash_count: u32, bit_count: usize) -> impl Iterator<Item = usize> {
    let h1 = hash64(key, seed);
    let h2 = mix(h1 ^ seed.rotate_left(32)) | 1;

    let modulus = bit_count as u64;

    (0..hash_count).map(move |i| {
        let combined = h1.wrapping_add(u64::from(i).wrapping_mul(h2));

        // `combined % modulus` is strictly less than `modulus`, which came
        // from a usize, so the cast back is exact on every target. Done with a
        // u64 modulo rather than a checked conversion because this runs once
        // per probe on every lookup.
        //
        // `bit_count` is non-zero: the builder floors it at BITS_PER_WORD and
        // the decoder rejects a zero bit count.
        #[allow(clippy::cast_possible_truncation)]
        let bit = (combined % modulus) as usize;
        bit
    })
}

/// Reads a fixed-size array from a slice, reporting truncation as corruption.
fn read_array<const N: usize>(slice: &[u8]) -> Result<[u8; N]> {
    slice.try_into().map_err(|_| Error::Corrupt {
        expected: "a complete fixed-width field",
    })
}

/// Computes the optimal bit count and hash count for `n` items at rate `p`.
///
/// Returns at least one bit and one hash so that an empty filter is still
/// well-formed and `contains` never divides by zero.
fn optimal_sizing(n: usize, p: f64) -> (usize, u32) {
    if n == 0 {
        return (BITS_PER_WORD, 1);
    }

    // Precision: `n` beyond 2^53 loses exactness in f64, but a filter that
    // large is far past what fits in memory anyway, and MAX_BITS clamps below
    // that point.
    let n_f = n as f64;
    let ln2 = core::f64::consts::LN_2;

    // m = -n ln(p) / (ln 2)^2
    let bits = (-n_f * p.ln() / (ln2 * ln2)).ceil();

    // Clamp before converting: an extreme `p` makes `bits` exceed usize, and
    // an unclamped cast would ask the allocator for a hopeless amount and
    // abort the process rather than return.
    let bit_count = if bits.is_finite() && bits > 0.0 {
        // Saturating: values above MAX_BITS land on MAX_BITS.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let clamped = bits.min(MAX_BITS as f64) as usize;
        clamped.max(BITS_PER_WORD)
    } else {
        BITS_PER_WORD
    };

    // k = (m/n) ln 2
    let hashes = ((bit_count as f64 / n_f) * ln2).round();

    // `hashes` is non-negative and bounded by MAX_BITS/n, so the clamp keeps
    // the cast in range.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let hash_count = (hashes.clamp(1.0, f64::from(MAX_HASHES)) as u32).clamp(1, MAX_HASHES);

    (bit_count, hash_count)
}

impl Filter for Bloom001 {
    fn id(&self) -> &'static str {
        dmc_core::filter_id!("bloom", 1)
    }

    fn contains(&self, key: &[u8]) -> bool {
        self.probes_for(key)
            .all(|bit| self.bits[bit / BITS_PER_WORD] & (1u64 << (bit % BITS_PER_WORD)) != 0)
    }

    fn len(&self) -> usize {
        self.len
    }

    fn memory_bytes(&self) -> usize {
        self.bits.len() * core::mem::size_of::<u64>()
    }

    /// Estimates the rate from the filter's actual fill.
    ///
    /// `p = (X/m)^k`, where `X` is the number of bits set: a probe reports a
    /// false positive when all `k` of its bits happen to be set, and the chance
    /// of any one being set is the fill ratio.
    ///
    /// Measured rather than predicted from the key count via
    /// `(1 - e^(-kn/m))^k`. The two agree for a freshly built filter, but only
    /// the measured form stays right after a [`union`](Bloom001::union) or an
    /// [`intersect`](Bloom001::intersect), where the recorded key count no
    /// longer determines how full the filter is. An intersection in particular
    /// runs denser than its key count implies, and predicting from that count
    /// would understate its rate — which is the one direction a filter must not
    /// be wrong in.
    fn false_positive_rate(&self) -> f64 {
        let set: usize = self.bits.iter().map(|w| w.count_ones() as usize).sum();

        if set == 0 {
            return 0.0;
        }

        let k = f64::from(self.hash_count);
        let fill = set as f64 / self.bit_count as f64;

        fill.powf(k)
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        // `encode` appends, so the caller's buffer may already hold something.
        // Remember where this filter starts, since `finalize` checksums from
        // there rather than from the front of the buffer.
        let start = out.len();

        self.header().encode(out);

        for word in &self.bits {
            out.extend_from_slice(&word.to_le_bytes());
        }

        // Must be last: the checksum covers the body, which did not exist when
        // the header went out. Without this the encoding carries a zeroed
        // checksum field and will not decode.
        Header::finalize(out, start);

        Ok(())
    }
}

dmc_core::register_filter! {
    family: "bloom",
    version: 1,
    id: "bloom_001",
    description: "Classic Bloom filter with Kirsch-Mitzenmacher double hashing.",
    // Bloom diverges from the strict default on nothing. Every axis is restated
    // here rather than left implicit, because the conformance suite turns each
    // one into a check and a reader should see why each holds:
    //
    // - tolerates_duplicate_keys / len_counts_duplicates: setting an
    //   already-set bit is a no-op, so a repeat is absorbed, and `len` still
    //   counts every key supplied.
    // - order_independent_construction: bit setting is commutative, so
    //   shuffling the input yields the same bit array.
    // - honors_target_fpr: sized from the request via `optimal_sizing`,
    //   subject to the MAX_BITS clamp at extreme requests.
    // - supports_deletion: clearing a key's bits would clear them for every
    //   key sharing one. A counting variant is a separate family, not
    //   bloom_002.
    // - is_adaptive: immutable once built; querying never writes.
    // - supports_union / supports_intersection: the backing store is a bit
    //   array, so both are pointwise bitwise operations between filters of
    //   matching shape; see `crate::ops`. Intersection is approximate — it
    //   keeps every shared key but reports a rate above either input's — which
    //   is a documented property of the operation, not a weaker claim here.
    // - estimates_cardinality: `estimated_len` inverts the fill ratio into a
    //   distinct key count, which is what keeps the accounting honest after a
    //   union, where `len` no longer describes what the filter holds.
    // - max_practical_keys: bounded only by MAX_BITS, which degrades the rate
    //   rather than failing, so no key count stops the filter working.
    capabilities: dmc_core::Capabilities::strict(),
    build: Bloom001::build_boxed,
    decode: Bloom001::decode_boxed,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(n: usize) -> Vec<Vec<u8>> {
        (0..n).map(|i| format!("key-{i}").into_bytes()).collect()
    }

    fn as_slices(owned: &[Vec<u8>]) -> Vec<&[u8]> {
        owned.iter().map(Vec::as_slice).collect()
    }

    #[test]
    fn every_inserted_key_is_found() {
        let owned = keys(1_000);
        let filter = Bloom001::build(&as_slices(&owned), &Params::new(1_000, 0.01)).unwrap();

        for key in &owned {
            assert!(filter.contains(key), "false negative for {key:?}");
        }
    }

    #[test]
    fn false_positive_rate_is_near_the_request() {
        let owned = keys(10_000);
        let filter = Bloom001::build(&as_slices(&owned), &Params::new(10_000, 0.01)).unwrap();

        let false_positives = (0..10_000)
            .map(|i| format!("absent-{i}").into_bytes())
            .filter(|k| filter.contains(k))
            .count();

        let observed = false_positives as f64 / 10_000.0;
        // Allow generous slack; this catches a broken filter, not a mildly
        // mistuned one.
        assert!(
            observed < 0.03,
            "observed false positive rate {observed} far above the 0.01 request"
        );
    }

    #[test]
    fn reported_rate_tracks_the_request() {
        let owned = keys(1_000);
        let filter = Bloom001::build(&as_slices(&owned), &Params::new(1_000, 0.01)).unwrap();
        let reported = filter.false_positive_rate();

        assert!(
            reported > 0.001 && reported < 0.05,
            "reported rate {reported} implausible for a 0.01 request"
        );
    }

    #[test]
    fn tighter_rate_costs_more_memory() {
        let owned = keys(1_000);
        let loose = Bloom001::build(&as_slices(&owned), &Params::new(1_000, 0.1)).unwrap();
        let tight = Bloom001::build(&as_slices(&owned), &Params::new(1_000, 0.0001)).unwrap();

        assert!(tight.memory_bytes() > loose.memory_bytes());
    }

    #[test]
    fn rejects_out_of_range_false_positive_rate() {
        let owned = keys(1);
        assert!(Bloom001::build(&as_slices(&owned), &Params::new(1, 0.0)).is_err());
        assert!(Bloom001::build(&as_slices(&owned), &Params::new(1, 1.0)).is_err());
        assert!(Bloom001::build(&as_slices(&owned), &Params::new(1, f64::NAN)).is_err());
    }

    #[test]
    fn empty_key_set_builds_and_finds_nothing() {
        let filter = Bloom001::build(&[], &Params::new(0, 0.01)).unwrap();

        assert!(filter.is_empty());
        assert!(!filter.contains(b"anything"));
        assert_eq!(filter.false_positive_rate(), 0.0);
    }

    #[test]
    fn duplicate_keys_are_harmless() {
        let owned = vec![b"same".to_vec(), b"same".to_vec(), b"same".to_vec()];
        let filter = Bloom001::build(&as_slices(&owned), &Params::new(3, 0.01)).unwrap();

        assert!(filter.contains(b"same"));
        assert_eq!(filter.len(), 3);
    }

    #[test]
    fn empty_key_is_a_valid_member() {
        let owned = vec![Vec::new()];
        let filter = Bloom001::build(&as_slices(&owned), &Params::new(1, 0.01)).unwrap();

        assert!(filter.contains(b""));
    }

    #[test]
    fn seed_changes_which_keys_collide() {
        let owned = keys(100);
        let a = Bloom001::build(&as_slices(&owned), &Params::new(100, 0.01).with_seed(1)).unwrap();
        let b = Bloom001::build(&as_slices(&owned), &Params::new(100, 0.01).with_seed(2)).unwrap();

        assert_ne!(a.bits, b.bits, "different seeds produced identical filters");
    }

    #[test]
    fn same_seed_reproduces_the_filter() {
        let owned = keys(100);
        let params = Params::new(100, 0.01).with_seed(7);
        let a = Bloom001::build(&as_slices(&owned), &params).unwrap();
        let b = Bloom001::build(&as_slices(&owned), &params).unwrap();

        assert_eq!(a, b);
    }

    #[test]
    fn round_trips_through_encoding() {
        let owned = keys(500);
        let filter = Bloom001::build(&as_slices(&owned), &Params::new(500, 0.01)).unwrap();

        let mut bytes = Vec::new();
        filter.encode(&mut bytes).unwrap();

        let decoded = Bloom001::decode(&bytes).unwrap();

        assert_eq!(filter, decoded);
        for key in &owned {
            assert!(decoded.contains(key));
        }
    }

    #[test]
    fn rejects_truncated_payload() {
        let payload = sample_payload();

        assert!(Bloom001::decode(&payload[..payload.len() - 4]).is_err());
        assert!(Bloom001::decode(&[]).is_err());
    }

    /// Returns a complete, decodable encoding of a small filter.
    ///
    /// Includes the shared [`Header`]; the offset constants below index into
    /// it, so a header layout change breaks these tests loudly rather than
    /// letting them poke at the wrong fields.
    fn sample_payload() -> Vec<u8> {
        let filter = Bloom001::build(&[b"x"], &Params::new(1, 0.01)).unwrap();
        let mut bytes = Vec::new();
        filter.encode(&mut bytes).unwrap();
        bytes
    }

    /// Re-checksums a payload after a test has edited a field in it.
    ///
    /// Without this, every corruption test below would be answered by the
    /// header's integrity check rather than by the field bound it names — the
    /// tests would still pass, and would stop testing anything. Re-finalizing
    /// makes each edit look like a filter that was legitimately written with
    /// that value, which is the case each test is actually about.
    ///
    /// The exception is the checksum test itself, which edits a byte and
    /// deliberately does not call this.
    fn rechecksum(payload: &mut [u8]) {
        Header::finalize(payload, 0);
    }

    /// Byte range of the header's `len` field, per the `Header` layout table.
    const LEN_AT: core::ops::Range<usize> = 17..25;

    /// Byte range of the header's `capacity` field, which bloom uses for its
    /// bit count.
    const CAPACITY_AT: core::ops::Range<usize> = 25..33;

    /// Byte range of custom slot 0, which bloom uses for its hash count.
    const HASH_COUNT_AT: core::ops::Range<usize> = 33..41;

    #[test]
    fn rejects_absurd_declared_bit_count() {
        // A corrupt bit count must not reach the arithmetic that derives the
        // word count from it.
        let mut payload = sample_payload();
        payload[CAPACITY_AT].copy_from_slice(&u64::MAX.to_le_bytes());
        rechecksum(&mut payload);

        assert!(Bloom001::decode(&payload).is_err());
    }

    #[test]
    fn rejects_zero_declared_bit_count() {
        // Rejected by the shared header, which treats a zero capacity as
        // corrupt for every implementation.
        let mut payload = sample_payload();
        payload[CAPACITY_AT].copy_from_slice(&0u64.to_le_bytes());
        rechecksum(&mut payload);

        assert!(Bloom001::decode(&payload).is_err());
    }

    #[test]
    fn rejects_absurd_declared_hash_count() {
        let mut payload = sample_payload();
        payload[HASH_COUNT_AT].copy_from_slice(&u64::MAX.to_le_bytes());
        rechecksum(&mut payload);

        assert!(Bloom001::decode(&payload).is_err());
    }

    #[test]
    fn rejects_zero_declared_hash_count() {
        // The shared header does not validate custom slots, so this bound is
        // this implementation's to enforce.
        let mut payload = sample_payload();
        payload[HASH_COUNT_AT].copy_from_slice(&0u64.to_le_bytes());
        rechecksum(&mut payload);

        assert!(Bloom001::decode(&payload).is_err());
    }

    #[test]
    fn rejects_word_count_disagreeing_with_bit_count() {
        let mut payload = sample_payload();
        // Claim twice the bits without supplying the words for them. The key
        // count must stay within the new capacity or the header rejects it
        // first, which would pass this test for the wrong reason.
        let declared = u64::from_le_bytes(payload[CAPACITY_AT].try_into().unwrap());
        payload[CAPACITY_AT].copy_from_slice(&(declared * 2).to_le_bytes());
        rechecksum(&mut payload);

        assert!(Bloom001::decode(&payload).is_err());
    }

    #[test]
    fn rejects_a_key_count_larger_than_the_bit_count() {
        // `usize::try_from` alone only rejects counts that overflow a 32-bit
        // usize. On a 64-bit target u64::MAX passed straight through, decoding
        // into a filter that claimed eighteen quintillion keys in an eight-byte
        // array. Found by the correctness suite; see plan step 050.020.100.
        //
        // Now caught by the shared header's `len <= capacity` check, which is
        // where the bound belongs: it holds for every implementation.
        let mut payload = sample_payload();
        payload[LEN_AT].copy_from_slice(&u64::MAX.to_le_bytes());
        rechecksum(&mut payload);

        assert!(Bloom001::decode(&payload).is_err());
    }

    #[test]
    fn accepts_a_key_count_up_to_the_bit_count() {
        // The bound is inclusive: one key per bit is useless but honest, and
        // rejecting it would reject filters that were legitimately built.
        let mut payload = sample_payload();
        let declared_bits = u64::from_le_bytes(payload[CAPACITY_AT].try_into().unwrap());
        payload[LEN_AT].copy_from_slice(&declared_bits.to_le_bytes());
        rechecksum(&mut payload);

        let decoded = Bloom001::decode(&payload).expect("len == bit_count is legal");
        assert_eq!(decoded.len() as u64, declared_bits);
    }

    #[test]
    fn rejects_a_flipped_seed_bit() {
        // The gap the checksum exists to close. Every structural check passes a
        // corrupted seed: the family, version, payload version, capacity, and
        // key count all validate. What decodes is a filter that hashes keys to
        // different bits than the one that was written, so it answers `false`
        // for keys that were inserted.
        //
        // Before the checksum, all eight seed bytes were corruptible without
        // detection. Verified here byte by byte rather than at one offset,
        // since a checksum that covered only part of the field would still pass
        // a single-offset test.
        const SEED_AT: core::ops::Range<usize> = 9..17;

        for offset in SEED_AT {
            let mut payload = sample_payload();
            payload[offset] ^= 0x01;

            // Deliberately not re-checksummed: that is the point.
            assert!(
                Bloom001::decode(&payload).is_err(),
                "a flipped bit in seed byte {offset} decoded cleanly"
            );
        }
    }

    #[test]
    fn rejects_a_flipped_bit_anywhere_in_the_encoding() {
        // The checksum covers the body too, not only the header. A cleared bit
        // in the bit array yields a valid encoding of a smaller key set, which
        // no amount of checking can repair — but it can be refused, which is
        // the difference between a filter that fails to load and one that
        // silently loses members.
        let filter =
            Bloom001::build(&[b"alice", b"bob", b"carol"], &Params::new(64, 0.01)).unwrap();
        let mut encoded = Vec::new();
        filter.encode(&mut encoded).unwrap();

        for offset in 0..encoded.len() {
            let mut corrupted = encoded.clone();
            corrupted[offset] ^= 0x01;

            assert!(
                Bloom001::decode(&corrupted).is_err(),
                "a flipped bit at offset {offset} of {} decoded cleanly",
                encoded.len()
            );
        }
    }

    #[test]
    fn an_unfinalized_encoding_does_not_decode() {
        // `encode` writes a zeroed checksum placeholder that `finalize` fills
        // in. An implementation that forgets the second step produces bytes
        // that fail to load, which is how it finds out.
        // Built from a real encoding so that every field but the checksum is
        // exactly what a legitimate writer would produce; only the finalize
        // step is skipped.
        let mut bytes = sample_payload();
        bytes[Header::CHECKSUM_OFFSET..Header::CHECKSUM_OFFSET + 4]
            .copy_from_slice(&0u32.to_le_bytes());

        assert!(
            Bloom001::decode(&bytes).is_err(),
            "an encoding with a zeroed checksum placeholder should not decode"
        );

        // The same bytes, finalized, decode.
        Header::finalize(&mut bytes, 0);
        assert!(Bloom001::decode(&bytes).is_ok());
    }

    #[test]
    fn rejects_unknown_payload_version() {
        let mut payload = sample_payload();
        // Offset 8 in the shared header layout.
        payload[8] = 99;
        rechecksum(&mut payload);

        assert!(Bloom001::decode(&payload).is_err());
    }

    #[test]
    fn rejects_another_familys_encoding() {
        // `decode` is public, so it must not load bytes that the registry
        // would have routed elsewhere. Claim a different family, leaving every
        // other field intact.
        let mut payload = sample_payload();
        payload[0..4].copy_from_slice(&(FAMILY_CODE + 1).to_le_bytes());
        rechecksum(&mut payload);

        assert!(Bloom001::decode(&payload).is_err());
    }

    #[test]
    fn rejects_another_version_of_this_family() {
        // The frozen-implementation promise: bloom_002's bytes must not decode
        // here even though the family matches.
        let mut payload = sample_payload();
        payload[4..8].copy_from_slice(&(VERSION + 1).to_le_bytes());
        rechecksum(&mut payload);

        assert!(Bloom001::decode(&payload).is_err());
    }

    #[test]
    fn the_header_names_this_implementation() {
        let payload = sample_payload();
        let (header, _) = Header::decode(&payload).unwrap();

        assert_eq!(header.family_code, FAMILY_CODE);
        assert_eq!(header.version, VERSION);
        assert_eq!(header.family(), Some(FAMILY));
        assert_eq!(header.payload_version, PAYLOAD_VERSION);
    }

    #[test]
    fn hash_count_is_bounded() {
        // An extreme false positive request must not produce thousands of probes.
        let (_, hash_count) = optimal_sizing(10, 1e-300);
        assert!(hash_count <= MAX_HASHES);
    }

    #[test]
    fn bit_count_is_bounded_for_extreme_requests() {
        // Without a ceiling this sizing would ask for an allocation that
        // aborts the process rather than returning an error.
        let (bit_count, _) = optimal_sizing(usize::MAX / 2, 1e-300);
        assert!(
            bit_count <= MAX_BITS,
            "bit count {bit_count} exceeds the cap"
        );
    }

    #[test]
    fn extreme_request_builds_instead_of_aborting() {
        let owned = keys(4);
        let filter = Bloom001::build(&as_slices(&owned), &Params::new(1_000_000, 1e-300)).unwrap();

        // Clamped, so it cannot honor the request; it must still be correct.
        for key in &owned {
            assert!(filter.contains(key));
        }
    }

    #[test]
    fn sizing_is_sane_for_a_single_key() {
        let (bit_count, hash_count) = optimal_sizing(1, 0.01);
        assert!(bit_count >= BITS_PER_WORD);
        assert!(hash_count >= 1);
    }
}
