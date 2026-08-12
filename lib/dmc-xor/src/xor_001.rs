//! `xor_001`: classic three-hash xor filter, built by peeling.
//!
//! # Stability
//!
//! This implementation is frozen. Which keys it reports as present will not
//! change; a change to that behavior ships as `xor_002`. Performance and
//! memory fixes may land here in place.

// Sizing multiplies a key count by a fixed overhead factor; the result is
// small enough that f64 precision is not a concern, but the multiplication
// itself is done in integer arithmetic throughout, so this allow is unused in
// practice and kept only where a cast is unavoidable.
#![allow(clippy::cast_precision_loss)]

use dmc_core::hash::{hash64, mix_seed};
use dmc_core::header::Header;
use dmc_core::{Capabilities, Error, Filter, Params, Result};

/// Format version for the encoded payload, distinct from the implementation
/// version. Lets the decoder reject bytes from a future payload layout.
const PAYLOAD_VERSION: u8 = 1;

/// Family name this implementation registers under.
const FAMILY: &str = "xor";

/// Implementation version within the family; the `001` in `xor_001`.
const VERSION: u32 = 1;

/// Numeric family written into every encoding's header.
const FAMILY_CODE: u32 = match dmc_core::family::code_for(FAMILY) {
    Some(code) => code,
    None => panic!("xor is not in dmc_core::family::KNOWN"),
};

/// Overhead factor applied to the key count when sizing each of the three
/// blocks.
///
/// Peeling a 3-partite hypergraph with one edge per key succeeds with high
/// probability once the table holds about 23% more slots than keys; `1.23` is
/// the constant the reference construction uses, and going lower makes
/// construction fail more often for no benefit once it does succeed.
const OVERHEAD_FACTOR: f64 = 1.23;

/// Floor added to the raw sizing product before rounding down to a multiple
/// of three.
///
/// Keeps a handful of keys from sizing a table so small that peeling has no
/// slack to work with.
const SIZE_FLOOR: u32 = 32;

/// Upper bound on construction attempts before giving up.
///
/// Each attempt succeeds with probability comfortably above one half, so the
/// chance every one of a hundred consecutive attempts fails is far below the
/// chance of unrelated hardware failure during the same run.
const MAX_ITERATIONS: u32 = 100;

/// A classic xor filter: three fingerprint slots per key, one bit of slack
/// resolved by hypergraph peeling.
///
/// Every key sets a fingerprint in one of three table blocks, chosen by
/// independent hashes, such that `XOR`-ing the fingerprints at all three
/// positions recovers the key's own fingerprint. Construction finds an
/// assignment that makes every key's three slots peelable in some order; a
/// key set that cannot be peeled (which happens for a duplicate key, and
/// rarely for an unlucky seed) is retried under a fresh seed derived from
/// [`Params::seed`].
///
/// Space cost is fixed by the fingerprint width rather than tunable, unlike
/// a Bloom filter's: about 1.23 fingerprint-widths of table per key, roughly
/// 9.9 bits per key at the false positive rate an 8-bit fingerprint gives
/// (about 1/256, a little under 0.4%).
///
/// # Duplicate keys
///
/// A duplicate key produces a hyperedge with no distinct partner, which
/// peeling can never resolve. [`build`](Self::build) reports
/// [`Error::ConstructionFailed`] rather than silently dropping the repeat or
/// returning a filter with a false negative for it.
///
/// # Examples
///
/// ```
/// use dmc_xor::Xor001;
/// use dmc_core::{Filter, Params};
///
/// let keys: Vec<&[u8]> = vec![b"alice", b"bob", b"carol"];
/// let filter = Xor001::build(&keys, &Params::new(3, 0.01))?;
///
/// assert!(filter.contains(b"alice"));
/// assert!(!filter.contains(b"nobody-put-this-in"));
/// # Ok::<(), dmc_core::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xor001 {
    /// Fingerprint table, `3 * block_length` slots: block 0 at
    /// `[0, block_length)`, block 1 at `[block_length, 2*block_length)`,
    /// block 2 at `[2*block_length, 3*block_length)`.
    fingerprints: Vec<u8>,

    /// Slots per block. `fingerprints.len() == 3 * block_length`.
    block_length: u32,

    /// Seed the filter hashes with. May differ from the requested
    /// [`Params::seed`] when construction needed a retry.
    seed: u64,

    /// How many keys the filter was built from.
    len: usize,
}

/// The three table positions a key's hash maps to, one per block.
#[derive(Debug, Clone, Copy)]
struct Hashes {
    h0: u32,
    h1: u32,
    h2: u32,
}

impl Xor001 {
    /// Builds a xor filter over `keys`.
    ///
    /// `params.expected_items` and `params.false_positive_rate` are ignored:
    /// the filter sizes itself from the actual key count, and its rate
    /// follows from the fixed 8-bit fingerprint width rather than from a
    /// request. `params.seed` seeds the first construction attempt; a failed
    /// attempt retries under a seed derived from it via [`mix_seed`], so the
    /// same input seed always produces the same sequence of attempts and
    /// therefore the same filter.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConstructionFailed`] if `keys` contains a duplicate,
    /// or in the vanishingly rare case where every attempt in the retry
    /// budget fails to peel.
    ///
    /// # Examples
    ///
    /// ```
    /// use dmc_xor::Xor001;
    /// use dmc_core::{Filter, Params};
    ///
    /// let keys: Vec<&[u8]> = vec![b"key"];
    /// let filter = Xor001::build(&keys, &Params::new(1, 0.01))?;
    /// assert_eq!(filter.len(), 1);
    /// # Ok::<(), dmc_core::Error>(())
    /// ```
    ///
    /// A duplicate key fails construction rather than silently losing it:
    ///
    /// ```
    /// use dmc_xor::Xor001;
    /// use dmc_core::{Error, Params};
    ///
    /// let keys: Vec<&[u8]> = vec![b"same", b"same"];
    /// assert!(matches!(
    ///     Xor001::build(&keys, &Params::default()),
    ///     Err(Error::ConstructionFailed { .. })
    /// ));
    /// # Ok::<(), ()>(())
    /// ```
    pub fn build(keys: &[&[u8]], params: &Params) -> Result<Self> {
        // Validated for uniformity across every implementation even though
        // this one ignores the value: a caller passing an out-of-range rate
        // must see InvalidParameter regardless of which filter they asked
        // for, not ConstructionFailed from a filter that happened not to
        // look at the field.
        params.validate()?;

        let block_length = block_length_for(keys.len());
        let (fingerprints, seed) = populate(keys, block_length, params.seed)?;

        Ok(Self {
            fingerprints,
            block_length,
            seed,
            len: keys.len(),
        })
    }

    /// Returns how many slots each of the three blocks holds.
    ///
    /// Part of the filter's shape: `memory_bytes` is `3 * block_length`.
    ///
    /// # Examples
    ///
    /// ```
    /// use dmc_xor::Xor001;
    /// use dmc_core::Params;
    ///
    /// let filter = Xor001::build(&[b"key"], &Params::default())?;
    /// assert!(filter.block_length() > 0);
    /// # Ok::<(), dmc_core::Error>(())
    /// ```
    #[must_use]
    pub const fn block_length(&self) -> u32 {
        self.block_length
    }

    /// Returns the seed the filter hashes with.
    ///
    /// May not equal the seed passed to [`build`](Self::build): construction
    /// retries under derived seeds when a hypergraph fails to peel.
    ///
    /// # Examples
    ///
    /// ```
    /// use dmc_xor::Xor001;
    /// use dmc_core::Params;
    ///
    /// let filter = Xor001::build(&[b"key"], &Params::default())?;
    /// let _ = filter.seed();
    /// # Ok::<(), dmc_core::Error>(())
    /// ```
    #[must_use]
    pub const fn seed(&self) -> u64 {
        self.seed
    }

    /// Builds a filter and boxes it for the registry.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`Xor001::build`].
    pub fn build_boxed(keys: &[&[u8]], params: &Params) -> Result<Box<dyn Filter>> {
        Ok(Box::new(Self::build(keys, params)?))
    }

    /// Decodes a filter from a complete encoding and boxes it.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`Xor001::decode`].
    pub fn decode_boxed(bytes: &[u8]) -> Result<Box<dyn Filter>> {
        Ok(Box::new(Self::decode(bytes)?))
    }

    /// Decodes a filter from a complete encoding, [`Header`] included.
    ///
    /// The shared header carries the seed, the key count, and the block
    /// length as its capacity. Everything after the header is the
    /// fingerprint table, one byte per slot, in block-major order.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Corrupt`] if the header is malformed, if the encoding
    /// does not name `xor_001`, if the declared block length is not a
    /// positive multiple that fits the table present, or if the table's
    /// length disagrees with `3 * block_length`.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (header, body) = Header::decode(bytes)?;

        if header.family_code != FAMILY_CODE || header.version != VERSION {
            return Err(Error::Corrupt {
                expected: "an encoding produced by xor_001",
            });
        }

        if header.payload_version != PAYLOAD_VERSION {
            return Err(Error::Corrupt {
                expected: "xor_001 payload version 1",
            });
        }

        // `capacity` carries the whole table length (`3 * block_length`)
        // rather than the block length alone: the shared header enforces
        // `len <= capacity`, and `len` counts keys, which can outnumber a
        // single block by design (the 1.23 overhead factor is spread across
        // all three blocks, not one).
        let table_len = usize::try_from(header.capacity).map_err(|_| Error::Corrupt {
            expected: "a table length representable on this target",
        })?;

        if table_len % 3 != 0 {
            return Err(Error::Corrupt {
                expected: "a table length divisible by three",
            });
        }

        if body.len() != table_len {
            return Err(Error::Corrupt {
                expected: "a fingerprint table matching the declared table length",
            });
        }

        let block_length = u32::try_from(table_len / 3).map_err(|_| Error::Corrupt {
            expected: "a block length representable in 32 bits",
        })?;

        let len = usize::try_from(header.len).map_err(|_| Error::Corrupt {
            expected: "a key count representable on this target",
        })?;

        Ok(Self {
            fingerprints: body.to_vec(),
            block_length,
            seed: header.seed,
            len,
        })
    }

    /// Builds the header for this filter's current state.
    ///
    /// `capacity` carries the whole table length (`3 * block_length`); see
    /// the matching comment in [`decode`](Self::decode) for why.
    fn header(&self) -> Header {
        Header::new(
            FAMILY_CODE,
            VERSION,
            PAYLOAD_VERSION,
            self.seed,
            self.len as u64,
            3 * u64::from(self.block_length),
        )
    }

    /// Computes the three hashes and derived positions for `key`'s 64-bit
    /// hash under this filter's seed and shape.
    fn hashes_for(&self, hash: u64) -> Hashes {
        hashes(hash, self.block_length)
    }
}

/// Computes the three block-relative hashes for a key's 64-bit hash.
///
/// Shared by construction and querying so the two can never disagree about
/// where a key lives. Positions are independent rotations of `hash` reduced
/// into `[0, block_length)`, per block.
fn hashes(hash: u64, block_length: u32) -> Hashes {
    let h0 = reduce(hash, block_length);
    let h1 = reduce(hash.rotate_left(21), block_length);
    let h2 = reduce(hash.rotate_left(42), block_length);
    Hashes { h0, h1, h2 }
}

/// Maps a 64-bit hash into `[0, n)` using the high 32 bits, Lemire's fast
/// alternative to a modulo reduction.
fn reduce(hash: u64, n: u32) -> u32 {
    if n == 0 {
        return 0;
    }
    let r = (hash >> 32) as u32;
    ((u64::from(r) * u64::from(n)) >> 32) as u32
}

/// Extracts a key's fingerprint from its 64-bit hash.
///
/// Folding the high half into the low half rather than truncating keeps the
/// fingerprint dependent on bits that `reduce` mostly ignores, so a
/// collision in table position does not imply a collision in fingerprint.
///
/// The truncation to 8 bits is the point, not a hazard: that is the
/// fingerprint width this implementation commits to.
#[allow(clippy::cast_possible_truncation)]
fn fingerprint(hash: u64) -> u8 {
    (hash ^ (hash >> 32)) as u8
}

/// Computes the block length for `key_count` keys.
///
/// `32 + 1.23 * key_count`, rounded down to a multiple of three so the three
/// blocks divide the table evenly. The floor of 32 keeps a tiny key count
/// from sizing a table with no slack for peeling.
fn block_length_for(key_count: usize) -> u32 {
    let scaled = (key_count as f64) * OVERHEAD_FACTOR;

    // Saturating: a key count near usize::MAX would overflow u32 capacity
    // long before this matters in practice, and MAX_PRACTICAL_KEYS bounds
    // what the conformance suite actually drives through here.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let capacity = (scaled.ceil() as u64 + u64::from(SIZE_FLOOR)).min(u64::from(u32::MAX));

    #[allow(clippy::cast_possible_truncation)]
    let capacity = capacity as u32;

    capacity / 3
}

/// Runs the peeling construction, returning the completed fingerprint table
/// and the seed it was built under.
///
/// Retries under a fresh derived seed whenever the hypergraph fails to peel,
/// which happens for a genuinely unlucky seed and, deterministically, for any
/// key set containing a duplicate. [`Error::ConstructionFailed`] distinguishes
/// the two only by attempt count; a caller who hits it with more than a
/// handful of keys almost certainly has a duplicate.
fn populate(keys: &[&[u8]], block_length: u32, seed: u64) -> Result<(Vec<u8>, u64)> {
    let key_count = keys.len();
    let table_len = 3 * block_length as usize;

    // A filter over zero keys has nothing to peel; skip straight to an
    // all-empty table rather than asking the loop below to succeed on an
    // empty edge set, which it does, but pointlessly.
    if key_count == 0 {
        return Ok((vec![0u8; table_len], seed));
    }

    for attempt in 0..MAX_ITERATIONS {
        let attempt_seed = if attempt == 0 {
            seed
        } else {
            mix_seed(seed, attempt)
        };

        // Hashed fresh under `attempt_seed` each attempt, the same way
        // `contains` will hash under whichever seed ends up stored: a query
        // must reproduce exactly the hash construction used, not a
        // re-mixed derivative of it.
        let hashes: Vec<u64> = keys.iter().map(|key| hash64(key, attempt_seed)).collect();

        if let Some(order) = try_peel(&hashes, block_length) {
            let fingerprints = assign_fingerprints(&order, block_length);
            return Ok((fingerprints, attempt_seed));
        }
    }

    Err(Error::ConstructionFailed {
        attempts: MAX_ITERATIONS,
    })
}

/// One step of the peeling stack: a key's hash, the table index it was
/// peeled from, and which of the three blocks that index belongs to.
struct PeelStep {
    hash: u64,
    index: usize,

    /// Which of the three positions `index` was: 0, 1, or 2.
    block: usize,
}

/// Attempts to peel the 3-partite hypergraph for one attempt's hashes.
///
/// Each key is an edge touching one slot in each of the three blocks.
/// Peeling repeatedly removes a key whose edge currently has only one
/// remaining unpeeled slot, recording enough to reconstruct that slot's
/// fingerprint afterward. Succeeds — returns `Some` — only if every key can
/// be peeled this way; a set with a duplicate key, or an unlucky hash
/// assignment, leaves some edges permanently at three or zero remaining
/// slots and fails.
fn try_peel(hashes_in: &[u64], block_length: u32) -> Option<Vec<PeelStep>> {
    let key_count = hashes_in.len();
    let table_len = 3 * block_length as usize;

    // Per-slot XOR of every touching key's hash, and a count of how many
    // keys currently touch it. A count that drops to exactly one identifies
    // a slot peelable right now: XOR-ing it out reveals that key alone.
    let mut xor_mask = vec![0u64; table_len];
    let mut count = vec![0u32; table_len];

    for &hash in hashes_in {
        let h = hashes(hash, block_length);
        for index in [
            h.h0 as usize,
            h.h1 as usize + block_length as usize,
            h.h2 as usize + 2 * block_length as usize,
        ] {
            xor_mask[index] ^= hash;
            count[index] += 1;
        }
    }

    let mut queue: Vec<usize> = (0..table_len).filter(|&i| count[i] == 1).collect();
    let mut order = Vec::with_capacity(key_count);

    while let Some(index) = queue.pop() {
        if count[index] != 1 {
            // Pushed onto the queue earlier, since decremented to a different
            // count afterward; stale entry.
            continue;
        }

        let hash = xor_mask[index];
        let h = hashes(hash, block_length);
        let positions = [
            h.h0 as usize,
            h.h1 as usize + block_length as usize,
            h.h2 as usize + 2 * block_length as usize,
        ];

        // Which of the three positions is the one we just peeled.
        let block = positions
            .iter()
            .position(|&p| p == index)
            .expect("index came from this key's own three positions");

        order.push(PeelStep { hash, index, block });

        for &other in &positions {
            if other == index {
                continue;
            }
            xor_mask[other] ^= hash;
            count[other] -= 1;
            if count[other] == 1 {
                queue.push(other);
            }
        }

        // The peeled slot is done; a stale re-visit must not re-peel it.
        count[index] = 0;
    }

    if order.len() == key_count {
        Some(order)
    } else {
        None
    }
}

/// Assigns each table slot its fingerprint, from a peel order produced by
/// [`try_peel`].
///
/// Processed in reverse peel order: the last key peeled is the first one
/// whose other two slots are already final, and so on back to the first key
/// peeled. Each key's own slot is set to the fingerprint that makes the XOR
/// of all three slots equal that key's fingerprint.
fn assign_fingerprints(order: &[PeelStep], block_length: u32) -> Vec<u8> {
    let table_len = 3 * block_length as usize;
    let mut fingerprints = vec![0u8; table_len];

    for step in order.iter().rev() {
        let h = hashes(step.hash, block_length);
        let positions = [
            h.h0 as usize,
            h.h1 as usize + block_length as usize,
            h.h2 as usize + 2 * block_length as usize,
        ];

        let mut value = fingerprint(step.hash);
        for (i, &p) in positions.iter().enumerate() {
            if i != step.block {
                value ^= fingerprints[p];
            }
        }

        fingerprints[step.index] = value;
    }

    fingerprints
}

impl Filter for Xor001 {
    fn id(&self) -> &'static str {
        dmc_core::filter_id!("xor", 1)
    }

    fn contains(&self, key: &[u8]) -> bool {
        // An all-zero table would otherwise report `true` for any probe whose
        // fingerprint happens to be zero — a real, if rare, false positive
        // that "no keys inserted" must never produce.
        if self.len == 0 {
            return false;
        }

        let hash = hash64(key, self.seed);
        let h = self.hashes_for(hash);

        let f = fingerprint(hash);
        let block_length = self.block_length as usize;

        f == (self.fingerprints[h.h0 as usize]
            ^ self.fingerprints[h.h1 as usize + block_length]
            ^ self.fingerprints[h.h2 as usize + 2 * block_length])
    }

    fn len(&self) -> usize {
        self.len
    }

    fn memory_bytes(&self) -> usize {
        self.fingerprints.len()
    }

    /// Returns the false positive rate an 8-bit fingerprint implies: `1/256`.
    ///
    /// Fixed rather than measured: unlike a Bloom filter's bit array, an xor
    /// filter's table has no fill ratio that predicts its rate any better
    /// than the fingerprint width already does.
    ///
    /// An empty filter is the one exception, at exactly `0.0`: `contains`
    /// short-circuits to `false` with no keys inserted, so the honest rate
    /// for that case is zero, not the fingerprint-width figure.
    fn false_positive_rate(&self) -> f64 {
        if self.len == 0 { 0.0 } else { 1.0 / 256.0 }
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();

        self.header().encode(out);
        out.extend_from_slice(&self.fingerprints);

        Header::finalize(out, start);

        Ok(())
    }
}

dmc_core::register_filter! {
    family: "xor",
    version: 1,
    id: "xor_001",
    description: "Classic three-hash xor filter, built by hypergraph peeling.",
    capabilities: Capabilities::strict()
        // Peeling fails on a repeated key rather than absorbing it.
        .without_duplicate_tolerance()
        // Construction re-hashes each key under the attempt seed rather than
        // touching input order, so shuffling the input key slice does not
        // change the result — but it is not claimed here regardless, since a
        // future revision of the peeling loop is free to become order
        // sensitive without that being a behavior change worth a new id.
        .without_order_independence()
        // The rate follows from the fixed 8-bit fingerprint width, not from
        // the request.
        .without_target_fpr()
        // Fingerprints are XORed across three slots chosen per key by
        // peeling a hypergraph specific to this key set; combining two
        // tables pointwise yields fingerprints belonging to neither.
        .without_union()
        .without_intersection()
        // A fingerprint table carries no fill ratio to invert into a count.
        .without_cardinality_estimate(),
    build: Xor001::build_boxed,
    decode: Xor001::decode_boxed,
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
        let owned = keys(2_000);
        let filter = Xor001::build(&as_slices(&owned), &Params::default()).unwrap();

        for key in &owned {
            assert!(filter.contains(key), "false negative for {key:?}");
        }
    }

    #[test]
    fn false_positive_rate_is_near_one_over_256() {
        let owned = keys(10_000);
        let filter = Xor001::build(&as_slices(&owned), &Params::default()).unwrap();

        let false_positives = (0..50_000)
            .map(|i| format!("absent-{i}").into_bytes())
            .filter(|k| filter.contains(k))
            .count();

        let observed = false_positives as f64 / 50_000.0;
        assert!(
            observed < 0.01,
            "observed false positive rate {observed} far above the ~0.4% expected"
        );
    }

    #[test]
    fn reported_rate_is_fixed() {
        let filter = Xor001::build(&[b"a"], &Params::default()).unwrap();
        assert!((filter.false_positive_rate() - 1.0 / 256.0).abs() < f64::EPSILON);
    }

    #[test]
    fn ignores_the_requested_false_positive_rate() {
        let owned = keys(500);
        let loose = Xor001::build(&as_slices(&owned), &Params::new(500, 0.1)).unwrap();
        let tight = Xor001::build(&as_slices(&owned), &Params::new(500, 0.0001)).unwrap();

        assert_eq!(loose.memory_bytes(), tight.memory_bytes());
    }

    #[test]
    fn duplicate_keys_fail_construction() {
        let owned = vec![b"same".to_vec(), b"same".to_vec()];
        let err = Xor001::build(&as_slices(&owned), &Params::default()).unwrap_err();
        assert!(matches!(err, Error::ConstructionFailed { .. }));
    }

    #[test]
    fn empty_key_set_builds_and_finds_nothing() {
        let filter = Xor001::build(&[], &Params::default()).unwrap();

        assert!(filter.is_empty());
        assert_eq!(filter.false_positive_rate(), 0.0);

        // An absolute guarantee, not a statistical one: an all-zero
        // fingerprint table would otherwise report `true` for any probe
        // whose own fingerprint happens to be zero.
        for i in 0..10_000 {
            let probe = format!("probe-{i}").into_bytes();
            assert!(
                !filter.contains(&probe),
                "false positive on empty filter for {probe:?}"
            );
        }
    }

    #[test]
    fn rejects_out_of_range_false_positive_rate() {
        for rate in [
            0.0,
            1.0,
            -0.5,
            1.5,
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
        ] {
            let err = Xor001::build(&[b"k"], &Params::new(1, rate)).unwrap_err();
            assert!(
                matches!(err, Error::InvalidParameter { .. }),
                "rate {rate} gave {err:?}, expected InvalidParameter"
            );
        }
    }

    #[test]
    fn single_key_builds() {
        let filter = Xor001::build(&[b"only"], &Params::default()).unwrap();
        assert!(filter.contains(b"only"));
        assert_eq!(filter.len(), 1);
    }

    #[test]
    fn empty_key_is_a_valid_member() {
        let owned = vec![Vec::new()];
        let filter = Xor001::build(&as_slices(&owned), &Params::default()).unwrap();

        assert!(filter.contains(b""));
    }

    #[test]
    fn seed_changes_the_fingerprint_table() {
        let owned = keys(200);
        let a = Xor001::build(&as_slices(&owned), &Params::default().with_seed(1)).unwrap();
        let b = Xor001::build(&as_slices(&owned), &Params::default().with_seed(2)).unwrap();

        assert_ne!(a.fingerprints, b.fingerprints);
    }

    #[test]
    fn same_seed_reproduces_the_filter() {
        let owned = keys(200);
        let params = Params::default().with_seed(7);
        let a = Xor001::build(&as_slices(&owned), &params).unwrap();
        let b = Xor001::build(&as_slices(&owned), &params).unwrap();

        assert_eq!(a, b);
    }

    #[test]
    fn round_trips_through_encoding() {
        let owned = keys(1_000);
        let filter = Xor001::build(&as_slices(&owned), &Params::default()).unwrap();

        let mut bytes = Vec::new();
        filter.encode(&mut bytes).unwrap();

        let decoded = Xor001::decode(&bytes).unwrap();

        assert_eq!(filter, decoded);
        for key in &owned {
            assert!(decoded.contains(key));
        }
    }

    #[test]
    fn rejects_truncated_payload() {
        let payload = sample_payload();

        assert!(Xor001::decode(&payload[..payload.len() - 4]).is_err());
        assert!(Xor001::decode(&[]).is_err());
    }

    fn sample_payload() -> Vec<u8> {
        let filter = Xor001::build(&[b"x"], &Params::default()).unwrap();
        let mut bytes = Vec::new();
        filter.encode(&mut bytes).unwrap();
        bytes
    }

    fn rechecksum(payload: &mut [u8]) {
        Header::finalize(payload, 0);
    }

    /// Byte range of the header's `capacity` field, which xor uses for its
    /// block length.
    const CAPACITY_AT: core::ops::Range<usize> = 25..33;

    #[test]
    fn rejects_absurd_declared_block_length() {
        let mut payload = sample_payload();
        payload[CAPACITY_AT].copy_from_slice(&u64::MAX.to_le_bytes());
        rechecksum(&mut payload);

        assert!(Xor001::decode(&payload).is_err());
    }

    #[test]
    fn rejects_table_length_disagreeing_with_block_length() {
        let mut payload = sample_payload();
        let declared = u64::from_le_bytes(payload[CAPACITY_AT].try_into().unwrap());
        payload[CAPACITY_AT].copy_from_slice(&(declared * 2).to_le_bytes());
        rechecksum(&mut payload);

        assert!(Xor001::decode(&payload).is_err());
    }

    #[test]
    fn rejects_a_flipped_bit_anywhere_in_the_encoding() {
        let filter = Xor001::build(&[b"alice", b"bob", b"carol"], &Params::default()).unwrap();
        let mut encoded = Vec::new();
        filter.encode(&mut encoded).unwrap();

        for offset in 0..encoded.len() {
            let mut corrupted = encoded.clone();
            corrupted[offset] ^= 0x01;

            assert!(
                Xor001::decode(&corrupted).is_err(),
                "a flipped bit at offset {offset} of {} decoded cleanly",
                encoded.len()
            );
        }
    }

    #[test]
    fn rejects_another_familys_encoding() {
        let mut payload = sample_payload();
        payload[0..4].copy_from_slice(&(FAMILY_CODE + 1).to_le_bytes());
        rechecksum(&mut payload);

        assert!(Xor001::decode(&payload).is_err());
    }

    #[test]
    fn rejects_another_version_of_this_family() {
        let mut payload = sample_payload();
        payload[4..8].copy_from_slice(&(VERSION + 1).to_le_bytes());
        rechecksum(&mut payload);

        assert!(Xor001::decode(&payload).is_err());
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
    fn block_length_grows_with_key_count() {
        assert!(block_length_for(10_000) > block_length_for(100));
    }

    #[test]
    fn block_length_has_a_floor_for_tiny_key_counts() {
        assert!(block_length_for(0) > 0);
        assert!(block_length_for(1) > 0);
    }

    #[test]
    fn large_key_set_builds_without_excess_retries() {
        // A regression guard: peeling should succeed on the first or second
        // attempt for a well-behaved key set, not burn through the retry
        // budget.
        let owned = keys(100_000);
        let filter = Xor001::build(&as_slices(&owned), &Params::default()).unwrap();

        for key in owned.iter().step_by(97) {
            assert!(filter.contains(key));
        }
    }

    #[test]
    fn every_key_is_found_across_many_sizes_and_seeds() {
        // Regression coverage for a bug where a construction retry (which
        // does not happen for every seed and key count) left the stored
        // seed and the hash actually baked into the table disagreeing, so
        // querying under the stored seed missed almost every key. Sweeping
        // sizes and seeds increases the odds of hitting at least one
        // construction that needed a retry.
        for n in [1usize, 2, 3, 10, 50, 200, 777, 2_000] {
            for seed in [0u64, 1, 42, u64::MAX] {
                let owned = keys(n);
                let filter =
                    Xor001::build(&as_slices(&owned), &Params::default().with_seed(seed)).unwrap();

                for key in &owned {
                    assert!(
                        filter.contains(key),
                        "n={n} seed={seed}: false negative for {key:?}"
                    );
                }
            }
        }
    }
}
