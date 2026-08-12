//! `fuse_001`: binary fuse filter, built by segmented hypergraph peeling.
//!
//! # Stability
//!
//! This implementation is frozen. Which keys it reports as present will not
//! change; a change to that behavior ships as `fuse_002`. Performance and
//! memory fixes may land here in place.

// Sizing computes a segment length and an overhead factor from the key
// count via logarithms; the intermediate values are small enough that f64
// precision is not the concern the lint is written for.
#![allow(clippy::cast_precision_loss)]

use dmc_core::hash::{hash64, mix_seed};
use dmc_core::header::Header;
use dmc_core::{Capabilities, Error, Filter, Params, Result};

/// Format version for the encoded payload, distinct from the implementation
/// version. Lets the decoder reject bytes from a future payload layout.
const PAYLOAD_VERSION: u8 = 1;

/// Family name this implementation registers under.
const FAMILY: &str = "fuse";

/// Implementation version within the family; the `001` in `fuse_001`.
const VERSION: u32 = 1;

/// Numeric family written into every encoding's header.
const FAMILY_CODE: u32 = match dmc_core::family::code_for(FAMILY) {
    Some(code) => code,
    None => panic!("fuse is not in dmc_core::family::KNOWN"),
};

/// Upper bound on a segment's length, in slots.
///
/// Keeps a single segment from growing large enough to blow the cache
/// benefit segmentation exists for, on a key set well past what this
/// implementation is sized for.
const MAX_SEGMENT_LENGTH: u32 = 262_144;

/// Upper bound on construction attempts before giving up.
///
/// Each attempt succeeds with probability comfortably above one half, so the
/// chance every one of a hundred consecutive attempts fails is far below the
/// chance of unrelated hardware failure during the same run.
const MAX_ITERATIONS: u32 = 100;

/// A binary fuse filter: three fingerprint slots per key, drawn from three
/// consecutive segments of a shared table rather than three independent
/// blocks.
///
/// Sharing segments between a key's three positions is what separates this
/// from the classic xor filter (`dmc-xor`'s `Xor001`): it lowers the table's
/// overhead from about 1.23x the key count to about 1.13x, at the cost of a
/// construction pass with more bookkeeping. The two agree on everything
/// else — the same peel-and-assign construction, the same 8-bit fingerprint,
/// the same fixed false positive rate near 1/256.
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
/// use dmc_fuse::Fuse001;
/// use dmc_core::{Filter, Params};
///
/// let keys: Vec<&[u8]> = vec![b"alice", b"bob", b"carol"];
/// let filter = Fuse001::build(&keys, &Params::new(3, 0.01))?;
///
/// assert!(filter.contains(b"alice"));
/// assert!(!filter.contains(b"nobody-put-this-in"));
/// # Ok::<(), dmc_core::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fuse001 {
    /// Fingerprint table, `shape.array_length` slots.
    fingerprints: Vec<u8>,

    /// The filter's segmented layout, shared between construction and query.
    shape: Shape,

    /// Seed the filter hashes with. May differ from the requested
    /// [`Params::seed`] when construction needed a retry.
    seed: u64,

    /// How many keys the filter was built from.
    len: usize,
}

/// The segmented layout a binary fuse filter hashes keys into.
///
/// Fixed once at build time from the key count alone; query and construction
/// both derive a key's three table positions from this and nothing else, so
/// the two can never disagree about where a key lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Shape {
    /// Length of one segment, a power of two.
    segment_length: u32,

    /// `segment_length - 1`, used to mask into a segment.
    segment_length_mask: u32,

    /// How many segments the table has.
    segment_count: u32,

    /// `segment_count * segment_length`, the span a key's first position is
    /// drawn from.
    segment_count_length: u32,

    /// Total table length: `(segment_count + 2) * segment_length`.
    array_length: u32,
}

impl Shape {
    /// Computes the layout for `key_count` keys.
    ///
    /// Segment length and the overhead factor both come from fits calibrated
    /// against the three-hash construction below; see
    /// [`segment_length_for`] and [`size_factor_for`]. A `key_count` of zero
    /// or one is a degenerate filter with no peeling to do, sized just large
    /// enough to hold the header's non-zero-capacity requirement.
    fn for_key_count(key_count: usize) -> Self {
        let segment_length = segment_length_for(key_count).min(MAX_SEGMENT_LENGTH);
        let segment_length_mask = segment_length - 1;

        if key_count <= 1 {
            // One segment's worth of slack either side of a single segment,
            // matching the general shape below with a capacity of zero.
            let segment_count = 1;
            let array_length = 3 * segment_length;
            return Self {
                segment_length,
                segment_length_mask,
                segment_count,
                segment_count_length: segment_count * segment_length,
                array_length,
            };
        }

        let size_factor = size_factor_for(key_count);

        // capacity = round(key_count * size_factor). size_factor is bounded
        // (never below 1.125, and never large enough to threaten a u64), so
        // the round-trip through f64 cannot go negative or overflow here.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let capacity = ((key_count as f64) * size_factor).round() as u64;

        // init_segment_count = ceil(capacity / segment_length) - 2
        let init_segment_count = capacity
            .div_ceil(u64::from(segment_length))
            .saturating_sub(2);

        let array_length_probe = (init_segment_count + 2) * u64::from(segment_length);

        let mut segment_count = array_length_probe.div_ceil(u64::from(segment_length));
        segment_count = if segment_count <= 2 {
            1
        } else {
            segment_count - 2
        };

        let array_length = (segment_count + 2) * u64::from(segment_length);

        // Bounded well below u32::MAX for any key count this implementation
        // is sized for; a key count that would overflow here has already
        // failed to allocate the fingerprint table.
        #[allow(clippy::cast_possible_truncation)]
        let segment_count = segment_count as u32;
        #[allow(clippy::cast_possible_truncation)]
        let array_length = array_length as u32;

        Self {
            segment_length,
            segment_length_mask,
            segment_count,
            segment_count_length: segment_count * segment_length,
            array_length,
        }
    }

    /// Computes the three table positions for a key's 64-bit hash.
    ///
    /// The first position is drawn from the whole `segment_count_length`
    /// span; the second and third each advance by one `segment_length` and
    /// then get `XOR`-ed with a slice of `hash`, so all three land in
    /// consecutive, overlapping segments rather than three independent
    /// blocks. That overlap is what lets the table run smaller than three
    /// disjoint blocks would need.
    ///
    /// Every truncation to `u32` below is deliberate: `mulhi` reduces into
    /// `[0, segment_count_length)`, which fits by construction, and the two
    /// masks keep only `segment_length_mask`'s low bits, which is the point
    /// of a mask.
    #[allow(clippy::cast_possible_truncation)]
    fn positions(&self, hash: u64) -> [usize; 3] {
        let h0 = mulhi(hash, u64::from(self.segment_count_length)) as u32;
        let h1 = h0 + self.segment_length;
        let h2 = h1 + self.segment_length;

        let h1 = h1 ^ ((hash >> 18) as u32 & self.segment_length_mask);
        let h2 = h2 ^ (hash as u32 & self.segment_length_mask);

        [h0 as usize, h1 as usize, h2 as usize]
    }
}

/// High 64 bits of a 64-bit-by-64-bit product, used to reduce a hash into
/// `[0, n)` without a division.
///
/// <http://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/>
///
/// The truncation back to `u64` is exact: shifting a 128-bit product right
/// by 64 leaves at most 64 significant bits.
#[allow(clippy::cast_possible_truncation)]
fn mulhi(hash: u64, n: u64) -> u64 {
    ((u128::from(hash) * u128::from(n)) >> 64) as u64
}

/// Computes the segment length for `key_count` keys: the largest power of
/// two that keeps segments from growing faster than the table needs to,
/// fitted from the construction's own success rate rather than derived
/// analytically.
///
/// Floors at 4Ki so a tiny key count still gets a workable segment, and the
/// caller clamps the top at [`MAX_SEGMENT_LENGTH`].
fn segment_length_for(key_count: usize) -> u32 {
    if key_count == 0 {
        return 4;
    }

    let exponent = ((key_count as f64).ln() / 3.33f64.ln() + 2.25).floor();

    // `exponent` is bounded well below 32 for any key count this
    // implementation can allocate a table for.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let exponent = exponent.max(0.0) as u32;

    1u32 << exponent.min(31)
}

/// Computes the table overhead factor for `key_count` keys: how many slots
/// the table holds per key, before segmenting.
///
/// `1.125` is the floor: even an enormous key set needs at least that much
/// slack for peeling to succeed reliably. The `log` term gives smaller key
/// sets extra slack, since a small hypergraph has less room to average out
/// an unlucky hash assignment.
fn size_factor_for(key_count: usize) -> f64 {
    (0.875 + 0.25 * 1_000_000.0f64.ln() / (key_count as f64).ln()).max(1.125)
}

impl Fuse001 {
    /// Builds a binary fuse filter over `keys`.
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
    /// use dmc_fuse::Fuse001;
    /// use dmc_core::{Filter, Params};
    ///
    /// let keys: Vec<&[u8]> = vec![b"key"];
    /// let filter = Fuse001::build(&keys, &Params::new(1, 0.01))?;
    /// assert_eq!(filter.len(), 1);
    /// # Ok::<(), dmc_core::Error>(())
    /// ```
    ///
    /// A duplicate key fails construction rather than silently losing it:
    ///
    /// ```
    /// use dmc_fuse::Fuse001;
    /// use dmc_core::{Error, Params};
    ///
    /// let keys: Vec<&[u8]> = vec![b"same", b"same"];
    /// assert!(matches!(
    ///     Fuse001::build(&keys, &Params::default()),
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

        let shape = Shape::for_key_count(keys.len());
        let (fingerprints, seed) = populate(keys, shape, params.seed)?;

        Ok(Self {
            fingerprints,
            shape,
            seed,
            len: keys.len(),
        })
    }

    /// Returns the seed the filter hashes with.
    ///
    /// May not equal the seed passed to [`build`](Self::build): construction
    /// retries under derived seeds when a hypergraph fails to peel.
    ///
    /// # Examples
    ///
    /// ```
    /// use dmc_fuse::Fuse001;
    /// use dmc_core::Params;
    ///
    /// let filter = Fuse001::build(&[b"key"], &Params::default())?;
    /// let _ = filter.seed();
    /// # Ok::<(), dmc_core::Error>(())
    /// ```
    #[must_use]
    pub const fn seed(&self) -> u64 {
        self.seed
    }

    /// Returns how many slots the fingerprint table holds.
    ///
    /// # Examples
    ///
    /// ```
    /// use dmc_fuse::Fuse001;
    /// use dmc_core::Params;
    ///
    /// let filter = Fuse001::build(&[b"key"], &Params::default())?;
    /// assert!(filter.array_length() > 0);
    /// # Ok::<(), dmc_core::Error>(())
    /// ```
    #[must_use]
    pub const fn array_length(&self) -> u32 {
        self.shape.array_length
    }

    /// Builds a filter and boxes it for the registry.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`Fuse001::build`].
    pub fn build_boxed(keys: &[&[u8]], params: &Params) -> Result<Box<dyn Filter>> {
        Ok(Box::new(Self::build(keys, params)?))
    }

    /// Decodes a filter from a complete encoding and boxes it.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`Fuse001::decode`].
    pub fn decode_boxed(bytes: &[u8]) -> Result<Box<dyn Filter>> {
        Ok(Box::new(Self::decode(bytes)?))
    }

    /// Decodes a filter from a complete encoding, [`Header`] included.
    ///
    /// The shared header carries the seed and the key count. The segment
    /// length rides in custom slot [`SEGMENT_LENGTH_SLOT`](Self::SEGMENT_LENGTH_SLOT)
    /// and the segment count in [`SEGMENT_COUNT_SLOT`](Self::SEGMENT_COUNT_SLOT);
    /// `capacity` carries the table length, from which the rest of the shape
    /// is rebuilt. Everything after the header is the fingerprint table, one
    /// byte per slot.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Corrupt`] if the header is malformed, if the encoding
    /// does not name `fuse_001`, if the declared shape is inconsistent, or if
    /// the table present disagrees with the declared array length.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (header, body) = Header::decode(bytes)?;

        if header.family_code != FAMILY_CODE || header.version != VERSION {
            return Err(Error::Corrupt {
                expected: "an encoding produced by fuse_001",
            });
        }

        if header.payload_version != PAYLOAD_VERSION {
            return Err(Error::Corrupt {
                expected: "fuse_001 payload version 1",
            });
        }

        let array_length = u32::try_from(header.capacity).map_err(|_| Error::Corrupt {
            expected: "an array length representable in 32 bits",
        })?;

        let segment_length = u32::try_from(header.custom[Self::SEGMENT_LENGTH_SLOT])
            .ok()
            .filter(|&n| n.is_power_of_two())
            .ok_or(Error::Corrupt {
                expected: "a segment length that is a power of two",
            })?;

        let segment_count =
            u32::try_from(header.custom[Self::SEGMENT_COUNT_SLOT]).map_err(|_| Error::Corrupt {
                expected: "a segment count representable in 32 bits",
            })?;

        if segment_count == 0 {
            return Err(Error::Corrupt {
                expected: "a non-zero segment count",
            });
        }

        let segment_count_length =
            segment_count
                .checked_mul(segment_length)
                .ok_or(Error::Corrupt {
                    expected: "a segment shape whose product fits in 32 bits",
                })?;

        let expected_array_length =
            (segment_count + 2)
                .checked_mul(segment_length)
                .ok_or(Error::Corrupt {
                    expected: "a segment shape whose array length fits in 32 bits",
                })?;

        if expected_array_length != array_length {
            return Err(Error::Corrupt {
                expected: "an array length matching segment_count and segment_length",
            });
        }

        if body.len() != array_length as usize {
            return Err(Error::Corrupt {
                expected: "a fingerprint table matching the declared array length",
            });
        }

        let len = usize::try_from(header.len).map_err(|_| Error::Corrupt {
            expected: "a key count representable on this target",
        })?;

        Ok(Self {
            fingerprints: body.to_vec(),
            shape: Shape {
                segment_length,
                segment_length_mask: segment_length - 1,
                segment_count,
                segment_count_length,
                array_length,
            },
            seed: header.seed,
            len,
        })
    }

    /// Custom header slot carrying the segment length.
    ///
    /// Public because it is part of the encoding: a reader inspecting
    /// `fuse_001` bytes needs to know which slot to look in.
    pub const SEGMENT_LENGTH_SLOT: usize = 0;

    /// Custom header slot carrying the segment count.
    pub const SEGMENT_COUNT_SLOT: usize = 1;

    /// Builds the header for this filter's current state.
    fn header(&self) -> Header {
        Header::new(
            FAMILY_CODE,
            VERSION,
            PAYLOAD_VERSION,
            self.seed,
            self.len as u64,
            u64::from(self.shape.array_length),
        )
        .with_custom(
            Self::SEGMENT_LENGTH_SLOT,
            u64::from(self.shape.segment_length),
        )
        .with_custom(
            Self::SEGMENT_COUNT_SLOT,
            u64::from(self.shape.segment_count),
        )
    }
}

/// Extracts a key's fingerprint from its 64-bit hash.
///
/// Folding the high half into the low half rather than truncating keeps the
/// fingerprint dependent on bits that [`Shape::positions`] mostly ignores, so
/// a collision in table position does not imply a collision in fingerprint.
///
/// The truncation to 8 bits is the point, not a hazard: that is the
/// fingerprint width this implementation commits to.
#[allow(clippy::cast_possible_truncation)]
fn fingerprint(hash: u64) -> u8 {
    (hash ^ (hash >> 32)) as u8
}

/// Runs the peeling construction, returning the completed fingerprint table
/// and the seed it was built under.
///
/// Retries under a fresh derived seed whenever the hypergraph fails to peel,
/// which happens for a genuinely unlucky seed and, deterministically, for any
/// key set containing a duplicate. [`Error::ConstructionFailed`] distinguishes
/// the two only by attempt count; a caller who hits it with more than a
/// handful of keys almost certainly has a duplicate.
fn populate(keys: &[&[u8]], shape: Shape, seed: u64) -> Result<(Vec<u8>, u64)> {
    let key_count = keys.len();
    let array_length = shape.array_length as usize;

    if key_count == 0 {
        return Ok((vec![0u8; array_length], seed));
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

        if let Some(order) = try_peel(&hashes, shape) {
            let fingerprints = assign_fingerprints(&order, shape);
            return Ok((fingerprints, attempt_seed));
        }
    }

    Err(Error::ConstructionFailed {
        attempts: MAX_ITERATIONS,
    })
}

/// One step of the peeling stack: a key's hash, the table index it was
/// peeled from, and which of the three positions that index was.
struct PeelStep {
    hash: u64,
    index: usize,
    which: usize,
}

/// Attempts to peel the segmented hypergraph for one attempt's hashes.
///
/// Same peeling structure as the classic xor filter's construction — repeatedly
/// remove a key whose edge has exactly one remaining unpeeled slot — but over
/// [`Shape::positions`]' three overlapping-segment positions instead of three
/// disjoint blocks. Succeeds — returns `Some` — only if every key can be
/// peeled; a set with a duplicate key, or an unlucky hash assignment, leaves
/// some edges permanently unpeelable and fails.
fn try_peel(hashes_in: &[u64], shape: Shape) -> Option<Vec<PeelStep>> {
    let key_count = hashes_in.len();
    let array_length = shape.array_length as usize;

    let mut xor_mask = vec![0u64; array_length];
    let mut count = vec![0u32; array_length];

    for &hash in hashes_in {
        for index in shape.positions(hash) {
            xor_mask[index] ^= hash;
            count[index] += 1;
        }
    }

    let mut queue: Vec<usize> = (0..array_length).filter(|&i| count[i] == 1).collect();
    let mut order = Vec::with_capacity(key_count);

    while let Some(index) = queue.pop() {
        if count[index] != 1 {
            // Pushed onto the queue earlier, since decremented to a
            // different count afterward; stale entry.
            continue;
        }

        let hash = xor_mask[index];
        let positions = shape.positions(hash);

        let which = positions
            .iter()
            .position(|&p| p == index)
            .expect("index came from this key's own three positions");

        order.push(PeelStep { hash, index, which });

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
fn assign_fingerprints(order: &[PeelStep], shape: Shape) -> Vec<u8> {
    let mut fingerprints = vec![0u8; shape.array_length as usize];

    for step in order.iter().rev() {
        let positions = shape.positions(step.hash);

        let mut value = fingerprint(step.hash);
        for (i, &p) in positions.iter().enumerate() {
            if i != step.which {
                value ^= fingerprints[p];
            }
        }

        fingerprints[step.index] = value;
    }

    fingerprints
}

impl Filter for Fuse001 {
    fn id(&self) -> &'static str {
        dmc_core::filter_id!("fuse", 1)
    }

    fn contains(&self, key: &[u8]) -> bool {
        // An all-zero table would otherwise report `true` for any probe whose
        // fingerprint happens to be zero — a real, if rare, false positive
        // that "no keys inserted" must never produce.
        if self.len == 0 {
            return false;
        }

        let hash = hash64(key, self.seed);
        let positions = self.shape.positions(hash);

        let f = fingerprint(hash);
        f == (self.fingerprints[positions[0]]
            ^ self.fingerprints[positions[1]]
            ^ self.fingerprints[positions[2]])
    }

    fn len(&self) -> usize {
        self.len
    }

    fn memory_bytes(&self) -> usize {
        self.fingerprints.len()
    }

    /// Returns the false positive rate an 8-bit fingerprint implies: `1/256`.
    ///
    /// Fixed rather than measured, for the same reason as the classic xor
    /// filter: the table has no fill ratio that predicts its rate any better
    /// than the fingerprint width already does.
    ///
    /// An empty filter is the one exception, at exactly `0.0`: `contains`
    /// short-circuits to `false` with no keys inserted, so the honest rate
    /// for that case is zero, not the fingerprint-width figure.
    fn false_positive_rate(&self) -> f64 {
        if self.len == 0 {
            return 0.0;
        }

        1.0 / 256.0
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
    family: "fuse",
    version: 1,
    id: "fuse_001",
    description: "Binary fuse filter, built by segmented hypergraph peeling.",
    capabilities: Capabilities::strict()
        // Peeling fails on a repeated key rather than absorbing it.
        .without_duplicate_tolerance()
        // Not claimed, matching xor_001: construction is order independent
        // today, but a future revision of the peeling loop is free to become
        // order sensitive without that being a behavior change worth a new
        // id.
        .without_order_independence()
        // The rate follows from the fixed 8-bit fingerprint width, not from
        // the request.
        .without_target_fpr()
        // Fingerprints are XORed across three positions chosen per key by
        // peeling a hypergraph specific to this key set; combining two
        // tables pointwise yields fingerprints belonging to neither.
        .without_union()
        .without_intersection()
        // A fingerprint table carries no fill ratio to invert into a count.
        .without_cardinality_estimate(),
    build: Fuse001::build_boxed,
    decode: Fuse001::decode_boxed,
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
        let owned = keys(5_000);
        let filter = Fuse001::build(&as_slices(&owned), &Params::default()).unwrap();

        for key in &owned {
            assert!(filter.contains(key), "false negative for {key:?}");
        }
    }

    #[test]
    fn false_positive_rate_is_near_one_over_256() {
        let owned = keys(20_000);
        let filter = Fuse001::build(&as_slices(&owned), &Params::default()).unwrap();

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
        let filter = Fuse001::build(&[b"a"], &Params::default()).unwrap();
        assert!((filter.false_positive_rate() - 1.0 / 256.0).abs() < f64::EPSILON);
    }

    #[test]
    fn ignores_the_requested_false_positive_rate() {
        let owned = keys(500);
        let loose = Fuse001::build(&as_slices(&owned), &Params::new(500, 0.1)).unwrap();
        let tight = Fuse001::build(&as_slices(&owned), &Params::new(500, 0.0001)).unwrap();

        assert_eq!(loose.memory_bytes(), tight.memory_bytes());
    }

    #[test]
    fn is_smaller_than_a_comparable_xor_filter() {
        // The whole point of segmenting: less table for the same key count
        // and fingerprint width.
        let owned = keys(50_000);
        let fuse = Fuse001::build(&as_slices(&owned), &Params::default()).unwrap();
        let xor = dmc_xor::Xor001::build(&as_slices(&owned), &Params::default()).unwrap();

        assert!(
            fuse.memory_bytes() < xor.memory_bytes(),
            "fuse {} bytes, xor {} bytes",
            fuse.memory_bytes(),
            xor.memory_bytes()
        );
    }

    #[test]
    fn duplicate_keys_fail_construction() {
        let owned = vec![b"same".to_vec(), b"same".to_vec()];
        let err = Fuse001::build(&as_slices(&owned), &Params::default()).unwrap_err();
        assert!(matches!(err, Error::ConstructionFailed { .. }));
    }

    #[test]
    fn empty_key_set_builds_and_finds_nothing() {
        let filter = Fuse001::build(&[], &Params::default()).unwrap();

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
            let err = Fuse001::build(&[b"k"], &Params::new(1, rate)).unwrap_err();
            assert!(
                matches!(err, Error::InvalidParameter { .. }),
                "rate {rate} gave {err:?}, expected InvalidParameter"
            );
        }
    }

    #[test]
    fn single_key_builds() {
        let filter = Fuse001::build(&[b"only"], &Params::default()).unwrap();
        assert!(filter.contains(b"only"));
        assert_eq!(filter.len(), 1);
    }

    #[test]
    fn two_keys_build() {
        // The smallest key count that exercises the general sizing path
        // rather than the key_count <= 1 special case.
        let filter = Fuse001::build(&[b"a", b"b"], &Params::default()).unwrap();
        assert!(filter.contains(b"a"));
        assert!(filter.contains(b"b"));
    }

    #[test]
    fn empty_key_is_a_valid_member() {
        let owned = vec![Vec::new()];
        let filter = Fuse001::build(&as_slices(&owned), &Params::default()).unwrap();

        assert!(filter.contains(b""));
    }

    #[test]
    fn seed_changes_the_fingerprint_table() {
        let owned = keys(500);
        let a = Fuse001::build(&as_slices(&owned), &Params::default().with_seed(1)).unwrap();
        let b = Fuse001::build(&as_slices(&owned), &Params::default().with_seed(2)).unwrap();

        assert_ne!(a.fingerprints, b.fingerprints);
    }

    #[test]
    fn same_seed_reproduces_the_filter() {
        let owned = keys(500);
        let params = Params::default().with_seed(7);
        let a = Fuse001::build(&as_slices(&owned), &params).unwrap();
        let b = Fuse001::build(&as_slices(&owned), &params).unwrap();

        assert_eq!(a, b);
    }

    #[test]
    fn round_trips_through_encoding() {
        let owned = keys(2_000);
        let filter = Fuse001::build(&as_slices(&owned), &Params::default()).unwrap();

        let mut bytes = Vec::new();
        filter.encode(&mut bytes).unwrap();

        let decoded = Fuse001::decode(&bytes).unwrap();

        assert_eq!(filter, decoded);
        for key in &owned {
            assert!(decoded.contains(key));
        }
    }

    #[test]
    fn rejects_truncated_payload() {
        let payload = sample_payload();

        assert!(Fuse001::decode(&payload[..payload.len() - 4]).is_err());
        assert!(Fuse001::decode(&[]).is_err());
    }

    fn sample_payload() -> Vec<u8> {
        let filter = Fuse001::build(&[b"x", b"y", b"z"], &Params::default()).unwrap();
        let mut bytes = Vec::new();
        filter.encode(&mut bytes).unwrap();
        bytes
    }

    fn rechecksum(payload: &mut [u8]) {
        Header::finalize(payload, 0);
    }

    /// Byte range of the header's `capacity` field, which fuse uses for its
    /// array length.
    const CAPACITY_AT: core::ops::Range<usize> = 25..33;

    /// Byte range of custom slot 0, the segment length.
    const SEGMENT_LENGTH_AT: core::ops::Range<usize> = 33..41;

    /// Byte range of custom slot 1, the segment count.
    const SEGMENT_COUNT_AT: core::ops::Range<usize> = 41..49;

    #[test]
    fn rejects_absurd_declared_array_length() {
        let mut payload = sample_payload();
        payload[CAPACITY_AT].copy_from_slice(&u64::MAX.to_le_bytes());
        rechecksum(&mut payload);

        assert!(Fuse001::decode(&payload).is_err());
    }

    #[test]
    fn rejects_a_segment_length_that_is_not_a_power_of_two() {
        let mut payload = sample_payload();
        payload[SEGMENT_LENGTH_AT].copy_from_slice(&100u64.to_le_bytes());
        rechecksum(&mut payload);

        assert!(Fuse001::decode(&payload).is_err());
    }

    #[test]
    fn rejects_a_zero_segment_count() {
        let mut payload = sample_payload();
        payload[SEGMENT_COUNT_AT].copy_from_slice(&0u64.to_le_bytes());
        rechecksum(&mut payload);

        assert!(Fuse001::decode(&payload).is_err());
    }

    #[test]
    fn rejects_a_shape_whose_array_length_disagrees_with_capacity() {
        let mut payload = sample_payload();
        let declared = u64::from_le_bytes(payload[CAPACITY_AT].try_into().unwrap());
        payload[CAPACITY_AT].copy_from_slice(&(declared * 2).to_le_bytes());
        rechecksum(&mut payload);

        assert!(Fuse001::decode(&payload).is_err());
    }

    #[test]
    fn rejects_a_flipped_bit_anywhere_in_the_encoding() {
        let filter = Fuse001::build(&[b"alice", b"bob", b"carol"], &Params::default()).unwrap();
        let mut encoded = Vec::new();
        filter.encode(&mut encoded).unwrap();

        for offset in 0..encoded.len() {
            let mut corrupted = encoded.clone();
            corrupted[offset] ^= 0x01;

            assert!(
                Fuse001::decode(&corrupted).is_err(),
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

        assert!(Fuse001::decode(&payload).is_err());
    }

    #[test]
    fn rejects_another_version_of_this_family() {
        let mut payload = sample_payload();
        payload[4..8].copy_from_slice(&(VERSION + 1).to_le_bytes());
        rechecksum(&mut payload);

        assert!(Fuse001::decode(&payload).is_err());
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
    fn large_key_set_builds_without_excess_retries() {
        let owned = keys(100_000);
        let filter = Fuse001::build(&as_slices(&owned), &Params::default()).unwrap();

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
                    Fuse001::build(&as_slices(&owned), &Params::default().with_seed(seed)).unwrap();

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
