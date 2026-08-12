//! `zor_001`: fuse-shaped filter with deterministic peeling, backed by a fuse
//! auxiliary for abandoned keys.
//!
//! # Stability
//!
//! This implementation is frozen. Which keys it reports as present will not
//! change; a change to that behavior ships as `zor_002`. Performance and
//! memory fixes may land here in place.

// Sizing computes a segment length and an overhead factor from the key
// count via logarithms; the intermediate values are small enough that f64
// precision is not the concern the lint is written for.
#![allow(clippy::cast_precision_loss)]

use dmc_core::hash::{hash64, mix_seed};
use dmc_core::header::Header;
use dmc_core::{Capabilities, Error, Filter, Params, Result};
use dmc_fuse::Fuse001;

/// Format version for the encoded payload, distinct from the implementation
/// version. Lets the decoder reject bytes from a future payload layout.
const PAYLOAD_VERSION: u8 = 1;

/// Family name this implementation registers under.
const FAMILY: &str = "zor";

/// Implementation version within the family; the `001` in `zor_001`.
const VERSION: u32 = 1;

/// Numeric family written into every encoding's header.
const FAMILY_CODE: u32 = match dmc_core::family::code_for(FAMILY) {
    Some(code) => code,
    None => panic!("zor is not in dmc_core::family::KNOWN"),
};

/// Upper bound on a segment's length, in slots.
///
/// Keeps a single segment from growing large enough to blow the cache
/// benefit segmentation exists for, on a key set well past what this
/// implementation is sized for.
const MAX_SEGMENT_LENGTH: u32 = 262_144;

/// How many table positions each key occupies.
///
/// The paper's Figure 1 reports the abandoned fraction dropping sharply as
/// arity rises from 3 to 5 and flattening past that (6.1% at 3-wise, 0.9% at
/// 5-wise, 0.4% at 8-wise, all at `m = n`); this implementation fixes arity
/// at the front of that curve rather than exposing it as a build parameter,
/// so `zor_001` names one specific, frozen construction the way every other
/// `_NNN` id here does.
const ARITY: usize = 5;

/// [`ARITY`] as `u32`, for the arithmetic that computes table sizes.
///
/// `ARITY` is a small compile-time constant, so this narrowing cannot
/// truncate; a `const` avoids re-asserting that at every call site.
#[allow(clippy::cast_possible_truncation)]
const ARITY_U32: u32 = ARITY as u32;

/// A zor filter: the same ARITY-position fuse-style query mechanism as
/// [`Fuse001`], but built by construction that never restarts.
///
/// Fuse-style peeling can get stuck on a "core" where every remaining slot
/// has at least two incident keys and no restart threshold is met other than
/// giving up and reseeding. Zor's construction instead makes deterministic
/// progress on a stuck core: it finds a lowest-degree slot, keeps one of its
/// incident keys to resolve there, and abandons the rest. Abandoning a key
/// removes it from every other slot it touches, which frees up further
/// degree-1 slots and lets peeling continue. Repeating this guarantees
/// termination — each intervention strictly shrinks the remaining key set —
/// in exchange for a small abandoned fraction that would otherwise have
/// triggered a full restart under fuse's construction.
///
/// The main structure alone would report a false negative for any abandoned
/// key. To keep the same false-positive-only contract as every other filter
/// in this project, abandoned keys are stored in a second, smaller
/// [`Fuse001`] built over just that remainder; a query checks the main
/// structure first and only consults the auxiliary if the main structure
/// says "absent". The paper recommends sizing the auxiliary's fingerprint a
/// further `log2(1/α)` bits wider than the main one so its own false
/// positive rate stays negligible next to the main structure's; this
/// implementation instead reuses [`Fuse001`] as-is for the auxiliary, at its
/// fixed 8-bit fingerprint, trading a slightly higher combined false
/// positive rate for not needing a second, width-parameterized peeling
/// implementation. [`false_positive_rate`](Filter::false_positive_rate)
/// reports the resulting combined rate honestly. See the module docs for the
/// resulting space trade-off against [`Fuse001`] alone.
///
/// # Duplicate keys
///
/// A duplicate key produces a hyperedge with no distinct partner. Where
/// [`Fuse001`] fails construction outright on this, zor's abandonment
/// mechanism instead routes the repeat through the auxiliary: peeling stalls
/// on the duplicate's slots, the intervention step abandons one of the two
/// occurrences, and the auxiliary resolves it from there. A key set with
/// enough duplicates degrades the abandoned fraction but does not fail
/// construction.
///
/// # Examples
///
/// ```
/// use dmc_zor::Zor001;
/// use dmc_core::{Filter, Params};
///
/// let keys: Vec<&[u8]> = vec![b"alice", b"bob", b"carol"];
/// let filter = Zor001::build(&keys, &Params::new(3, 0.01))?;
///
/// assert!(filter.contains(b"alice"));
/// assert!(!filter.contains(b"nobody-put-this-in"));
/// # Ok::<(), dmc_core::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Zor001 {
    /// Fingerprint table for the keys that were peeled, `shape.array_length`
    /// slots. Slots belonging only to abandoned keys hold whatever the last
    /// write left there and are never consulted meaningfully on their own —
    /// `contains` always XORs all ARITY of a key's positions together.
    fingerprints: Vec<u8>,

    /// The main structure's segmented layout.
    shape: Shape,

    /// Seed the main structure hashes with. May differ from the requested
    /// [`Params::seed`] when construction needed a retry.
    seed: u64,

    /// Auxiliary filter over the keys abandoned by the main structure's
    /// construction, or `None` if nothing was abandoned.
    aux: Option<Fuse001>,

    /// How many keys the filter was built from, peeled and abandoned alike.
    len: usize,
}

/// The segmented layout a zor filter's main structure hashes keys into.
///
/// [`ARITY`]-wise generalization of `dmc-fuse`'s own 3-wise `Shape`:
/// [`positions`](Self::positions) draws [`ARITY`] positions from [`ARITY`]
/// consecutive, overlapping segments instead of fuse's fixed three, which is
/// what lets this implementation reach the paper's low-abandonment regime
/// (Figure 1: abandonment keeps dropping from 3-wise through about 5-wise).
/// Not shared with `dmc-fuse`'s type even where the shapes coincide, because
/// each `_NNN` implementation in this project is frozen and self-contained;
/// sharing a private type across crates would couple two supposedly
/// independent frozen encodings.
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

    /// Total table length: `(segment_count + ARITY - 1) * segment_length`.
    array_length: u32,
}

impl Shape {
    /// Computes the layout for `key_count` keys.
    ///
    /// See [`size_factor_for`] for how the overhead factor compares to
    /// fuse's own. A `key_count` of zero or one is a degenerate filter with
    /// no peeling to do, sized just large enough to hold the header's
    /// non-zero-capacity requirement.
    fn for_key_count(key_count: usize) -> Self {
        let segment_length = segment_length_for(key_count).min(MAX_SEGMENT_LENGTH);
        let segment_length_mask = segment_length - 1;
        let slack_segments = ARITY_U32 - 1;

        if key_count <= 1 {
            let segment_count = 1;
            let array_length = (segment_count + slack_segments) * segment_length;
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
        // (never below 1.02, and never large enough to threaten a u64), so
        // the round-trip through f64 cannot go negative or overflow here.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let capacity = ((key_count as f64) * size_factor).round() as u64;

        let init_segment_count = capacity
            .div_ceil(u64::from(segment_length))
            .saturating_sub(u64::from(slack_segments));

        let array_length_probe =
            (init_segment_count + u64::from(slack_segments)) * u64::from(segment_length);

        let mut segment_count = array_length_probe.div_ceil(u64::from(segment_length));
        segment_count = if segment_count <= u64::from(slack_segments) {
            1
        } else {
            segment_count - u64::from(slack_segments)
        };

        let array_length = (segment_count + u64::from(slack_segments)) * u64::from(segment_length);

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

    /// Computes the [`ARITY`] table positions for a key's 64-bit hash.
    ///
    /// The first position is drawn from the whole `segment_count_length`
    /// span, generalizing fuse's own derivation. Each subsequent position
    /// advances by one more segment and is then `XOR`-ed with an
    /// independent low-bit slice of a rotated copy of `hash`, so all
    /// [`ARITY`] positions land in consecutive, overlapping segments rather
    /// than [`ARITY`] disjoint blocks — the rotation amount differs per
    /// position so the slices do not repeat the same bits of `hash` against
    /// each other.
    #[allow(clippy::cast_possible_truncation)]
    fn positions(&self, hash: u64) -> [usize; ARITY] {
        let base = mulhi(hash, u64::from(self.segment_count_length)) as u32;

        let mut positions = [0usize; ARITY];
        positions[0] = base as usize;

        for (i, slot) in positions.iter_mut().enumerate().skip(1) {
            // i in 1..ARITY, so i * 17 never repeats a prior rotation amount
            // for any ARITY this implementation is sized for, keeping each
            // position's bit slice independent of the others'.
            #[allow(clippy::cast_possible_truncation)]
            let rotation = (i as u32) * 17;
            let noise = (hash.rotate_left(rotation) as u32) & self.segment_length_mask;
            *slot = ((base + (i as u32) * self.segment_length) ^ noise) as usize;
        }

        positions
    }
}

/// High 64 bits of a 64-bit-by-64-bit product, used to reduce a hash into
/// `[0, n)` without a division.
///
/// <http://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/>
#[allow(clippy::cast_possible_truncation)]
fn mulhi(hash: u64, n: u64) -> u64 {
    ((u128::from(hash) * u128::from(n)) >> 64) as u64
}

/// Computes the segment length for `key_count` keys.
///
/// Identical fit to `dmc-fuse`'s own `segment_length_for`; zor's lower
/// overhead factor comes entirely from [`size_factor_for`], not from a
/// different segment length.
fn segment_length_for(key_count: usize) -> u32 {
    if key_count == 0 {
        return 4;
    }

    let exponent = ((key_count as f64).ln() / 3.33f64.ln() + 2.25).floor();

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let exponent = exponent.max(0.0) as u32;

    1u32 << exponent.min(31)
}

/// Computes the table overhead factor for `key_count` keys: how many slots
/// the table holds per key, before segmenting.
///
/// The floor (`1.13`) sits below fuse's own (`1.125` is fuse's floor, but
/// fuse's log term pushes it past `1.13` everywhere except very large key
/// counts): loosening it further drives the abandoned fraction up faster
/// than the smaller main table saves, since every abandoned key still costs
/// its share of the auxiliary's own ~13% overhead on top. The constants here
/// are fitted empirically against this construction's own abandoned-fraction
/// behavior at [`ARITY`], the same way fuse's are fitted against its restart
/// rate; see the `abandoned_fraction_is_small` and
/// `is_smaller_than_a_comparable_fuse_filter` tests.
fn size_factor_for(key_count: usize) -> f64 {
    (0.85 + 0.22 * 1_000_000.0f64.ln() / (key_count.max(2) as f64).ln()).max(1.13)
}

impl Zor001 {
    /// Builds a zor filter over `keys`.
    ///
    /// `params.expected_items` and `params.false_positive_rate` are ignored:
    /// the filter sizes itself from the actual key count, and its rate
    /// follows from the fixed fingerprint widths of the main and auxiliary
    /// structures rather than from a request. `params.seed` seeds the main
    /// structure's hashing and, derived via [`mix_seed`], the auxiliary's.
    ///
    /// Unlike [`Fuse001::build`] and the classic xor filter's `build`, this
    /// never retries under a fresh seed: construction cannot fail here by
    /// design, so the seed given is the seed used.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidParameter`] if `false_positive_rate` is
    /// outside `0.0..1.0`. Never returns
    /// [`Error::ConstructionFailed`](dmc_core::Error::ConstructionFailed):
    /// deterministic peeling always terminates.
    ///
    /// # Examples
    ///
    /// ```
    /// use dmc_zor::Zor001;
    /// use dmc_core::{Filter, Params};
    ///
    /// let keys: Vec<&[u8]> = vec![b"key"];
    /// let filter = Zor001::build(&keys, &Params::new(1, 0.01))?;
    /// assert_eq!(filter.len(), 1);
    /// # Ok::<(), dmc_core::Error>(())
    /// ```
    pub fn build(keys: &[&[u8]], params: &Params) -> Result<Self> {
        // Validated for uniformity across every implementation even though
        // this one ignores the value: a caller passing an out-of-range rate
        // must see InvalidParameter regardless of which filter they asked
        // for, not a silently accepted request.
        params.validate()?;

        let shape = Shape::for_key_count(keys.len());
        let seed = params.seed;

        if keys.is_empty() {
            return Ok(Self {
                fingerprints: vec![0u8; shape.array_length as usize],
                shape,
                seed,
                aux: None,
                len: 0,
            });
        }

        let hashes: Vec<u64> = keys.iter().map(|key| hash64(key, seed)).collect();
        let PeelResult { order, abandoned } = peel(&hashes, shape);
        let fingerprints = assign_fingerprints(&order, shape);

        let main = Self {
            fingerprints,
            shape,
            seed,
            aux: None,
            len: keys.len(),
        };

        if abandoned.is_empty() {
            return Ok(main);
        }

        // Opportunistic skip (paper Section 2.6): an abandoned key that the
        // main structure already reports present needs no auxiliary entry,
        // since it will never reach a false negative at query time. This can
        // only shrink the auxiliary; it never changes which keys the
        // complete filter reports as present.
        let aux_seed = mix_seed(seed, 1);
        let aux_keys: Vec<&[u8]> = abandoned
            .iter()
            .map(|&i| keys[i])
            .filter(|key| !main.contains(key))
            .collect();

        let aux = if aux_keys.is_empty() {
            None
        } else {
            Some(Fuse001::build(
                &aux_keys,
                &Params::default().with_seed(aux_seed),
            )?)
        };

        Ok(Self { aux, ..main })
    }

    /// Returns the seed the main structure hashes with.
    ///
    /// # Examples
    ///
    /// ```
    /// use dmc_zor::Zor001;
    /// use dmc_core::Params;
    ///
    /// let filter = Zor001::build(&[b"key"], &Params::default())?;
    /// let _ = filter.seed();
    /// # Ok::<(), dmc_core::Error>(())
    /// ```
    #[must_use]
    pub const fn seed(&self) -> u64 {
        self.seed
    }

    /// Returns how many keys the auxiliary structure holds, or zero if
    /// construction abandoned nothing.
    ///
    /// # Examples
    ///
    /// ```
    /// use dmc_zor::Zor001;
    /// use dmc_core::Params;
    ///
    /// let filter = Zor001::build(&[b"key"], &Params::default())?;
    /// let _ = filter.abandoned_len();
    /// # Ok::<(), dmc_core::Error>(())
    /// ```
    #[must_use]
    pub fn abandoned_len(&self) -> usize {
        self.aux.as_ref().map_or(0, Filter::len)
    }

    /// Builds a filter and boxes it for the registry.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`Zor001::build`].
    pub fn build_boxed(keys: &[&[u8]], params: &Params) -> Result<Box<dyn Filter>> {
        Ok(Box::new(Self::build(keys, params)?))
    }

    /// Decodes a filter from a complete encoding and boxes it.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`Zor001::decode`].
    pub fn decode_boxed(bytes: &[u8]) -> Result<Box<dyn Filter>> {
        Ok(Box::new(Self::decode(bytes)?))
    }

    /// Decodes a filter from a complete encoding, [`Header`] included.
    ///
    /// The shared header carries the main structure's seed and the total key
    /// count. The segment length rides in custom slot
    /// [`SEGMENT_LENGTH_SLOT`](Self::SEGMENT_LENGTH_SLOT), the segment count
    /// in [`SEGMENT_COUNT_SLOT`](Self::SEGMENT_COUNT_SLOT), and whether an
    /// auxiliary follows in [`HAS_AUX_SLOT`](Self::HAS_AUX_SLOT). The body is
    /// the main fingerprint table, one byte per slot, followed by the
    /// auxiliary's own complete encoding when present.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Corrupt`] if the header is malformed, if the encoding
    /// does not name `zor_001`, if the declared shape is inconsistent, if the
    /// main table present disagrees with the declared array length, or if an
    /// auxiliary is declared but its own encoding fails to decode.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (header, body) = Header::decode(bytes)?;

        if header.family_code != FAMILY_CODE || header.version != VERSION {
            return Err(Error::Corrupt {
                expected: "an encoding produced by zor_001",
            });
        }

        if header.payload_version != PAYLOAD_VERSION {
            return Err(Error::Corrupt {
                expected: "zor_001 payload version 1",
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

        let expected_array_length = (segment_count + (ARITY_U32 - 1))
            .checked_mul(segment_length)
            .ok_or(Error::Corrupt {
                expected: "a segment shape whose array length fits in 32 bits",
            })?;

        if expected_array_length != array_length {
            return Err(Error::Corrupt {
                expected: "an array length matching segment_count and segment_length",
            });
        }

        if body.len() < array_length as usize {
            return Err(Error::Corrupt {
                expected: "a fingerprint table matching the declared array length",
            });
        }

        let (main_body, aux_body) = body.split_at(array_length as usize);

        let has_aux = header.custom[Self::HAS_AUX_SLOT] != 0;
        let aux = if has_aux {
            if aux_body.is_empty() {
                return Err(Error::Corrupt {
                    expected: "an auxiliary encoding following the main table",
                });
            }
            Some(Fuse001::decode(aux_body)?)
        } else {
            if !aux_body.is_empty() {
                return Err(Error::Corrupt {
                    expected: "no trailing bytes when no auxiliary is declared",
                });
            }
            None
        };

        let len = usize::try_from(header.len).map_err(|_| Error::Corrupt {
            expected: "a key count representable on this target",
        })?;

        Ok(Self {
            fingerprints: main_body.to_vec(),
            shape: Shape {
                segment_length,
                segment_length_mask: segment_length - 1,
                segment_count,
                segment_count_length,
                array_length,
            },
            seed: header.seed,
            aux,
            len,
        })
    }

    /// Custom header slot carrying the main structure's segment length.
    ///
    /// Public because it is part of the encoding: a reader inspecting
    /// `zor_001` bytes needs to know which slot to look in.
    pub const SEGMENT_LENGTH_SLOT: usize = 0;

    /// Custom header slot carrying the main structure's segment count.
    pub const SEGMENT_COUNT_SLOT: usize = 1;

    /// Custom header slot carrying whether an auxiliary encoding follows the
    /// main table: `0` for none, non-zero when present.
    pub const HAS_AUX_SLOT: usize = 2;

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
        .with_custom(Self::HAS_AUX_SLOT, u64::from(self.aux.is_some()))
    }
}

/// Extracts a key's main-structure fingerprint from its 64-bit hash.
///
/// Folding the high half into the low half rather than truncating keeps the
/// fingerprint dependent on bits that [`Shape::positions`] mostly ignores, so
/// a collision in table position does not imply a collision in fingerprint.
#[allow(clippy::cast_possible_truncation)]
fn fingerprint(hash: u64) -> u8 {
    (hash ^ (hash >> 32)) as u8
}

/// One step of the peeling stack: a key's hash, the table index it was
/// peeled from, and which of the ARITY positions that index was.
struct PeelStep {
    hash: u64,
    index: usize,
    which: usize,
}

/// The outcome of [`peel`]: every key partitioned into resolved order or
/// abandoned index.
struct PeelResult {
    /// Peel order for the keys the main structure resolves, in the order
    /// they were peeled. Reversing this is the order fingerprints must be
    /// assigned in.
    order: Vec<PeelStep>,

    /// Indices into the original key slice of every abandoned key, in the
    /// order abandonment happened.
    abandoned: Vec<usize>,
}

/// Mutable working state for [`peel`], carried across both the ordinary
/// peel step and the intervention step so neither has to thread five
/// separate arrays through the other.
struct PeelState<'a> {
    /// Each key's ARITY table positions, indexed by key. Fixed for the
    /// whole construction; only the fields below change as peeling
    /// proceeds.
    positions: &'a [[usize; ARITY]],

    /// Per-slot list of currently-incident, still-active key indices.
    incident: Vec<Vec<u32>>,

    /// Per-slot count, always equal to `incident[slot].len()`. Kept
    /// alongside `incident` rather than recomputed from it so the peel
    /// queue can check degree without touching the (possibly large) vector.
    degree: Vec<u32>,

    /// Slots newly at degree one, awaiting a peel step.
    queue: Vec<usize>,

    /// Slots at degree two or more, bucketed by degree, so
    /// [`intervene`](Self::intervene) can find a minimum-degree slot without
    /// rescanning the whole table on every blocking event. A slot can appear
    /// more than once across buckets — stale entries from before its last
    /// degree change — so a pop is only trusted after checking it against
    /// the live `degree` value, the same staleness pattern `queue` already
    /// uses.
    by_degree: std::collections::BTreeMap<u32, Vec<usize>>,

    /// Completed peel steps, in the order they were resolved.
    order: Vec<PeelStep>,

    /// Indices of every key abandoned so far.
    abandoned: Vec<usize>,
}

impl<'a> PeelState<'a> {
    fn new(positions: &'a [[usize; ARITY]], array_length: usize, key_count: usize) -> Self {
        let mut incident: Vec<Vec<u32>> = vec![Vec::new(); array_length];
        for (key_idx, pos) in positions.iter().enumerate() {
            for &slot in pos {
                incident[slot].push(u32::try_from(key_idx).expect("key index fits in u32"));
            }
        }

        let degree: Vec<u32> = incident
            .iter()
            .map(|v| u32::try_from(v.len()).unwrap_or(u32::MAX))
            .collect();
        let queue = (0..array_length).filter(|&i| degree[i] == 1).collect();

        let mut by_degree: std::collections::BTreeMap<u32, Vec<usize>> =
            std::collections::BTreeMap::new();
        for (slot, &d) in degree.iter().enumerate() {
            if d >= 2 {
                by_degree.entry(d).or_default().push(slot);
            }
        }

        Self {
            positions,
            incident,
            degree,
            queue,
            by_degree,
            order: Vec::with_capacity(key_count),
            abandoned: Vec::new(),
        }
    }

    /// Removes `key_idx` from every slot in its position list except
    /// `skip_slot` (pass `usize::MAX` to remove from all of them),
    /// decrementing degree and enqueuing any slot that reaches degree one
    /// (or rebucketing any slot that lands at two or more) as a result.
    fn retract(&mut self, key_idx: usize, skip_slot: usize) {
        for &slot in &self.positions[key_idx] {
            if slot == skip_slot {
                continue;
            }
            if let Some(pos) = self.incident[slot]
                .iter()
                .position(|&k| k as usize == key_idx)
            {
                self.incident[slot].swap_remove(pos);
                self.degree[slot] -= 1;
                let new_degree = self.degree[slot];
                if new_degree == 1 {
                    self.queue.push(slot);
                } else if new_degree >= 2 {
                    self.by_degree.entry(new_degree).or_default().push(slot);
                }
            }
        }
    }

    /// Resolves `key_idx` at `slot`, recording the peel step and retracting
    /// the key from its two other positions.
    fn resolve(&mut self, key_idx: usize, slot: usize, hash: u64) {
        let which = self.positions[key_idx]
            .iter()
            .position(|&p| p == slot)
            .expect("slot came from this key's own positions");

        self.order.push(PeelStep {
            hash,
            index: slot,
            which,
        });
        self.degree[slot] = 0;
        self.incident[slot].clear();

        self.retract(key_idx, slot);
    }

    /// Drains the peel queue, resolving every slot that reaches degree one
    /// as a consequence of an earlier resolution or retraction.
    fn drain_queue(&mut self, hashes_in: &[u64], active: &mut [bool]) {
        while let Some(slot) = self.queue.pop() {
            if self.degree[slot] != 1 {
                // Pushed earlier, since decremented to a different degree
                // afterward; stale entry.
                continue;
            }

            // Degree exactly one: exactly one live key remains here.
            let Some(&key_idx) = self.incident[slot].first() else {
                continue;
            };
            let key_idx = key_idx as usize;

            if !active[key_idx] {
                continue;
            }

            active[key_idx] = false;
            self.resolve(key_idx, slot, hashes_in[key_idx]);
        }
    }

    /// Pops a slot genuinely still at degree two or more from
    /// [`by_degree`](Self::by_degree), discarding stale entries left behind
    /// by earlier degree changes along the way.
    fn pop_min_degree_slot(&mut self) -> Option<usize> {
        loop {
            let &lowest = self.by_degree.keys().next()?;
            let bucket = self.by_degree.get_mut(&lowest).expect("key just read");
            let Some(slot) = bucket.pop() else {
                self.by_degree.remove(&lowest);
                continue;
            };
            if bucket.is_empty() {
                self.by_degree.remove(&lowest);
            }
            if self.degree[slot] == lowest {
                return Some(slot);
            }
            // Stale: this slot's degree moved since it was bucketed. Its
            // current degree (if still >= 2) was already pushed to the
            // right bucket when it changed, so dropping this entry loses
            // nothing.
        }
    }

    /// Forces progress on a stuck core: finds a minimum-degree slot among
    /// those with degree at least two, keeps one of its incident keys to
    /// resolve there, and abandons the rest.
    ///
    /// # Panics
    ///
    /// Panics if every slot has degree zero or one, which the caller must
    /// never call this with: [`drain_queue`](Self::drain_queue) having
    /// emptied the queue while active keys remain is exactly the condition
    /// that guarantees some slot is still at degree two or more.
    fn intervene(&mut self, hashes_in: &[u64], active: &mut [bool]) {
        let intervention_slot = self
            .pop_min_degree_slot()
            .expect("keys remain, so some slot has degree >= 2");

        // Keep the first key by index for reproducibility; abandon the rest.
        let mut incident_keys = self.incident[intervention_slot].clone();
        incident_keys.sort_unstable();
        let keep = incident_keys[0] as usize;

        for &other in &incident_keys[1..] {
            let other = other as usize;
            active[other] = false;
            self.abandoned.push(other);
            self.retract(other, usize::MAX);
        }

        // `keep` still sits on `intervention_slot` and, after the abandons
        // above, on however many of its other two slots survived. Retract
        // it from those too, leaving only `intervention_slot`, then
        // resolve it there directly rather than waiting a queue
        // round-trip.
        self.retract(keep, intervention_slot);
        active[keep] = false;
        self.resolve(keep, intervention_slot, hashes_in[keep]);
    }
}

/// Runs zor's deterministic peeling construction to completion.
///
/// Structurally the same hypergraph as [`Fuse001`]'s: each key is an edge
/// touching the ARITY table slots [`Shape::positions`] gives its hash.
/// Peeling repeatedly resolves a key whose edge has exactly one remaining
/// slot, exactly as fuse's construction does. The difference is what happens
/// when the queue of such slots runs dry with keys still unresolved: instead
/// of reporting failure for the caller to retry under a new seed, this picks
/// a minimum-degree slot, keeps one of its incident keys to resolve there,
/// and abandons the rest, which frees that slot to degree one and lets
/// peeling continue. Because each intervention strictly reduces the number
/// of unresolved keys, this always terminates.
///
/// Needs an explicit adjacency list rather than fuse's count+xor-only
/// bookkeeping: an intervention must enumerate every key currently incident
/// to the chosen slot, which the xor trick alone only supports when exactly
/// one such key remains.
fn peel(hashes_in: &[u64], shape: Shape) -> PeelResult {
    let key_count = hashes_in.len();
    let array_length = shape.array_length as usize;

    // Per-key positions, computed once and reused by every lookup below
    // rather than recomputed from a slot's xor_mask the way fuse's peeling
    // does — abandonment needs to enumerate a slot's incident keys directly,
    // which the xor trick cannot do once more than one key remains.
    let positions: Vec<[usize; ARITY]> = hashes_in.iter().map(|&h| shape.positions(h)).collect();

    let mut state = PeelState::new(&positions, array_length, key_count);
    let mut active = vec![true; key_count];

    loop {
        state.drain_queue(hashes_in, &mut active);

        if state.order.len() + state.abandoned.len() == key_count {
            break;
        }

        state.intervene(hashes_in, &mut active);
    }

    PeelResult {
        order: state.order,
        abandoned: state.abandoned,
    }
}

/// Assigns each table slot its fingerprint, from a peel order produced by
/// [`peel`].
///
/// Processed in reverse peel order: the last key peeled is the first one
/// whose other two slots are already final, and so on back to the first key
/// peeled. Each key's own slot is set to the fingerprint that makes the XOR
/// of all ARITY slots equal that key's fingerprint. Abandoned keys never
/// appear in `order`, so their slots are whatever an intervening peeled key
/// happened to leave there — never consulted as ground truth for an
/// abandoned key, since abandoned keys are answered by the auxiliary.
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

impl Filter for Zor001 {
    fn id(&self) -> &'static str {
        dmc_core::filter_id!("zor", 1)
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
        let combined = positions
            .iter()
            .fold(0u8, |acc, &p| acc ^ self.fingerprints[p]);

        if f == combined {
            return true;
        }

        self.aux.as_ref().is_some_and(|aux| aux.contains(key))
    }

    fn len(&self) -> usize {
        self.len
    }

    fn memory_bytes(&self) -> usize {
        self.fingerprints.len() + self.aux.as_ref().map_or(0, Filter::memory_bytes)
    }

    /// Returns the false positive rate the main and auxiliary fingerprint
    /// widths imply together: `1 - (1 - ε1)(1 - ε2) ≈ ε1 + ε2`, per the
    /// paper's Section 2.4.
    ///
    /// With no auxiliary (nothing was abandoned), this is exactly the main
    /// structure's `1/256`, identical to [`Fuse001::false_positive_rate`].
    ///
    /// An empty filter is the one exception, at exactly `0.0`: `contains`
    /// short-circuits to `false` with no keys inserted, so the honest rate
    /// for that case is zero, not the fingerprint-width figure.
    fn false_positive_rate(&self) -> f64 {
        if self.len == 0 {
            return 0.0;
        }

        let main_rate = 1.0 / 256.0;
        let Some(aux) = &self.aux else {
            return main_rate;
        };

        let aux_rate = aux.false_positive_rate();
        main_rate + aux_rate - main_rate * aux_rate
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();

        self.header().encode(out);
        out.extend_from_slice(&self.fingerprints);

        if let Some(aux) = &self.aux {
            aux.encode(out)?;
        }

        Header::finalize(out, start);

        Ok(())
    }
}

dmc_core::register_filter! {
    family: "zor",
    version: 1,
    id: "zor_001",
    description: "Fuse-shaped filter with deterministic peeling, backed by a fuse auxiliary for abandoned keys.",
    capabilities: Capabilities::strict()
        // Unlike fuse and xor, a duplicate key does not fail construction:
        // peeling stalls on it, the intervention step abandons one of the
        // two occurrences, and the auxiliary resolves it from there (see the
        // type docs' "Duplicate keys" section). `len` still counts every
        // repeat in the input, matching the strict default.
        //
        // Construction re-hashes each key under the fixed seed rather than
        // touching input order, so shuffling the input key slice does not
        // change the result today — but it is not claimed here regardless,
        // matching xor_001 and fuse_001's stance that a future revision of
        // the peeling loop is free to become order sensitive.
        .without_order_independence()
        // The rate follows from the fixed fingerprint widths, not from the
        // request.
        .without_target_fpr()
        // Fingerprints are XORed across ARITY positions chosen per key by
        // peeling a hypergraph specific to this key set, same as fuse and
        // xor; combining two tables pointwise yields fingerprints belonging
        // to neither.
        .without_union()
        .without_intersection()
        // A fingerprint table carries no fill ratio to invert into a count.
        .without_cardinality_estimate(),
    build: Zor001::build_boxed,
    decode: Zor001::decode_boxed,
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
        let filter = Zor001::build(&as_slices(&owned), &Params::default()).unwrap();

        for key in &owned {
            assert!(filter.contains(key), "false negative for {key:?}");
        }
    }

    #[test]
    fn false_positive_rate_is_low() {
        let owned = keys(20_000);
        let filter = Zor001::build(&as_slices(&owned), &Params::default()).unwrap();

        let false_positives = (0..50_000)
            .map(|i| format!("absent-{i}").into_bytes())
            .filter(|k| filter.contains(k))
            .count();

        let observed = false_positives as f64 / 50_000.0;
        assert!(
            observed < 0.02,
            "observed false positive rate {observed} far above the expected ~0.4-0.8%"
        );
    }

    #[test]
    fn reported_rate_predicts_the_observed_rate() {
        let owned = keys(20_000);
        let filter = Zor001::build(&as_slices(&owned), &Params::default()).unwrap();

        let false_positives = (0..100_000)
            .map(|i| format!("absent-{i}").into_bytes())
            .filter(|k| filter.contains(k))
            .count();
        let observed = false_positives as f64 / 100_000.0;

        // Loose bound: the reported rate is a model, not a measurement: it
        // should be in the right ballpark, not exact to several digits.
        assert!(
            (filter.false_positive_rate() - observed).abs() < 0.02,
            "reported {} vs observed {observed}",
            filter.false_positive_rate()
        );
    }

    #[test]
    fn ignores_the_requested_false_positive_rate() {
        let owned = keys(500);
        let loose = Zor001::build(&as_slices(&owned), &Params::new(500, 0.1)).unwrap();
        let tight = Zor001::build(&as_slices(&owned), &Params::new(500, 0.0001)).unwrap();

        assert_eq!(loose.memory_bytes(), tight.memory_bytes());
    }

    #[test]
    fn duplicate_keys_are_found_via_the_auxiliary_rather_than_failing() {
        let owned = vec![b"same".to_vec(), b"same".to_vec()];
        let filter = Zor001::build(&as_slices(&owned), &Params::default()).unwrap();

        assert!(filter.contains(b"same"));
    }

    #[test]
    fn empty_key_set_builds_and_finds_nothing() {
        let filter = Zor001::build(&[], &Params::default()).unwrap();

        assert!(filter.is_empty());
        assert_eq!(filter.false_positive_rate(), 0.0);

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
            let err = Zor001::build(&[b"k"], &Params::new(1, rate)).unwrap_err();
            assert!(
                matches!(err, Error::InvalidParameter { .. }),
                "rate {rate} gave {err:?}, expected InvalidParameter"
            );
        }
    }

    #[test]
    fn single_key_builds() {
        let filter = Zor001::build(&[b"only"], &Params::default()).unwrap();
        assert!(filter.contains(b"only"));
        assert_eq!(filter.len(), 1);
    }

    #[test]
    fn two_keys_build() {
        let filter = Zor001::build(&[b"a", b"b"], &Params::default()).unwrap();
        assert!(filter.contains(b"a"));
        assert!(filter.contains(b"b"));
    }

    #[test]
    fn empty_key_is_a_valid_member() {
        let owned = vec![Vec::new()];
        let filter = Zor001::build(&as_slices(&owned), &Params::default()).unwrap();

        assert!(filter.contains(b""));
    }

    #[test]
    fn seed_changes_the_fingerprint_table() {
        let owned = keys(500);
        let a = Zor001::build(&as_slices(&owned), &Params::default().with_seed(1)).unwrap();
        let b = Zor001::build(&as_slices(&owned), &Params::default().with_seed(2)).unwrap();

        assert_ne!(a.fingerprints, b.fingerprints);
    }

    #[test]
    fn same_seed_reproduces_the_filter() {
        let owned = keys(500);
        let params = Params::default().with_seed(7);
        let a = Zor001::build(&as_slices(&owned), &params).unwrap();
        let b = Zor001::build(&as_slices(&owned), &params).unwrap();

        assert_eq!(a, b);
    }

    #[test]
    fn round_trips_through_encoding() {
        let owned = keys(2_000);
        let filter = Zor001::build(&as_slices(&owned), &Params::default()).unwrap();

        let mut bytes = Vec::new();
        filter.encode(&mut bytes).unwrap();

        let decoded = Zor001::decode(&bytes).unwrap();

        assert_eq!(filter, decoded);
        for key in &owned {
            assert!(decoded.contains(key));
        }
    }

    #[test]
    fn round_trips_when_nothing_is_abandoned() {
        // A small, well-behaved key set where the main structure alone
        // resolves everything, exercising the no-auxiliary encoding path.
        let owned = keys(3);
        let filter = Zor001::build(&as_slices(&owned), &Params::default()).unwrap();
        assert_eq!(filter.abandoned_len(), 0);

        let mut bytes = Vec::new();
        filter.encode(&mut bytes).unwrap();
        let decoded = Zor001::decode(&bytes).unwrap();

        assert_eq!(filter, decoded);
    }

    #[test]
    fn rejects_truncated_payload() {
        let payload = sample_payload();

        assert!(Zor001::decode(&payload[..payload.len() - 4]).is_err());
        assert!(Zor001::decode(&[]).is_err());
    }

    fn sample_payload() -> Vec<u8> {
        let owned = keys(2_000);
        let filter = Zor001::build(&as_slices(&owned), &Params::default()).unwrap();
        let mut bytes = Vec::new();
        filter.encode(&mut bytes).unwrap();
        bytes
    }

    fn rechecksum(payload: &mut [u8]) {
        Header::finalize(payload, 0);
    }

    /// Byte range of the header's `capacity` field, which zor uses for its
    /// main table's array length.
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

        assert!(Zor001::decode(&payload).is_err());
    }

    #[test]
    fn rejects_a_segment_length_that_is_not_a_power_of_two() {
        let mut payload = sample_payload();
        payload[SEGMENT_LENGTH_AT].copy_from_slice(&100u64.to_le_bytes());
        rechecksum(&mut payload);

        assert!(Zor001::decode(&payload).is_err());
    }

    #[test]
    fn rejects_a_zero_segment_count() {
        let mut payload = sample_payload();
        payload[SEGMENT_COUNT_AT].copy_from_slice(&0u64.to_le_bytes());
        rechecksum(&mut payload);

        assert!(Zor001::decode(&payload).is_err());
    }

    #[test]
    fn rejects_a_flipped_bit_anywhere_in_the_encoding() {
        let owned = keys(500);
        let filter = Zor001::build(&as_slices(&owned), &Params::default()).unwrap();
        let mut encoded = Vec::new();
        filter.encode(&mut encoded).unwrap();

        for offset in 0..encoded.len() {
            let mut corrupted = encoded.clone();
            corrupted[offset] ^= 0x01;

            assert!(
                Zor001::decode(&corrupted).is_err(),
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

        assert!(Zor001::decode(&payload).is_err());
    }

    #[test]
    fn rejects_another_version_of_this_family() {
        let mut payload = sample_payload();
        payload[4..8].copy_from_slice(&(VERSION + 1).to_le_bytes());
        rechecksum(&mut payload);

        assert!(Zor001::decode(&payload).is_err());
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
    fn is_smaller_than_a_comparable_fuse_filter() {
        // The whole point of abandonment: less overhead than fuse needs to
        // survive a full restart.
        let owned = keys(50_000);
        let zor = Zor001::build(&as_slices(&owned), &Params::default()).unwrap();
        let fuse = Fuse001::build(&as_slices(&owned), &Params::default()).unwrap();

        assert!(
            zor.memory_bytes() < fuse.memory_bytes(),
            "zor {} bytes, fuse {} bytes",
            zor.memory_bytes(),
            fuse.memory_bytes()
        );
    }

    #[test]
    fn abandoned_fraction_is_small() {
        let owned = keys(50_000);
        let filter = Zor001::build(&as_slices(&owned), &Params::default()).unwrap();

        let fraction = filter.abandoned_len() as f64 / owned.len() as f64;
        assert!(
            fraction < 0.1,
            "abandoned {} of {} keys ({fraction})",
            filter.abandoned_len(),
            owned.len()
        );
    }

    #[test]
    fn large_key_set_builds_and_finds_every_key() {
        let owned = keys(100_000);
        let filter = Zor001::build(&as_slices(&owned), &Params::default()).unwrap();

        for key in owned.iter().step_by(97) {
            assert!(filter.contains(key));
        }
    }

    #[test]
    fn every_key_is_found_across_many_sizes_and_seeds() {
        for n in [1usize, 2, 3, 10, 50, 200, 777, 2_000] {
            for seed in [0u64, 1, 42, u64::MAX] {
                let owned = keys(n);
                let filter =
                    Zor001::build(&as_slices(&owned), &Params::default().with_seed(seed)).unwrap();

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
