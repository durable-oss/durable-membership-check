//! Declared behavioral axes on which correct filters legitimately differ.
//!
//! Filter families disagree about things that are not bugs. A Bloom filter
//! tolerates duplicate keys; an xor filter fails construction on them. A Bloom
//! filter reproduces bit-identically from shuffled input; a peeling filter
//! explores its hypergraph in input order and does not. Two Bloom filters of
//! the same shape combine by a bitwise OR into one holding both key sets; two
//! xor filters combined pointwise hold neither.
//!
//! A conformance suite that does not know which is which either skips real
//! assertions or fails correct implementations. So each implementation declares
//! its capabilities alongside its [`Registration`](crate::registry::Registration),
//! and the suite reads them rather than carrying its own table of special cases.
//!
//! # Defaults are the strictest setting
//!
//! [`Capabilities::default`] claims every guarantee a filter could offer. An
//! implementation that declares nothing therefore gets the most demanding
//! suite, and a forgotten declaration fails loudly instead of quietly
//! under-testing. Opting out is deliberate.

/// What a filter implementation guarantees beyond the [`Filter`](crate::Filter)
/// trait's own contract.
///
/// Start from [`Capabilities::strict`] and chain a `without_*` method for each
/// axis that diverges. Building this way rather than with a struct literal
/// means a new axis added in a future version arrives at its strict setting
/// instead of failing to compile, and an implementation that has not thought
/// about the new axis gets the demanding check rather than a skipped one.
///
/// The fields are public so a conformance suite can read them, and the methods
/// are `const` so a registration can build one in a `const` context.
///
/// # Examples
///
/// A Bloom filter diverges on nothing:
///
/// ```
/// use dmc_core::Capabilities;
///
/// let caps = Capabilities::strict();
///
/// assert!(caps.tolerates_duplicate_keys);
/// assert!(caps.order_independent_construction);
/// assert!(caps.supports_union);
/// assert!(!caps.supports_deletion);
/// ```
///
/// A peeling filter diverges on several, each named at the point it is given
/// up:
///
/// ```
/// use dmc_core::Capabilities;
///
/// let caps = Capabilities::strict()
///     // Peeling fails on a repeated key rather than absorbing it.
///     .without_duplicate_tolerance()
///     // Hypergraph construction visits keys in input order.
///     .without_order_independence()
///     // The rate follows from the fingerprint width, not from the request.
///     .without_target_fpr()
///     // Fingerprints are XORed across three slots chosen per key; combining
///     // two tables pointwise yields fingerprints belonging to neither.
///     .without_union()
///     .without_intersection()
///     // A fingerprint table carries no fill ratio to invert into a count.
///     .without_cardinality_estimate();
///
/// assert!(!caps.tolerates_duplicate_keys);
/// assert!(!caps.honors_target_fpr);
/// assert!(!caps.supports_union);
/// ```
// Clippy suggests a state enum past three bools. That advice is for structs
// whose bools encode one mode in combination; these are independent axes, and
// any subset can hold at once. An enum would need a variant per combination.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// Whether a key set containing repeats builds successfully.
    ///
    /// When `true`, duplicates are absorbed and every distinct key is found.
    /// When `false`, construction must report
    /// [`Error::ConstructionFailed`](crate::Error::ConstructionFailed) rather
    /// than returning a filter with false negatives.
    pub tolerates_duplicate_keys: bool,

    /// Whether shuffling the input key slice produces a byte-identical filter.
    ///
    /// True for filters that set bits commutatively. False for peeling filters,
    /// which explore their hypergraph in input order; those must still contain
    /// every member and report the same length.
    pub order_independent_construction: bool,

    /// Whether [`len`](crate::Filter::len) counts repeats in the input.
    ///
    /// A filter that rejects duplicate keys never observes one, so this axis
    /// only has content where `tolerates_duplicate_keys` is `true`.
    pub len_counts_duplicates: bool,

    /// Whether the filter sizes itself from
    /// [`Params::false_positive_rate`](crate::Params::false_positive_rate).
    ///
    /// False for xor and binary fuse filters, whose rate follows from a fixed
    /// fingerprint width. Those must still report their achieved rate
    /// accurately through
    /// [`false_positive_rate`](crate::Filter::false_positive_rate).
    pub honors_target_fpr: bool,

    /// Whether keys can be removed after construction.
    ///
    /// The [`Filter`](crate::Filter) trait exposes no deletion method today, so
    /// this is `false` for every current implementation and exists so the
    /// conformance suite is ready for counting and cuckoo filters.
    pub supports_deletion: bool,

    /// Whether the filter mutates itself in response to a query.
    ///
    /// Adaptive filters re-hash an entry after a detected false positive, which
    /// breaks the query-purity assertion that a built filter is unchanged by
    /// being read. An adaptive filter may never trade away the no-false-negative
    /// guarantee.
    pub is_adaptive: bool,

    /// Largest key count the implementation is designed to hold, if bounded.
    ///
    /// `None` means no hard structural limit beyond available memory. Filters
    /// with a fixed-capacity table report it here so the suite does not test
    /// them past the point where failure is the documented behavior.
    pub max_practical_keys: Option<usize>,

    /// Whether two compatible filters combine into one holding both key sets.
    ///
    /// True for filters whose backing store combines pointwise, which for a
    /// Bloom filter is a bitwise OR. The result must contain every member of
    /// both inputs: a union that loses a member is a false negative, and no
    /// filter may trade that away.
    ///
    /// False by default is not an option here — see [`Capabilities::strict`],
    /// which claims this, since a filter that cannot union says so explicitly.
    pub supports_union: bool,

    /// Whether two compatible filters combine into one holding their overlap.
    ///
    /// True for filters whose backing store intersects pointwise, a bitwise AND
    /// for a Bloom filter. Unlike union, this is only *approximately* the
    /// intersection: the result contains every key in both inputs, but its
    /// false positive rate is higher than either input's, because a bit
    /// survives when any key of A and any key of B both set it, not necessarily
    /// the same key. An implementation claiming this must report the inflated
    /// rate honestly through
    /// [`false_positive_rate`](crate::Filter::false_positive_rate).
    pub supports_intersection: bool,

    /// Whether the filter estimates how many distinct keys it holds.
    ///
    /// Distinct from [`len`](crate::Filter::len), which counts the keys the
    /// filter was *built* from. After a union those disagree: the result holds
    /// the union of two key sets, whose distinct count is not the sum. A filter
    /// claiming this derives the estimate from its own contents, so it stays
    /// meaningful after a set operation.
    pub estimates_cardinality: bool,
}

impl Capabilities {
    /// Returns the strictest declaration: every guarantee claimed.
    ///
    /// The starting point for every registration. Chain a `without_*` method
    /// per axis that genuinely diverges, and say why in a comment there.
    ///
    /// `const`, so a registration can build its capabilities without a lazy
    /// initializer.
    ///
    /// # Examples
    ///
    /// ```
    /// use dmc_core::Capabilities;
    ///
    /// const CAPS: Capabilities = Capabilities::strict();
    /// assert!(CAPS.honors_target_fpr);
    /// ```
    #[must_use]
    pub const fn strict() -> Self {
        Self {
            tolerates_duplicate_keys: true,
            order_independent_construction: true,
            len_counts_duplicates: true,
            honors_target_fpr: true,
            // Not a weakening: the trait has no deletion method, so a `true`
            // here would ask the suite to test an API that does not exist.
            supports_deletion: false,
            // Strict means "pure": the suite asserts querying does not mutate.
            is_adaptive: false,
            max_practical_keys: None,
            supports_union: true,
            supports_intersection: true,
            estimates_cardinality: true,
        }
    }

    /// Declares that a key set containing repeats fails construction.
    ///
    /// Also clears [`len_counts_duplicates`](Capabilities::len_counts_duplicates),
    /// since a filter that rejects duplicates never observes one and the axis
    /// has no content for it.
    ///
    /// # Examples
    ///
    /// ```
    /// use dmc_core::Capabilities;
    ///
    /// let caps = Capabilities::strict().without_duplicate_tolerance();
    /// assert!(!caps.tolerates_duplicate_keys);
    /// assert!(!caps.len_counts_duplicates);
    /// ```
    #[must_use]
    pub const fn without_duplicate_tolerance(self) -> Self {
        Self {
            tolerates_duplicate_keys: false,
            len_counts_duplicates: false,
            ..self
        }
    }

    /// Declares that shuffling the input changes the built filter.
    ///
    /// The suite then asserts the weaker property: both orderings contain
    /// every member and report the same length.
    ///
    /// # Examples
    ///
    /// ```
    /// use dmc_core::Capabilities;
    ///
    /// let caps = Capabilities::strict().without_order_independence();
    /// assert!(!caps.order_independent_construction);
    /// ```
    #[must_use]
    pub const fn without_order_independence(self) -> Self {
        Self {
            order_independent_construction: false,
            ..self
        }
    }

    /// Declares that the filter ignores the requested false positive rate.
    ///
    /// The suite drops the rate-accuracy sweep but still asserts that
    /// [`false_positive_rate`](crate::Filter::false_positive_rate) predicts the
    /// observed rate. A filter that ignores the request must still describe
    /// itself honestly.
    ///
    /// # Examples
    ///
    /// ```
    /// use dmc_core::Capabilities;
    ///
    /// let caps = Capabilities::strict().without_target_fpr();
    /// assert!(!caps.honors_target_fpr);
    /// ```
    #[must_use]
    pub const fn without_target_fpr(self) -> Self {
        Self {
            honors_target_fpr: false,
            ..self
        }
    }

    /// Declares that the filter supports removing keys after construction.
    ///
    /// Named `with_` rather than `without_` because the strict default is
    /// `false`: the [`Filter`](crate::Filter) trait exposes no deletion method,
    /// so claiming it is an addition rather than an opt-out.
    ///
    /// # Examples
    ///
    /// ```
    /// use dmc_core::Capabilities;
    ///
    /// let caps = Capabilities::strict().with_deletion();
    /// assert!(caps.supports_deletion);
    /// ```
    #[must_use]
    pub const fn with_deletion(self) -> Self {
        Self {
            supports_deletion: true,
            ..self
        }
    }

    /// Declares that the filter mutates itself in response to a query.
    ///
    /// The suite drops the query-purity check and instead asserts that
    /// adaptation preserves the no-false-negative guarantee, which is the one
    /// thing an adaptive filter may never trade away.
    ///
    /// # Examples
    ///
    /// ```
    /// use dmc_core::Capabilities;
    ///
    /// let caps = Capabilities::strict().as_adaptive();
    /// assert!(caps.is_adaptive);
    /// ```
    #[must_use]
    pub const fn as_adaptive(self) -> Self {
        Self {
            is_adaptive: true,
            ..self
        }
    }

    /// Declares that the filter cannot be combined with another by union.
    ///
    /// The suite drops the union checks. A filter whose backing store does not
    /// combine pointwise — a cuckoo filter, whose entries live in one of two
    /// buckets chosen at insert time — declares this rather than offering a
    /// union that could lose members.
    ///
    /// # Examples
    ///
    /// ```
    /// use dmc_core::Capabilities;
    ///
    /// let caps = Capabilities::strict().without_union();
    /// assert!(!caps.supports_union);
    /// ```
    #[must_use]
    pub const fn without_union(self) -> Self {
        Self {
            supports_union: false,
            ..self
        }
    }

    /// Declares that the filter cannot be combined with another by intersection.
    ///
    /// Independent of [`without_union`](Capabilities::without_union): a filter
    /// may support one and not the other. A counting Bloom filter, for
    /// instance, unions by summing counters but has no sound counter-wise
    /// intersection.
    ///
    /// # Examples
    ///
    /// ```
    /// use dmc_core::Capabilities;
    ///
    /// let caps = Capabilities::strict().without_intersection();
    /// assert!(!caps.supports_intersection);
    /// assert!(caps.supports_union, "the axes are independent");
    /// ```
    #[must_use]
    pub const fn without_intersection(self) -> Self {
        Self {
            supports_intersection: false,
            ..self
        }
    }

    /// Declares that the filter cannot estimate its own distinct key count.
    ///
    /// The suite then reads [`len`](crate::Filter::len) as the only count the
    /// filter offers, and skips the checks that compare an estimate against a
    /// known set size.
    ///
    /// # Examples
    ///
    /// ```
    /// use dmc_core::Capabilities;
    ///
    /// let caps = Capabilities::strict().without_cardinality_estimate();
    /// assert!(!caps.estimates_cardinality);
    /// ```
    #[must_use]
    pub const fn without_cardinality_estimate(self) -> Self {
        Self {
            estimates_cardinality: false,
            ..self
        }
    }

    /// Declares a hard upper bound on the key count the filter is designed for.
    ///
    /// The suite stops testing past this point, where failing is the documented
    /// behavior rather than a bug.
    ///
    /// # Examples
    ///
    /// ```
    /// use dmc_core::Capabilities;
    ///
    /// let caps = Capabilities::strict().with_max_keys(1 << 20);
    /// assert_eq!(caps.max_practical_keys, Some(1 << 20));
    /// ```
    #[must_use]
    pub const fn with_max_keys(self, keys: usize) -> Self {
        Self {
            max_practical_keys: Some(keys),
            ..self
        }
    }
}

impl Default for Capabilities {
    /// Returns the strictest declaration: every guarantee claimed.
    ///
    /// An implementation opts out of individual axes rather than opting in, so
    /// a filter author who forgets to declare gets a failing suite rather than
    /// a passing one that tested nothing.
    ///
    /// # Examples
    ///
    /// ```
    /// use dmc_core::Capabilities;
    ///
    /// let caps = Capabilities::default();
    /// assert!(caps.tolerates_duplicate_keys);
    /// assert!(caps.order_independent_construction);
    /// assert!(caps.honors_target_fpr);
    /// assert_eq!(caps.max_practical_keys, None);
    /// ```
    ///
    /// Deletion and adaptivity are the two axes whose strict setting is
    /// `false`: claiming them would make the suite assert behavior the
    /// `Filter` trait cannot yet express.
    ///
    /// ```
    /// use dmc_core::Capabilities;
    ///
    /// let caps = Capabilities::default();
    /// assert!(!caps.supports_deletion);
    /// assert!(!caps.is_adaptive);
    /// ```
    ///
    /// Identical to [`Capabilities::strict`], which is `const` and is what a
    /// registration should call.
    fn default() -> Self {
        Self::strict()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_claims_every_optional_guarantee() {
        let caps = Capabilities::default();

        assert!(caps.tolerates_duplicate_keys);
        assert!(caps.order_independent_construction);
        assert!(caps.len_counts_duplicates);
        assert!(caps.honors_target_fpr);
        assert!(caps.supports_union);
        assert!(caps.supports_intersection);
        assert!(caps.estimates_cardinality);
        assert_eq!(caps.max_practical_keys, None);
    }

    #[test]
    fn set_operation_axes_are_independent() {
        // A counting Bloom filter unions by summing counters but has no sound
        // counter-wise intersection, so dropping one must not drop the other.
        let caps = Capabilities::strict().without_intersection();

        assert!(!caps.supports_intersection);
        assert!(caps.supports_union);
        assert!(caps.estimates_cardinality);
    }

    #[test]
    fn default_does_not_claim_capabilities_the_trait_cannot_express() {
        // `Filter` has no delete method and no interior mutability, so
        // claiming these by default would ask the suite to test nothing.
        let caps = Capabilities::default();

        assert!(!caps.supports_deletion);
        assert!(!caps.is_adaptive);
    }

    #[test]
    fn struct_update_syntax_leaves_other_axes_strict() {
        let caps = Capabilities {
            tolerates_duplicate_keys: false,
            ..Capabilities::default()
        };

        assert!(!caps.tolerates_duplicate_keys);
        assert!(caps.order_independent_construction, "unrelated axis moved");
    }
}
