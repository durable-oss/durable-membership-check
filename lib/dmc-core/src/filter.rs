//! The object-safe filter trait and its build parameters.

use crate::error::Result;

/// Parameters requested of a filter at build time.
///
/// Not every filter honors every field. Bloom filters use both
/// [`expected_items`](Params::expected_items) and
/// [`false_positive_rate`](Params::false_positive_rate) to size themselves,
/// while xor and binary fuse filters derive their size from the key count
/// alone and use the fingerprint width implied by the implementation. A filter
/// that ignores a field documents that on its constructor.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Params {
    /// How many distinct keys the filter is expected to hold.
    ///
    /// Used for sizing. Filters built from a known key slice override this
    /// with the actual count.
    pub expected_items: usize,

    /// Target false positive rate, in `0.0..1.0` exclusive.
    ///
    /// Approximate membership filters cannot honor this exactly; treat it as
    /// a request, and read the achieved rate back from
    /// [`Filter::false_positive_rate`].
    pub false_positive_rate: f64,

    /// Seed for the filter's internal hashing.
    ///
    /// Fixing this makes construction deterministic, which matters for
    /// reproducible builds and for tests. Filters that retry construction with
    /// fresh seeds derive those from this value, so a fixed seed still yields
    /// a fixed result.
    pub seed: u64,
}

impl Default for Params {
    /// Returns parameters sized for 1,000 items at a 1% false positive rate.
    ///
    /// # Examples
    ///
    /// ```
    /// use dmc_core::Params;
    ///
    /// let params = Params::default();
    /// assert_eq!(params.expected_items, 1_000);
    /// assert!((params.false_positive_rate - 0.01).abs() < f64::EPSILON);
    /// ```
    fn default() -> Self {
        Self {
            expected_items: 1_000,
            false_positive_rate: 0.01,
            seed: 0,
        }
    }
}

impl Params {
    /// Creates parameters for `expected_items` keys at `false_positive_rate`.
    ///
    /// # Examples
    ///
    /// ```
    /// use dmc_core::Params;
    ///
    /// let params = Params::new(10_000, 0.001);
    /// assert_eq!(params.expected_items, 10_000);
    /// ```
    #[must_use]
    pub fn new(expected_items: usize, false_positive_rate: f64) -> Self {
        Self {
            expected_items,
            false_positive_rate,
            seed: 0,
        }
    }

    /// Returns these parameters with `seed` applied.
    ///
    /// # Examples
    ///
    /// ```
    /// use dmc_core::Params;
    ///
    /// let params = Params::new(100, 0.01).with_seed(42);
    /// assert_eq!(params.seed, 42);
    /// ```
    #[must_use]
    pub fn with_seed(self, seed: u64) -> Self {
        Self { seed, ..self }
    }

    /// Validates the parameters, returning an error describing the first problem.
    ///
    /// Filter constructors call this at their entry point, since parameters
    /// typically arrive from a trust boundary.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidParameter`](crate::Error::InvalidParameter) if
    /// `false_positive_rate` is not in `0.0..1.0` exclusive, or is not finite.
    ///
    /// # Examples
    ///
    /// ```
    /// use dmc_core::Params;
    ///
    /// assert!(Params::new(10, 0.01).validate().is_ok());
    /// assert!(Params::new(10, 1.5).validate().is_err());
    /// ```
    pub fn validate(&self) -> Result<()> {
        if !self.false_positive_rate.is_finite()
            || self.false_positive_rate <= 0.0
            || self.false_positive_rate >= 1.0
        {
            return Err(crate::Error::InvalidParameter {
                name: "false_positive_rate",
                reason: format!(
                    "must be in the open range 0.0..1.0, got {}",
                    self.false_positive_rate
                ),
            });
        }
        Ok(())
    }
}

/// A membership filter that can answer "have I seen this key?".
///
/// This trait is object-safe: callers hold `Box<dyn Filter>` and never need to
/// name the concrete implementation. That is what lets the Ruby binding, and
/// any CLI or benchmark harness, work against every registered filter without
/// a match arm per type.
///
/// # Approximation
///
/// Implementations may return `true` from [`contains`](Filter::contains) for a
/// key that was never inserted, at roughly the rate reported by
/// [`false_positive_rate`](Filter::false_positive_rate). No implementation may
/// return `false` for a key that was inserted; false negatives are a bug, not
/// a tuning parameter.
///
/// # Supertraits
///
/// `Debug` lets callers print a boxed filter and lets tests assert directly on
/// `Result<Box<dyn Filter>, _>`. `Send + Sync` reflects that a built filter is
/// immutable, so it can be shared across threads without further wrapping.
pub trait Filter: core::fmt::Debug + Send + Sync {
    /// Returns the implementation id that built this filter, such as `bloom_001`.
    ///
    /// This is the exact versioned id, never a family alias, so that encoded
    /// filters name the implementation that can decode them.
    fn id(&self) -> &'static str;

    /// Tests whether `key` may be present.
    ///
    /// Returns `false` only if `key` was definitely never inserted. A `true`
    /// result means the key is probably present, subject to
    /// [`false_positive_rate`](Filter::false_positive_rate).
    fn contains(&self, key: &[u8]) -> bool;

    /// Returns how many keys this filter was built from.
    fn len(&self) -> usize;

    /// Returns whether this filter holds no keys.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns how many bytes of memory the filter's backing store occupies.
    ///
    /// Excludes the size of the filter struct itself; this measures the bit
    /// array or fingerprint table, which is what dominates and what callers
    /// compare across implementations.
    fn memory_bytes(&self) -> usize;

    /// Returns the estimated false positive rate for this filter as built.
    ///
    /// This is derived from the filter's actual size and key count, so it may
    /// differ from the rate requested in [`Params`].
    fn false_positive_rate(&self) -> f64;

    /// Encodes the filter to bytes, appending to `out`.
    ///
    /// The encoding begins with the implementation id so that
    /// [`decode`](crate::registry::decode) can route the remaining bytes to
    /// the right implementation.
    ///
    /// # Errors
    ///
    /// Returns an error if the filter's state cannot be represented, which for
    /// current implementations cannot happen but is fallible so that future
    /// implementations backed by external storage can report failure.
    fn encode(&self, out: &mut Vec<u8>) -> Result<()>;
}
