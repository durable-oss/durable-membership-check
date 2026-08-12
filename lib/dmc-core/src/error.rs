//! Error types for filter construction and decoding.

use core::fmt;

/// Errors returned by filter construction, encoding, and decoding.
///
/// Each variant is intended to be matchable by callers. Programmer errors
/// (for example, passing a `false_positive_rate` outside `0.0..1.0`) are
/// reported as [`Error::InvalidParameter`] rather than panicking, because the
/// parameters usually originate at a trust boundary such as the Ruby binding
/// or a config file.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A build parameter was outside its valid range.
    InvalidParameter {
        /// The parameter that was rejected.
        name: &'static str,
        /// Why it was rejected.
        reason: String,
    },

    /// No registered implementation matched the requested name.
    UnknownFilter {
        /// The name that was requested.
        requested: String,
    },

    /// Construction failed after exhausting its retry budget.
    ///
    /// Xor and binary fuse filters build by peeling a random hypergraph. A
    /// given seed can fail to peel; the builder retries with new seeds. This
    /// error means every attempt failed, which in practice indicates the key
    /// set contains duplicates or the capacity is too small.
    ConstructionFailed {
        /// How many seeds were tried.
        attempts: u32,
    },

    /// Encoded bytes were not valid for this filter.
    Corrupt {
        /// What the decoder expected to find.
        expected: &'static str,
    },

    /// Encoded bytes were produced by an implementation that is not linked in.
    ///
    /// The registry resolves by the exact `(family_code, version)` pair in the
    /// header, so a filter encoded by `bloom_002` cannot be decoded by a binary
    /// that only links `bloom_001`.
    UnknownEncoding {
        /// Numeric family recorded in the header.
        family_code: u32,

        /// Implementation version recorded in the header.
        version: u32,

        /// Family name, when `family_code` is one this build knows.
        ///
        /// `Some` even for a version that is not linked in, since the name
        /// comes from a static table rather than from the registry. `None` for
        /// a private-use code, which no table here can name.
        family: Option<&'static str>,
    },

    /// Two filters were combined whose shapes do not match.
    ///
    /// Set operations on a Bloom filter are bitwise operations on its backing
    /// array, so they are only defined between filters whose bit count, hash
    /// count, and seed all agree. Combining mismatched filters would produce a
    /// filter with false negatives, which is why this is an error rather than a
    /// best-effort merge.
    Incompatible {
        /// Which aspect of the shape disagreed, such as `bit_count`.
        aspect: &'static str,

        /// The left-hand filter's value, rendered.
        left: String,

        /// The right-hand filter's value, rendered.
        right: String,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidParameter { name, reason } => {
                write!(f, "invalid parameter `{name}`: {reason}")
            }
            Self::UnknownFilter { requested } => {
                write!(f, "no registered filter named `{requested}`")
            }
            Self::ConstructionFailed { attempts } => write!(
                f,
                "filter construction failed after {attempts} attempts; \
                 the key set may contain duplicates"
            ),
            Self::Corrupt { expected } => {
                write!(f, "corrupt encoded filter: expected {expected}")
            }
            Self::UnknownEncoding {
                family_code,
                version,
                family,
            } => match family {
                // A known family renders the id an operator would recognize,
                // which is what tells them the feature to enable. The code is
                // still shown, since it is what the bytes actually contain.
                Some(name) => write!(
                    f,
                    "encoded filter requires implementation `{name}_{version:03}` \
                     (family {family_code}), which is not linked in"
                ),
                // A private-use code names nothing this build can resolve, so
                // the numbers are all there is to report.
                None => write!(
                    f,
                    "encoded filter requires family {family_code} version {version}, \
                     which is not linked in and is not a family this build knows"
                ),
            },
            Self::Incompatible {
                aspect,
                left,
                right,
            } => {
                write!(
                    f,
                    "filters are not compatible: {aspect} differs ({left} vs {right})"
                )
            }
        }
    }
}

impl core::error::Error for Error {}

/// Result alias used throughout the crate.
pub type Result<T> = core::result::Result<T, Error>;
