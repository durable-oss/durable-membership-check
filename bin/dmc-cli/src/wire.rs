//! The JSON shapes exchanged with a client.
//!
//! Both modes speak the same vocabulary. In `serve` mode a [`Request`] arrives
//! per line on stdin and a [`Response`] leaves per line on stdout; in one-shot
//! mode the subcommand arguments are assembled into the same [`Request`] and
//! the single [`Response`] is printed. Keeping one set of types means the two
//! paths cannot drift apart in what they accept or report.
//!
//! # Keys are hex
//!
//! Keys are arbitrary bytes, and JSON strings are Unicode. Every key crosses
//! the boundary as a lowercase hex string so that a key containing a NUL, a
//! lone `0xFF`, or an invalid UTF-8 sequence survives the trip unchanged.
//! Those keys are exactly the ones the correctness suite cares about.

use serde::{Deserialize, Serialize};

/// A command from the client.
///
/// `serde` tags these by a `cmd` field, so a line reads as
/// `{"cmd":"contains","handle":1,...}`.
#[derive(Debug, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Lists every filter implementation linked into this binary.
    List,

    /// Reports one implementation's metadata and declared capabilities.
    Describe {
        /// Exact implementation id or family alias.
        name: String,
    },

    /// Builds a filter and retains it under a handle.
    Build {
        /// Exact implementation id or family alias.
        name: String,

        /// Keys to insert, hex-encoded.
        #[serde(default)]
        keys_hex: Vec<String>,

        /// Build parameters. Omitted fields take their `Params::default` value.
        #[serde(default)]
        params: ParamsSpec,
    },

    /// Queries a retained filter for membership.
    Contains {
        /// Handle returned by a previous `build` or `decode`.
        handle: u64,

        /// Keys to test, hex-encoded.
        keys_hex: Vec<String>,
    },

    /// Reports a retained filter's accounting fields.
    Info {
        /// Handle returned by a previous `build` or `decode`.
        handle: u64,
    },

    /// Encodes a retained filter to bytes.
    Encode {
        /// Handle returned by a previous `build` or `decode`.
        handle: u64,
    },

    /// Decodes bytes into a new retained filter.
    Decode {
        /// Encoded filter, hex-encoded.
        bytes_hex: String,
    },

    /// Combines two retained filters into a new one holding both key sets.
    Union {
        /// Left operand.
        left: u64,

        /// Right operand.
        right: u64,
    },

    /// Combines two retained filters into one holding their overlap.
    Intersect {
        /// Left operand.
        left: u64,

        /// Right operand.
        right: u64,
    },

    /// Estimates how many distinct keys a retained filter holds.
    EstimatedLen {
        /// Handle to estimate.
        handle: u64,
    },

    /// Estimates how alike two retained filters' key sets are.
    ///
    /// Reports the Jaccard similarity and both containment directions in one
    /// reply. Containment is asymmetric, so a client asking "is A inside B?"
    /// needs to know which side it got; sending both removes the ambiguity and
    /// costs one extra popcount.
    Similarity {
        /// Left operand.
        left: u64,

        /// Right operand.
        right: u64,
    },

    /// Releases a retained filter.
    Drop {
        /// Handle to release.
        handle: u64,
    },

    /// Ends a `serve` session.
    Quit,
}

/// Build parameters as they arrive over the wire.
///
/// Separate from [`dmc_core::Params`] because every field is optional here: a
/// client that cares only about the seed should not have to restate the rest,
/// and a missing field must mean "the documented default" rather than zero.
#[derive(Debug, Default, Deserialize)]
pub struct ParamsSpec {
    /// How many distinct keys the filter is expected to hold.
    pub expected_items: Option<usize>,

    /// Target false positive rate.
    ///
    /// Passed through unvalidated so that a client can deliberately send an
    /// out-of-range value and observe the `InvalidParameter` error. Validation
    /// belongs to the filter, not to this layer.
    ///
    /// Accepts a JSON number, or one of the strings `"nan"`, `"inf"`, and
    /// `"-inf"`. `Params::validate` rejects non-finite rates explicitly, so
    /// they are a test case — but JSON has no way to write them as numbers, so
    /// a client would otherwise be unable to reach that code path at all.
    #[serde(default, deserialize_with = "deserialize_rate")]
    pub false_positive_rate: Option<f64>,

    /// Seed for the filter's internal hashing.
    pub seed: Option<u64>,
}

/// Accepts a false positive rate as a number or as a non-finite keyword.
///
/// JSON cannot represent NaN or the infinities as numbers, and
/// `Params::validate` rejects all three by name. Without this a client could
/// not reach that validation at all, leaving the branch untestable from
/// outside the process.
fn deserialize_rate<'de, D>(deserializer: D) -> Result<Option<f64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    /// A rate as it may appear on the wire.
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Rate {
        /// The ordinary case.
        Number(f64),

        /// One of the non-finite keywords, case-insensitive.
        Keyword(String),
    }

    let Some(rate) = Option::<Rate>::deserialize(deserializer)? else {
        return Ok(None);
    };

    match rate {
        Rate::Number(value) => Ok(Some(value)),
        Rate::Keyword(word) => match word.to_ascii_lowercase().as_str() {
            "nan" => Ok(Some(f64::NAN)),
            "inf" | "infinity" | "+inf" => Ok(Some(f64::INFINITY)),
            "-inf" | "-infinity" => Ok(Some(f64::NEG_INFINITY)),
            other => Err(serde::de::Error::custom(format!(
                "false_positive_rate must be a number or one of \
                 \"nan\", \"inf\", \"-inf\"; got {other:?}"
            ))),
        },
    }
}

impl ParamsSpec {
    /// Resolves into concrete parameters, defaulting each absent field.
    ///
    /// `expected_items` defaults to the supplied key count rather than to
    /// `Params::default`'s 1,000, because a client that passes keys and no
    /// sizing means "size for these".
    #[must_use]
    pub fn resolve(&self, key_count: usize) -> dmc_core::Params {
        let defaults = dmc_core::Params::default();

        dmc_core::Params {
            expected_items: self.expected_items.unwrap_or(key_count),
            false_positive_rate: self
                .false_positive_rate
                .unwrap_or(defaults.false_positive_rate),
            seed: self.seed.unwrap_or(defaults.seed),
        }
    }
}

/// A reply to a [`Request`].
///
/// Every reply carries `ok`, so a client checks one field before reading the
/// rest. An error is a normal reply, not a broken pipe: sending deliberately
/// invalid input and reading back a structured error is how the correctness
/// suite tests the error paths.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum Response {
    /// The command succeeded.
    Ok(Payload),

    /// The command failed.
    Err {
        /// Always `false`.
        ok: bool,

        /// Which error variant fired, in `snake_case`.
        ///
        /// A client matches on this rather than on the message, so that
        /// rewording an error does not break a test.
        kind: String,

        /// The error's `Display` output.
        message: String,
    },
}

impl Response {
    /// Builds an error reply from a `dmc_core::Error`.
    ///
    /// The `kind` mirrors the variant name so a client can assert which error
    /// fired without parsing prose.
    #[must_use]
    pub fn from_error(err: &dmc_core::Error) -> Self {
        let kind = match err {
            dmc_core::Error::InvalidParameter { .. } => "invalid_parameter",
            dmc_core::Error::UnknownFilter { .. } => "unknown_filter",
            dmc_core::Error::ConstructionFailed { .. } => "construction_failed",
            dmc_core::Error::Corrupt { .. } => "corrupt",
            dmc_core::Error::UnknownEncoding { .. } => "unknown_encoding",
            dmc_core::Error::Incompatible { .. } => "incompatible",
            // `Error` is `#[non_exhaustive]`, so a variant added upstream
            // reaches the client as a named catch-all rather than as a panic.
            _ => "other",
        };

        Self::Err {
            ok: false,
            kind: kind.to_string(),
            message: err.to_string(),
        }
    }

    /// Builds an error reply for a failure that is not a `dmc_core::Error`.
    ///
    /// Malformed hex and unknown handles originate in this binary rather than
    /// in the library, and get their own kinds so a client can tell a harness
    /// bug from a filter bug.
    #[must_use]
    pub fn client_error(kind: &str, message: impl Into<String>) -> Self {
        Self::Err {
            ok: false,
            kind: kind.to_string(),
            message: message.into(),
        }
    }
}

/// The successful reply bodies.
///
/// Untagged: each variant is distinguished by its fields, so a client reads
/// `answers` from a `contains` reply without also matching a discriminator it
/// already knows from the request it sent.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum Payload {
    /// Reply to `list`.
    List {
        /// Always `true`.
        ok: bool,

        /// Every linked implementation, sorted by id.
        filters: Vec<FilterInfo>,
    },

    /// Reply to `describe`.
    Describe {
        /// Always `true`.
        ok: bool,

        /// The implementation the requested name resolved to.
        filter: FilterInfo,
    },

    /// Reply to `build` and `decode`.
    Built {
        /// Always `true`.
        ok: bool,

        /// Handle for later `contains`, `info`, `encode`, and `drop`.
        handle: u64,

        /// The filter's own accounting.
        info: BuiltInfo,
    },

    /// Reply to `contains`.
    Answers {
        /// Always `true`.
        ok: bool,

        /// One answer per probe key, in the order supplied.
        answers: Vec<bool>,
    },

    /// Reply to `info`.
    Info {
        /// Always `true`.
        ok: bool,

        /// The filter's own accounting.
        info: BuiltInfo,
    },

    /// Reply to `encode`.
    Encoded {
        /// Always `true`.
        ok: bool,

        /// The encoded filter, hex-encoded.
        bytes_hex: String,
    },

    /// Reply to `estimated_len`.
    Estimate {
        /// Always `true`.
        ok: bool,

        /// Estimated distinct key count.
        estimated_len: usize,
    },

    /// Reply to `similarity`.
    Similarity {
        /// Always `true`.
        ok: bool,

        /// Estimated Jaccard similarity, `|A ∩ B| / |A ∪ B|`.
        jaccard: f64,

        /// Estimated fraction of the left filter's keys found in the right.
        containment_left_in_right: f64,

        /// Estimated fraction of the right filter's keys found in the left.
        containment_right_in_left: f64,
    },

    /// Reply to `drop` and `quit`.
    Done {
        /// Always `true`.
        ok: bool,
    },
}

/// An implementation's registry entry, as reported to a client.
///
/// This is the metadata the Ruby suite reads to decide which checks apply, so
/// that adding a filter extends the suite without editing it.
#[derive(Debug, Serialize)]
pub struct FilterInfo {
    /// Versioned implementation id, such as `bloom_001`.
    pub id: String,

    /// Family name, such as `bloom`.
    pub family: String,

    /// Version within the family.
    pub version: u32,

    /// One-line description.
    pub description: String,

    /// The id the family alias currently resolves to.
    ///
    /// Lets a client check alias resolution without a second round trip.
    pub family_resolves_to: Option<String>,

    /// What this implementation guarantees beyond the `Filter` trait.
    pub capabilities: CapabilitiesInfo,
}

/// A [`dmc_core::Capabilities`] flattened for the wire.
///
/// Mirrored rather than derived on the core type, so that `dmc-core` does not
/// take a serde dependency to satisfy a CLI.
// Independent axes rather than one mode split across bools; see the same note
// on `dmc_core::Capabilities`, whose shape this mirrors field for field.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Serialize)]
pub struct CapabilitiesInfo {
    /// Whether a key set containing repeats builds successfully.
    pub tolerates_duplicate_keys: bool,

    /// Whether shuffling the input yields a byte-identical filter.
    pub order_independent_construction: bool,

    /// Whether `len` counts repeats in the input.
    pub len_counts_duplicates: bool,

    /// Whether the filter sizes itself from the requested rate.
    pub honors_target_fpr: bool,

    /// Whether keys can be removed after construction.
    pub supports_deletion: bool,

    /// Whether the filter mutates itself in response to a query.
    pub is_adaptive: bool,

    /// Largest key count the implementation is designed for, if bounded.
    pub max_practical_keys: Option<usize>,

    /// Whether two compatible filters combine into one holding both key sets.
    pub supports_union: bool,

    /// Whether two compatible filters combine into one holding their overlap.
    pub supports_intersection: bool,

    /// Whether the filter estimates how many distinct keys it holds.
    pub estimates_cardinality: bool,
}

impl From<&dmc_core::Capabilities> for CapabilitiesInfo {
    fn from(caps: &dmc_core::Capabilities) -> Self {
        Self {
            tolerates_duplicate_keys: caps.tolerates_duplicate_keys,
            order_independent_construction: caps.order_independent_construction,
            len_counts_duplicates: caps.len_counts_duplicates,
            honors_target_fpr: caps.honors_target_fpr,
            supports_deletion: caps.supports_deletion,
            is_adaptive: caps.is_adaptive,
            max_practical_keys: caps.max_practical_keys,
            supports_union: caps.supports_union,
            supports_intersection: caps.supports_intersection,
            estimates_cardinality: caps.estimates_cardinality,
        }
    }
}

/// A built filter's accounting, as reported to a client.
#[derive(Debug, Serialize)]
pub struct BuiltInfo {
    /// The exact implementation id that built it.
    pub id: String,

    /// How many keys it was built from.
    pub len: usize,

    /// Whether it holds no keys.
    pub is_empty: bool,

    /// Bytes occupied by the backing store.
    pub memory_bytes: usize,

    /// Estimated false positive rate as built.
    pub false_positive_rate: f64,
}

impl BuiltInfo {
    /// Reads the accounting fields off a built filter.
    #[must_use]
    pub fn of(filter: &dyn dmc_core::Filter) -> Self {
        Self {
            id: filter.id().to_string(),
            len: filter.len(),
            is_empty: filter.is_empty(),
            memory_bytes: filter.memory_bytes(),
            false_positive_rate: filter.false_positive_rate(),
        }
    }
}
