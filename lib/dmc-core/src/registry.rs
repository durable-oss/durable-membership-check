//! Compile-time plugin registry for filter implementations.
//!
//! Every filter implementation submits a [`Registration`] via [`inventory`].
//! Linking a filter crate is all it takes to make that filter reachable by
//! name from the Ruby binding, a CLI, or a benchmark harness; no downstream
//! code enumerates implementations by hand.
//!
//! # Implementation ids and family aliases
//!
//! An implementation registers under a versioned id such as `bloom_001`. That
//! id names a frozen implementation: once published, the keys it accepts and
//! rejects never change. A behavior-preserving fix (speed, memory) lands in
//! place; a change to which keys hit ships as `bloom_002` instead.
//!
//! The family name `bloom` is an alias that resolves to the highest registered
//! version in that family, computed when the registry index is first built. So
//! linking `bloom_002` moves the alias with no edits anywhere. Use
//! [`resolve_alias`] to see where an alias currently points.

use crate::capabilities::Capabilities;
use crate::error::{Error, Result};
use crate::filter::{Filter, Params};
use crate::header::Header;
use std::collections::BTreeMap;
use std::sync::OnceLock;

/// Builds a filter from a complete key set.
pub type BuildFn = fn(keys: &[&[u8]], params: &Params) -> Result<Box<dyn Filter>>;

/// Reconstructs a filter from its complete encoding, header included.
///
/// The registry routes on the header and then hands the whole encoding to the
/// implementation, rather than splitting it first: the implementation needs the
/// header's `seed`, `capacity`, and custom slots to rebuild itself, so passing
/// only the body would mean parsing the header twice.
pub type DecodeFn = fn(bytes: &[u8]) -> Result<Box<dyn Filter>>;

/// A filter implementation's entry in the registry.
///
/// Implementations construct this through the
/// [`register_filter!`](crate::register_filter) macro rather than by hand, so
/// that the id format stays consistent.
pub struct Registration {
    /// Versioned implementation id, such as `bloom_001`.
    pub id: &'static str,

    /// Family name that the id belongs to, such as `bloom`.
    pub family: &'static str,

    /// Numeric family, written into every encoding's header.
    ///
    /// Derived from [`family`](Registration::family) by
    /// [`register_filter!`](crate::register_filter) for families that
    /// [`family::KNOWN`](crate::family::KNOWN) lists, and supplied explicitly
    /// by out-of-tree implementations. See [`family`](crate::family) for the
    /// code space.
    pub family_code: u32,

    /// Version within the family. The family alias resolves to the highest.
    pub version: u32,

    /// One-line description, shown when listing available filters.
    pub description: &'static str,

    /// What this implementation guarantees beyond the [`Filter`] trait.
    ///
    /// Read by the conformance suite to decide which checks apply. See
    /// [`Capabilities`] for the axes and why the defaults are the strict
    /// setting.
    pub capabilities: Capabilities,

    /// Builds a filter from a key set.
    pub build: BuildFn,

    /// Decodes a filter from bytes previously produced by `Filter::encode`.
    pub decode: DecodeFn,
}

inventory::collect!(Registration);

/// Index over the registrations, built once on first use.
// The `by_*` names say what each map is keyed on, which is the whole content of
// this struct; renaming them to satisfy the prefix lint would lose that.
#[allow(clippy::struct_field_names)]
struct Index {
    /// Every registration keyed by exact implementation id.
    by_id: BTreeMap<&'static str, &'static Registration>,

    /// Family name to the highest-versioned registration in that family.
    by_family: BTreeMap<&'static str, &'static Registration>,

    /// Every registration keyed by the `(family_code, version)` pair that
    /// appears in an encoded header. This is what [`decode`] routes on.
    by_code: BTreeMap<(u32, u32), &'static Registration>,
}

fn index() -> &'static Index {
    static INDEX: OnceLock<Index> = OnceLock::new();
    INDEX.get_or_init(|| {
        let mut by_id = BTreeMap::new();
        let mut by_family: BTreeMap<&'static str, &'static Registration> = BTreeMap::new();
        let mut by_code = BTreeMap::new();

        for reg in inventory::iter::<Registration> {
            by_id.insert(reg.id, reg);
            by_code.insert((reg.family_code, reg.version), reg);

            by_family
                .entry(reg.family)
                .and_modify(|current| {
                    if reg.version > current.version {
                        *current = reg;
                    }
                })
                .or_insert(reg);
        }

        Index {
            by_id,
            by_family,
            by_code,
        }
    })
}

/// Looks up a registration by exact id or by family alias.
///
/// Exact ids win over family aliases, so a family named the same as an
/// implementation id resolves to the implementation.
fn lookup(name: &str) -> Option<&'static Registration> {
    let idx = index();
    idx.by_id
        .get(name)
        .or_else(|| idx.by_family.get(name))
        .copied()
}

/// Returns the registration a name resolves to, by exact id or family alias.
///
/// Resolution matches [`build`] exactly, so a caller can inspect what a name
/// would build before building it. That is what a CLI's `describe` subcommand
/// and the conformance suite both need: the [`Capabilities`] of the
/// implementation that a given name reaches.
///
/// # Examples
///
/// This crate registers no filters of its own, so lookups through it find
/// nothing until an implementation crate is linked:
///
/// ```
/// assert!(dmc_core::registry::find("bloom").is_none());
/// ```
#[must_use]
pub fn find(name: &str) -> Option<&'static Registration> {
    lookup(name)
}

/// Builds a filter by name from a set of keys.
///
/// `name` may be an exact implementation id (`bloom_001`) or a family alias
/// (`bloom`), which resolves to the highest registered version.
///
/// Duplicate keys are permitted for bloom filters but not for the peeling
/// filters; see each implementation's docs.
///
/// # Errors
///
/// Returns [`Error::UnknownFilter`] if no registered implementation matches
/// `name`, or whatever error the implementation's builder reports, including
/// [`Error::InvalidParameter`] for out-of-range parameters.
///
/// # Examples
///
/// This crate registers no filters of its own, so building through it only
/// succeeds once an implementation crate is linked. Depend on `dmc` for a
/// working catalog; here, an unregistered name reports itself:
///
/// ```
/// use dmc_core::{build, Error, Params};
///
/// let err = build("bloom", &[], &Params::default()).unwrap_err();
/// assert!(matches!(err, Error::UnknownFilter { .. }));
/// ```
pub fn build(name: &str, keys: &[&[u8]], params: &Params) -> Result<Box<dyn Filter>> {
    let reg = lookup(name).ok_or_else(|| Error::UnknownFilter {
        requested: name.to_string(),
    })?;
    (reg.build)(keys, params)
}

/// Returns every registered implementation, sorted by id.
///
/// Callers that need to present a catalog (a CLI's `--list`, the Ruby
/// binding's `DMC.filters`) use this rather than hardcoding names.
pub fn registrations() -> impl Iterator<Item = &'static Registration> {
    index().by_id.values().copied()
}

/// Returns the implementation id that a family alias currently resolves to.
///
/// Returns `None` if `name` is not a known family. An exact implementation id
/// is not a family, so `resolve_alias("bloom_001")` returns `None` while
/// `resolve_alias("bloom")` returns `Some("bloom_001")`.
///
/// This exists so alias resolution is inspectable: linking a new
/// implementation silently moves an alias, and this is how you check where it
/// landed.
#[must_use]
pub fn resolve_alias(name: &str) -> Option<&'static str> {
    index().by_family.get(name).map(|reg| reg.id)
}

/// Decodes a filter previously produced by [`Filter::encode`].
///
/// Routing is by the exact `(family_code, version)` pair in the header, never
/// by family alias. A filter encoded by `bloom_002` will not silently decode as
/// `bloom_001` just because that is what the alias points to in this binary.
///
/// # Errors
///
/// Returns [`Error::Corrupt`] if the bytes lack a well-formed
/// [`Header`], or [`Error::UnknownEncoding`] if the
/// implementation the header names is not linked into this binary.
pub fn decode(bytes: &[u8]) -> Result<Box<dyn Filter>> {
    // Only to route: the implementation re-reads the header for the fields it
    // needs, so the body is discarded here.
    let (header, _) = Header::decode(bytes)?;

    let reg = index()
        .by_code
        .get(&(header.family_code, header.version))
        .ok_or(Error::UnknownEncoding {
            family_code: header.family_code,
            version: header.version,
            family: header.family(),
        })?;

    (reg.decode)(bytes)
}

/// Registers a filter implementation with the plugin registry.
///
/// The id is built here from the family and the zero-padded version, so the
/// two cannot drift apart: there is no way to register an id of `bloom_002`
/// under family `xor`, because the id is not something the caller supplies.
///
/// `id` is still accepted as an optional literal, and when given it must equal
/// the constructed id. Write it out when you want the exact string greppable
/// from the registration site; omit it and the macro derives it.
///
/// `capabilities` is optional and defaults to
/// [`Capabilities::strict`](crate::Capabilities::strict), which claims every
/// guarantee. Chain a `without_*` method per axis on which the implementation
/// genuinely diverges, and say why in a comment there — the conformance suite
/// turns each one into a skipped check.
///
/// `family_code` is optional for a family that
/// [`family::KNOWN`](crate::family::KNOWN) lists, since the macro looks it up
/// at compile time. A family this project does not know needs one explicitly,
/// at or above [`PRIVATE_USE_START`](crate::family::PRIVATE_USE_START);
/// omitting it there is a compile error at the registration site.
///
/// # Examples
///
/// ```ignore
/// dmc_core::register_filter! {
///     family: "xor",
///     version: 1,
///     description: "Xor filter built by hypergraph peeling.",
///     capabilities: dmc_core::Capabilities::strict()
///         // Peeling fails on a repeated key rather than absorbing it.
///         .without_duplicate_tolerance()
///         // Construction visits keys in input order.
///         .without_order_independence(),
///     build: XorFilter::build_boxed,
///     decode: XorFilter::decode_boxed,
/// }
/// ```
///
/// An out-of-tree family assigns its own code:
///
/// ```ignore
/// dmc_core::register_filter! {
///     family: "acme-sketch",
///     family_code: 1_000,
///     version: 1,
///     description: "Acme's in-house sketch.",
///     build: AcmeSketch::build_boxed,
///     decode: AcmeSketch::decode_boxed,
/// }
/// ```
#[macro_export]
macro_rules! register_filter {
    // Full form: an explicit id, checked against the derived one at compile time.
    (
        family: $family:literal,
        $(family_code: $family_code:expr,)?
        version: $version:literal,
        id: $id:literal,
        description: $description:literal,
        $(capabilities: $capabilities:expr,)?
        build: $build:path,
        decode: $decode:path $(,)?
    ) => {
        const _: () = {
            // A byte-for-byte check that the written id matches the one the
            // macro derives. A mismatch fails the build at the registration
            // site rather than surfacing as a filter nobody can decode.
            let written = $id.as_bytes();
            let derived = $crate::filter_id!($family, $version).as_bytes();
            assert!(
                written.len() == derived.len(),
                "register_filter!: `id` does not match `family_NNN` built from `family` and `version`",
            );
            let mut i = 0;
            while i < written.len() {
                assert!(
                    written[i] == derived[i],
                    "register_filter!: `id` does not match `family_NNN` built from `family` and `version`",
                );
                i += 1;
            }
        };

        $crate::register_filter! {
            family: $family,
            $(family_code: $family_code,)?
            version: $version,
            description: $description,
            $(capabilities: $capabilities,)?
            build: $build,
            decode: $decode,
        }
    };

    // Derived form, no explicit code: the family must be one the table lists.
    //
    // Split into its own arm rather than folded into the arm below with an
    // optional fragment, because `require_code_for` panics at compile time on
    // an unknown family. Expanding it alongside an explicit code would fail the
    // build for exactly the out-of-tree registrations the explicit code exists
    // to serve.
    (
        family: $family:literal,
        version: $version:literal,
        description: $description:literal,
        $(capabilities: $capabilities:expr,)?
        build: $build:path,
        decode: $decode:path $(,)?
    ) => {
        $crate::register_filter! {
            family: $family,
            family_code: $crate::family::require_code_for($family),
            version: $version,
            description: $description,
            $(capabilities: $capabilities,)?
            build: $build,
            decode: $decode,
        }
    };

    // Derived form with an explicit code, and the arm every other form lands
    // on once its defaults are resolved.
    (
        family: $family:literal,
        family_code: $family_code:expr,
        version: $version:literal,
        description: $description:literal,
        $(capabilities: $capabilities:expr,)?
        build: $build:path,
        decode: $decode:path $(,)?
    ) => {
        $crate::inventory::submit! {
            $crate::registry::Registration {
                id: $crate::filter_id!($family, $version),
                family: $family,
                family_code: $family_code,
                version: $version,
                description: $description,
                // Absent a `capabilities` clause this is the strict setting,
                // so a filter author who forgets one gets the full suite.
                capabilities: {
                    #[allow(unused_mut, unused_assignments)]
                    let mut caps = $crate::Capabilities::strict();
                    $(caps = $capabilities;)?
                    caps
                },
                build: $build,
                decode: $decode,
            }
        }
    };
}

/// Builds the `family_NNN` implementation id from a family and version literal.
///
/// Versions are zero-padded to three digits, so ids sort the way a reader
/// expects and `bloom_010` does not sort before `bloom_002`. Versions past 999
/// simply widen; the padding is cosmetic, not a limit.
///
/// Used by [`register_filter!`](crate::register_filter). Exposed because a
/// filter crate naming its own id in a doc comment or an error message should
/// derive it the same way rather than writing the string twice.
///
/// # Examples
///
/// ```
/// assert_eq!(dmc_core::filter_id!("bloom", 1), "bloom_001");
/// assert_eq!(dmc_core::filter_id!("xor", 12), "xor_012");
/// assert_eq!(dmc_core::filter_id!("fuse", 123), "fuse_123");
/// ```
#[macro_export]
macro_rules! filter_id {
    ($family:literal, $version:literal) => {{
        // The padded bytes must outlive the expression, so bind them to a
        // `const` (promoted to static storage) before slicing. A `const fn`
        // cannot return a `&'static str` borrowed from its own locals.
        const PADDED: $crate::registry::PaddedId = $crate::registry::pad_version($family, $version);
        PADDED.as_str()
    }};
}

/// A `family_NNN` id built at compile time, stored inline.
///
/// Exists because a `const fn` cannot return a `&'static str` that borrows
/// from its own locals. [`filter_id!`](crate::filter_id) binds one of these to
/// a `const`, which lives in static storage, and then borrows from that.
///
/// Callers do not construct this directly; [`pad_version`] does.
#[derive(Debug, Clone, Copy)]
pub struct PaddedId {
    /// The id bytes, followed by unused zeroes.
    bytes: [u8; Self::CAP],

    /// How many of `bytes` are the id.
    len: usize,
}

impl PaddedId {
    /// Buffer size. A family name may use all but four of these bytes.
    const CAP: usize = 64;

    /// Borrows the id as a string slice.
    ///
    /// # Panics
    ///
    /// Cannot panic in practice: every byte [`pad_version`] writes is ASCII or
    /// came from a `&str`. The UTF-8 validation is kept because a `const fn`
    /// has no way to assert that, and it runs at compile time regardless.
    ///
    /// # Examples
    ///
    /// ```
    /// use dmc_core::registry::pad_version;
    ///
    /// const ID: dmc_core::registry::PaddedId = pad_version("bloom", 1);
    /// assert_eq!(ID.as_str(), "bloom_001");
    /// ```
    #[must_use]
    pub const fn as_str(&self) -> &str {
        let (head, _) = self.bytes.split_at(self.len);

        // Every byte written by `pad_version` is ASCII or came from a `&str`,
        // so this validation cannot fail. It runs at compile time regardless.
        match core::str::from_utf8(head) {
            Ok(s) => s,
            Err(_) => panic!("filter id was not valid UTF-8"),
        }
    }
}

/// Joins a family name and version into a `family_NNN` id at compile time.
///
/// Const because [`register_filter!`](crate::register_filter) needs the result
/// in a `const` context, where `format!` is unavailable. Callers reach this
/// through [`filter_id!`](crate::filter_id) rather than calling it directly.
///
/// Versions are zero-padded to three digits so that ids sort the way a reader
/// expects: `bloom_002` before `bloom_010`.
///
/// # Panics
///
/// Panics at compile time if the combined id would exceed the fixed 64-byte
/// buffer, which means a family name beyond 60 characters.
///
/// # Examples
///
/// ```
/// use dmc_core::registry::pad_version;
///
/// const A: dmc_core::registry::PaddedId = pad_version("bloom", 1);
/// const B: dmc_core::registry::PaddedId = pad_version("ribbon", 12);
///
/// assert_eq!(A.as_str(), "bloom_001");
/// assert_eq!(B.as_str(), "ribbon_012");
/// ```
#[must_use]
pub const fn pad_version(family: &str, version: u32) -> PaddedId {
    // A fixed buffer rather than a Vec: this runs in a const context, where
    // allocation is unavailable.
    let mut bytes = [0u8; PaddedId::CAP];

    let fam = family.as_bytes();
    assert!(
        fam.len() + 4 <= PaddedId::CAP,
        "filter family name is too long for an id"
    );

    let mut i = 0;
    while i < fam.len() {
        bytes[i] = fam[i];
        i += 1;
    }
    bytes[i] = b'_';
    i += 1;

    // Count decimal digits, with a floor of three so single- and double-digit
    // versions are zero-padded.
    let mut digits = 0;
    let mut probe = version;
    while probe > 0 {
        digits += 1;
        probe /= 10;
    }
    if digits < 3 {
        digits = 3;
    }

    // Emit most significant digit first. Dividing down to each position avoids
    // building the number in reverse, which would need a second buffer.
    let mut place = digits;
    while place > 0 {
        place -= 1;

        let mut scaled = version;
        let mut skip = place;
        while skip > 0 {
            scaled /= 10;
            skip -= 1;
        }

        // `scaled % 10` is 0..=9, so the cast is exact.
        #[allow(clippy::cast_possible_truncation)]
        let digit = (scaled % 10) as u8;

        bytes[i] = b'0' + digit;
        i += 1;
    }

    PaddedId { bytes, len: i }
}
