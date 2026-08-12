//! The fixed-width header that opens every encoded filter.
//!
//! Every implementation's encoding begins with the same 77 bytes. The header
//! names the implementation that wrote it, carries the fields that live on the
//! [`Filter`](crate::Filter) trait itself, reserves five slots for whatever an
//! implementation needs beyond that, and closes with a checksum over the whole
//! encoding.
//!
//! # Layout
//!
//! All multi-byte fields are little-endian, on every target. A big-endian host
//! converts on read and write rather than storing native order, so an encoding
//! moves between machines unchanged.
//!
//! | Offset | Width | Field |
//! |---|---|---|
//! | 0 | 4 | [`family_code`](Header::family_code) |
//! | 4 | 4 | [`version`](Header::version) |
//! | 8 | 1 | [`payload_version`](Header::payload_version) |
//! | 9 | 8 | [`seed`](Header::seed) |
//! | 17 | 8 | [`len`](Header::len) |
//! | 25 | 8 | [`capacity`](Header::capacity) |
//! | 33 | 40 | [`custom`](Header::custom), five `u64` slots |
//! | 73 | 4 | CRC-32C over the encoding, this field excluded |
//! | 77 | — | implementation body |
//!
//! # Writing an encoding
//!
//! Two steps, and the second is easy to forget: call [`Header::encode`], append
//! the body, then call [`Header::finalize`]. The checksum cannot be computed
//! until the body exists, so `encode` writes a zeroed placeholder that
//! `finalize` overwrites. An encoding that skips `finalize` fails to decode,
//! which is the intended way to notice.
//!
//! # What is validated here and what is not
//!
//! [`Header::decode`] verifies the checksum first, then rejects a truncated
//! header, a zero `family_code`, a zero `payload_version`, a zero `capacity`,
//! and a `len` above `capacity`. Those hold for every filter, so checking them
//! once means no implementation can forget to.
//!
//! The checksum runs first on purpose. A corrupted encoding should report
//! itself as corrupt rather than as whichever field the damage happened to land
//! in: "checksum mismatch" tells an operator their storage is bad, while
//! "non-zero capacity expected" sends them hunting a bug that is not there.
//!
//! It is also the only check that catches a flipped bit in [`seed`](Header::seed).
//! That field is structurally invisible — every other check passes, and the
//! filter decodes into one that answers differently from the original,
//! including `false` for keys that were inserted. Before the checksum existed,
//! all eight seed bytes were corruptible without detection.
//!
//! The checksum does not touch [`custom`](Header::custom) in the sense of
//! validating it. Only the implementation knows what those slots mean, so
//! bounding them stays in the implementation's `decode`, after this one returns.
//!
//! # What the checksum cannot do
//!
//! It detects that the bytes changed. It cannot make a corrupted filter sound.
//!
//! Clearing a set bit in a Bloom filter's bit array yields a perfectly valid
//! encoding of a smaller key set — the bytes *are* the data. What this buys is
//! that the encoding refuses to load rather than silently answering `false` for
//! a key that was inserted. A filter that fails loudly is recoverable; one that
//! quietly lies is not.
//!
//! It is also not a security check. See [`crc32c`](crate::crc32c).

use crate::crc32c;
use crate::error::{Error, Result};
use crate::family;

/// A decoded filter header.
///
/// Implementations build one through [`Header::new`] and fill in the custom
/// slots with [`with_custom`](Header::with_custom), rather than constructing
/// the struct literally, so that a field added later does not break them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Numeric family, per the [`family`] module.
    ///
    /// Never zero in a valid header. Together with
    /// [`version`](Header::version) this is what
    /// [`decode`](crate::registry::decode) routes on.
    pub family_code: u32,

    /// Implementation version within the family.
    ///
    /// `bloom_001` encodes `1` here. Zero is legal, though no implementation
    /// currently registers version 0.
    pub version: u32,

    /// Version of the implementation's own payload layout.
    ///
    /// Distinct from [`version`](Header::version): an implementation may change
    /// how it serializes itself without changing which keys it matches. Never
    /// zero, so that a zeroed buffer cannot parse as version 0 of anything.
    pub payload_version: u8,

    /// The seed the filter was built with, from [`Params::seed`](crate::Params::seed).
    ///
    /// Semantic for most implementations: decoding with the wrong seed yields a
    /// filter that answers differently rather than one that fails to parse.
    pub seed: u64,

    /// How many keys the filter was built from, as [`Filter::len`](crate::Filter::len)
    /// reports.
    pub len: u64,

    /// Size of the backing store, in units the implementation defines.
    ///
    /// `bloom_001` counts bits; a fingerprint-table filter counts slots. The
    /// unit does not matter to this module, which uses it only to bound
    /// [`len`](Header::len): a filter claiming more keys than its store could
    /// index is corrupt whatever the unit.
    ///
    /// Never zero in a valid header.
    pub capacity: u64,

    /// Five slots for implementation-defined values.
    ///
    /// `bloom_001` uses slot 0 for its hash count and leaves the rest zero. A
    /// peeling filter would use them for segment count and length. Unused slots
    /// are written as zero, and nothing here validates any of them.
    pub custom: [u64; Self::CUSTOM_SLOTS],
}

impl Header {
    /// How many implementation-defined slots the header carries.
    pub const CUSTOM_SLOTS: usize = 5;

    /// Encoded size of the header, in bytes.
    ///
    /// `family_code(4) version(4) payload_version(1) seed(8) len(8)
    /// capacity(8) custom(8*5) checksum(4)`.
    pub const SIZE: usize = 4 + 4 + 1 + 8 + 8 + 8 + 8 * Self::CUSTOM_SLOTS + 4;

    /// Byte offset of the checksum field within the header.
    ///
    /// Public because it is part of the format: a tool that repairs or inspects
    /// an encoding needs to know which four bytes to skip when recomputing.
    pub const CHECKSUM_OFFSET: usize = Self::SIZE - 4;

    /// Creates a header with every custom slot zeroed.
    ///
    /// # Examples
    ///
    /// ```
    /// use dmc_core::header::Header;
    ///
    /// let header = Header::new(1, 1, 1, 42, 1_000, 9_600);
    /// assert_eq!(header.seed, 42);
    /// assert_eq!(header.custom, [0; Header::CUSTOM_SLOTS]);
    /// ```
    #[must_use]
    pub const fn new(
        family_code: u32,
        version: u32,
        payload_version: u8,
        seed: u64,
        len: u64,
        capacity: u64,
    ) -> Self {
        Self {
            family_code,
            version,
            payload_version,
            seed,
            len,
            capacity,
            custom: [0; Self::CUSTOM_SLOTS],
        }
    }

    /// Returns this header with custom slot `index` set to `value`.
    ///
    /// # Panics
    ///
    /// Panics if `index` is at or beyond [`CUSTOM_SLOTS`](Header::CUSTOM_SLOTS).
    /// The index is always a literal at the call site, so this is a programmer
    /// error rather than something a caller can trigger with data.
    ///
    /// # Examples
    ///
    /// ```
    /// use dmc_core::header::Header;
    ///
    /// let header = Header::new(1, 1, 1, 0, 3, 640).with_custom(0, 7);
    /// assert_eq!(header.custom[0], 7);
    /// ```
    #[must_use]
    pub const fn with_custom(mut self, index: usize, value: u64) -> Self {
        assert!(
            index < Self::CUSTOM_SLOTS,
            "custom slot index is out of range"
        );
        self.custom[index] = value;
        self
    }

    /// Returns the family name for this header's code, if it is a known one.
    ///
    /// `None` for a private-use code, which no table here can name.
    #[must_use]
    pub const fn family(&self) -> Option<&'static str> {
        family::name_for(self.family_code)
    }

    /// Appends the header to `out`.
    ///
    /// Implementations call this at the start of their
    /// [`encode`](crate::Filter::encode), then append their body.
    ///
    /// # Examples
    ///
    /// ```
    /// use dmc_core::header::Header;
    ///
    /// let mut out = Vec::new();
    /// Header::new(1, 1, 1, 0, 0, 64).encode(&mut out);
    /// assert_eq!(out.len(), Header::SIZE);
    /// ```
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.family_code.to_le_bytes());
        out.extend_from_slice(&self.version.to_le_bytes());
        out.push(self.payload_version);
        out.extend_from_slice(&self.seed.to_le_bytes());
        out.extend_from_slice(&self.len.to_le_bytes());
        out.extend_from_slice(&self.capacity.to_le_bytes());

        for slot in &self.custom {
            out.extend_from_slice(&slot.to_le_bytes());
        }

        // Placeholder. The real value cannot be computed until the body exists,
        // so `finalize` overwrites these four bytes afterwards. Written as
        // zeroes rather than left absent so the header is always `SIZE` bytes
        // and every offset past it is fixed.
        out.extend_from_slice(&0u32.to_le_bytes());
    }

    /// Fills in the checksum over a completed encoding.
    ///
    /// Implementations call this as the last statement of their
    /// [`encode`](crate::Filter::encode), after appending their body. Until
    /// then the checksum field holds zeroes and
    /// [`decode`](Header::decode) would reject the encoding.
    ///
    /// `start` is where this filter's encoding begins within `out`. It is not
    /// always zero: `Filter::encode` appends to a caller's buffer, which may
    /// already hold something else.
    ///
    /// The checksum covers every byte of the encoding except its own four, so a
    /// flipped bit anywhere — header field or body — is caught. Recomputing it
    /// is what a repair tool would do; see
    /// [`CHECKSUM_OFFSET`](Header::CHECKSUM_OFFSET).
    ///
    /// # Panics
    ///
    /// Panics if `out` holds fewer than [`SIZE`](Header::SIZE) bytes past
    /// `start`, which would mean the caller did not write a header first. That
    /// is a programmer error in an implementation, not something data can
    /// trigger.
    ///
    /// # Examples
    ///
    /// ```
    /// use dmc_core::header::Header;
    ///
    /// let mut out = Vec::new();
    /// Header::new(1, 1, 1, 0, 1, 64).encode(&mut out);
    /// out.extend_from_slice(b"body");
    /// Header::finalize(&mut out, 0);
    ///
    /// // Now it round-trips; without the finalize it would not.
    /// let (header, body) = Header::decode(&out)?;
    /// assert_eq!(body, b"body");
    /// assert_eq!(header.seed, 0);
    /// # Ok::<(), dmc_core::Error>(())
    /// ```
    ///
    /// Appending to a non-empty buffer works the same way:
    ///
    /// ```
    /// use dmc_core::header::Header;
    ///
    /// let mut out = b"unrelated prefix".to_vec();
    /// let start = out.len();
    ///
    /// Header::new(1, 1, 1, 0, 1, 64).encode(&mut out);
    /// out.extend_from_slice(b"body");
    /// Header::finalize(&mut out, start);
    ///
    /// assert!(Header::decode(&out[start..]).is_ok());
    /// ```
    pub fn finalize(out: &mut [u8], start: usize) {
        assert!(
            out.len() >= start + Self::SIZE,
            "finalize called before a header was written"
        );

        let checksum_at = start + Self::CHECKSUM_OFFSET;

        // Everything before the checksum field, then everything after it. The
        // field cannot cover itself, and skipping it is what lets a verifier
        // recompute the same value from bytes that already carry one.
        let crc = crc32c::update(
            crc32c::update(0, &out[start..checksum_at]),
            &out[checksum_at + 4..],
        );

        out[checksum_at..checksum_at + 4].copy_from_slice(&crc.to_le_bytes());
    }

    /// Splits a header off the front of `bytes`, returning it and the body.
    ///
    /// The universal checks run here; see the module docs for which. An
    /// implementation's `decode` calls this first and then validates its own
    /// custom slots against the body it gets back.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Corrupt`] if `bytes` is shorter than
    /// [`SIZE`](Header::SIZE), if its checksum does not match the bytes it
    /// carries, or if the header declares a zero family code, a zero payload
    /// version, a zero capacity, or a key count above the declared capacity.
    ///
    /// The checksum is verified first, so a corrupted encoding reports itself
    /// as such rather than as whichever field the damage landed in.
    ///
    /// # Examples
    ///
    /// ```
    /// use dmc_core::header::Header;
    ///
    /// let mut bytes = Vec::new();
    /// Header::new(1, 1, 1, 7, 3, 640).encode(&mut bytes);
    /// bytes.extend_from_slice(b"body");
    /// Header::finalize(&mut bytes, 0);
    ///
    /// let (header, body) = Header::decode(&bytes)?;
    /// assert_eq!(header.seed, 7);
    /// assert_eq!(body, b"body");
    /// # Ok::<(), dmc_core::Error>(())
    /// ```
    pub fn decode(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.len() < Self::SIZE {
            return Err(Error::Corrupt {
                expected: "a 73-byte filter header",
            });
        }

        // Integrity first, before anything is derived from these bytes. A
        // corrupted encoding should report itself as corrupt rather than as
        // whichever field its damage happened to land in — "checksum mismatch"
        // tells an operator their storage is bad; "non-zero capacity expected"
        // sends them looking for a bug that is not there.
        //
        // This is also the only check that catches a flipped bit in `seed`,
        // which is structurally invisible: every other field validates, and the
        // filter decodes into one that answers differently from the original,
        // including `false` for keys that were inserted.
        let declared = u32::from_le_bytes([
            bytes[Self::CHECKSUM_OFFSET],
            bytes[Self::CHECKSUM_OFFSET + 1],
            bytes[Self::CHECKSUM_OFFSET + 2],
            bytes[Self::CHECKSUM_OFFSET + 3],
        ]);

        let computed = crc32c::update(
            crc32c::update(0, &bytes[..Self::CHECKSUM_OFFSET]),
            &bytes[Self::CHECKSUM_OFFSET + 4..],
        );

        if declared != computed {
            return Err(Error::Corrupt {
                expected: "a checksum matching the encoded bytes",
            });
        }

        let (head, body) = bytes.split_at(Self::SIZE);

        let mut cursor = Cursor::new(head);
        let family_code = cursor.u32();
        let version = cursor.u32();
        let payload_version = cursor.u8();
        let seed = cursor.u64();
        let len = cursor.u64();
        let capacity = cursor.u64();

        let mut custom = [0u64; Self::CUSTOM_SLOTS];
        for slot in &mut custom {
            *slot = cursor.u64();
        }

        // Zero is reserved in both spaces so that a zeroed buffer, which is a
        // common shape for corruption, cannot parse as a valid header.
        if family_code == 0 {
            return Err(Error::Corrupt {
                expected: "a non-zero family code",
            });
        }

        if payload_version == 0 {
            return Err(Error::Corrupt {
                expected: "a non-zero payload version",
            });
        }

        // A filter with no backing store cannot answer anything, and several
        // implementations use capacity as a modulus.
        if capacity == 0 {
            return Err(Error::Corrupt {
                expected: "a non-zero capacity",
            });
        }

        // One key per unit of capacity is already far past useful, so a count
        // beyond that is corruption rather than an unusual but honest filter.
        // This also bounds `len` for the `usize` conversion implementations do.
        if len > capacity {
            return Err(Error::Corrupt {
                expected: "a key count no larger than the capacity",
            });
        }

        Ok((
            Self {
                family_code,
                version,
                payload_version,
                seed,
                len,
                capacity,
                custom,
            },
            body,
        ))
    }
}

/// Sequential little-endian reader over a slice of known length.
///
/// Every read is infallible because [`Header::decode`] checks the length once
/// before constructing one. Keeping the offsets here rather than at each call
/// site means adding a field cannot silently shift the ones after it.
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    /// Wraps `bytes`, which must be at least [`Header::SIZE`] long.
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    /// Reads the next `N` bytes.
    fn take<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        out.copy_from_slice(&self.bytes[self.at..self.at + N]);
        self.at += N;
        out
    }

    fn u8(&mut self) -> u8 {
        self.take::<1>()[0]
    }

    fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.take::<4>())
    }

    fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.take::<8>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A header with every field set to something distinguishable, so a test
    /// that swaps two offsets fails rather than comparing equal.
    fn sample() -> Header {
        Header::new(1, 2, 3, 0x1122_3344_5566_7788, 100, 1_000)
            .with_custom(0, 11)
            .with_custom(1, 22)
            .with_custom(2, 33)
            .with_custom(3, 44)
            .with_custom(4, 55)
    }

    /// A complete, checksummed encoding of `header` with no body.
    ///
    /// Goes through `finalize`, since an encoding that skips it is not one any
    /// implementation would produce and would fail the integrity check before
    /// reaching whatever a test is actually asserting.
    fn encoded(header: &Header) -> Vec<u8> {
        encoded_with_body(header, b"")
    }

    /// A complete, checksummed encoding of `header` followed by `body`.
    fn encoded_with_body(header: &Header, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        header.encode(&mut out);
        out.extend_from_slice(body);
        Header::finalize(&mut out, 0);
        out
    }

    #[test]
    fn size_matches_the_documented_layout() {
        // 4 + 4 + 1 + 8 + 8 + 8 + 40 fields, plus a 4-byte checksum.
        assert_eq!(Header::SIZE, 77);
        assert_eq!(Header::CHECKSUM_OFFSET, 73);
    }

    #[test]
    fn round_trips_every_field() {
        let header = sample();
        let bytes = encoded(&header);
        let (decoded, body) = Header::decode(&bytes).unwrap();

        assert_eq!(decoded, header);
        assert_eq!(body, b"");
    }

    #[test]
    fn decode_returns_the_body_untouched() {
        let bytes = encoded_with_body(&sample(), &[0xde, 0xad, 0xbe, 0xef]);

        let (_, body) = Header::decode(&bytes).unwrap();
        assert_eq!(body, &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn encode_appends_rather_than_overwrites() {
        // A filter's `encode` appends to a caller's buffer; a header that
        // cleared it would corrupt whatever came before.
        let mut out = vec![0xaa, 0xbb];
        sample().encode(&mut out);

        assert_eq!(&out[..2], &[0xaa, 0xbb]);
        assert_eq!(out.len(), 2 + Header::SIZE);
    }

    #[test]
    fn fields_land_at_the_documented_offsets() {
        // Pins the wire format. A field reordered without updating the module
        // table would otherwise round-trip fine and break every stored filter.
        let bytes = encoded(&sample());

        assert_eq!(u32::from_le_bytes(bytes[0..4].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 2);
        assert_eq!(bytes[8], 3);
        assert_eq!(
            u64::from_le_bytes(bytes[9..17].try_into().unwrap()),
            0x1122_3344_5566_7788
        );
        assert_eq!(u64::from_le_bytes(bytes[17..25].try_into().unwrap()), 100);
        assert_eq!(u64::from_le_bytes(bytes[25..33].try_into().unwrap()), 1_000);
        assert_eq!(u64::from_le_bytes(bytes[33..41].try_into().unwrap()), 11);
        assert_eq!(u64::from_le_bytes(bytes[65..73].try_into().unwrap()), 55);
    }

    #[test]
    fn encoding_is_little_endian_on_every_host() {
        // Decoding a hand-written byte string is the only way to assert the
        // endianness contract without a big-endian target in CI.
        let mut bytes = vec![
            0x01, 0x00, 0x00, 0x00, // family_code = 1
            0x02, 0x00, 0x00, 0x00, // version = 2
            0x03, // payload_version = 3
        ];
        bytes.extend_from_slice(&[0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]); // seed
        bytes.extend_from_slice(&[0x64, 0, 0, 0, 0, 0, 0, 0]); // len = 100
        bytes.extend_from_slice(&[0xe8, 0x03, 0, 0, 0, 0, 0, 0]); // capacity = 1000
        for value in [11u64, 22, 33, 44, 55] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        // The checksum is computed rather than hand-written: its value depends
        // on every byte above, so writing it out by hand would make this test
        // about transcription rather than about endianness.
        bytes.extend_from_slice(&0u32.to_le_bytes());
        Header::finalize(&mut bytes, 0);

        let (decoded, _) = Header::decode(&bytes).unwrap();
        assert_eq!(decoded, sample());
    }

    #[test]
    fn rejects_every_truncation() {
        let bytes = encoded(&sample());
        for cut in 0..Header::SIZE {
            assert!(
                Header::decode(&bytes[..cut]).is_err(),
                "accepted a header truncated to {cut} bytes"
            );
        }
    }

    #[test]
    fn rejects_a_zeroed_buffer() {
        // The shape corruption most often takes. Zero is reserved in the family
        // code and payload version precisely so this cannot parse.
        assert!(Header::decode(&[0u8; Header::SIZE]).is_err());
    }

    #[test]
    fn rejects_zero_family_code() {
        let mut bytes = encoded(&sample());
        bytes[0..4].copy_from_slice(&0u32.to_le_bytes());

        assert!(Header::decode(&bytes).is_err());
    }

    #[test]
    fn rejects_zero_payload_version() {
        let mut bytes = encoded(&sample());
        bytes[8] = 0;

        assert!(Header::decode(&bytes).is_err());
    }

    #[test]
    fn rejects_zero_capacity() {
        let mut bytes = encoded(&sample());
        bytes[25..33].copy_from_slice(&0u64.to_le_bytes());

        assert!(Header::decode(&bytes).is_err());
    }

    #[test]
    fn rejects_a_key_count_above_capacity() {
        let mut bytes = encoded(&sample());
        bytes[17..25].copy_from_slice(&u64::MAX.to_le_bytes());

        assert!(Header::decode(&bytes).is_err());
    }

    #[test]
    fn accepts_a_key_count_equal_to_capacity() {
        // The bound is inclusive: one key per unit is useless but honest, and
        // rejecting it would reject filters that were legitimately built.
        let mut bytes = encoded(&sample());
        bytes[17..25].copy_from_slice(&1_000u64.to_le_bytes());
        // Re-checksummed, so this exercises the `len <= capacity` bound rather
        // than being answered by the integrity check.
        Header::finalize(&mut bytes, 0);

        let (decoded, _) = Header::decode(&bytes).unwrap();
        assert_eq!(decoded.len, 1_000);
    }

    #[test]
    fn custom_slots_are_not_validated() {
        // Only the implementation knows what these mean, so the shared decoder
        // passes even absurd values through for it to reject.
        let header = sample().with_custom(0, u64::MAX);
        let bytes = encoded(&header);
        let (decoded, _) = Header::decode(&bytes).unwrap();

        assert_eq!(decoded.custom[0], u64::MAX);
    }

    #[test]
    fn a_known_code_resolves_to_its_family() {
        assert_eq!(sample().family(), Some("bloom"));
    }

    #[test]
    fn a_private_use_code_resolves_to_nothing() {
        let header = Header::new(family::PRIVATE_USE_START, 1, 1, 0, 0, 64);
        assert_eq!(header.family(), None);
    }
}
