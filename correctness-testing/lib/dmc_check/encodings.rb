# frozen_string_literal: true

module DmcCheck
  # Hand-built encodings, for the tests that feed the decoder hostile input.
  #
  # Every encoded filter opens with the same fixed-width header, so a test that
  # wants "a structurally valid header naming an implementation nobody linked"
  # can say that rather than spelling out seventy-three bytes of offsets.
  #
  # Mirrors `lib/dmc-core/src/header.rs`. When that layout changes, this changes
  # with it, and the tests built on it keep saying what they mean — which is the
  # point of having it in one place.
  module Encodings
    # Field offsets and widths, from the table in `header.rs`.
    FAMILY_CODE = 0
    VERSION = 4
    PAYLOAD_VERSION = 8
    SEED = 9
    LEN = 17
    CAPACITY = 25
    CUSTOM = 33

    # Five `u64` slots an implementation may use for whatever it needs.
    CUSTOM_SLOTS = 5

    # Byte offset of the CRC-32C over the encoding.
    CHECKSUM = 73

    # Total header width. The implementation body begins here.
    HEADER_BYTES = 77

    # A family code above the assigned range, so no in-tree filter claims it.
    #
    # `family::PRIVATE_USE_START` is 1000; codes at or above it are for families
    # living outside this project. Nothing links one, which is exactly what
    # makes it useful for testing the unknown-implementation path.
    UNLINKED_FAMILY_CODE = 60_001

    module_function

    # Builds a header with every field defaulted to something valid.
    #
    # Defaults are chosen so the result passes structural validation: a nonzero
    # family code, a nonzero payload version, a nonzero capacity, and a `len`
    # within it. Override exactly the field a test means to attack, and every
    # other check still passes — so a rejection is attributable to that field
    # rather than to an accident elsewhere in the bytes.
    #
    # @param family_code [Integer]
    # @param version [Integer]
    # @param payload_version [Integer]
    # @param seed [Integer]
    # @param len [Integer]
    # @param capacity [Integer]
    # @param custom [Array<Integer>] up to five u64 slots, zero-filled
    # @param body [String] the implementation's own bytes
    # @return [String] a byte string
    def header(family_code: 1, version: 1, payload_version: 1, seed: 0,
               len: 0, capacity: 64, custom: [], body: "")
      raise ArgumentError, "at most #{CUSTOM_SLOTS} custom slots" if custom.length > CUSTOM_SLOTS

      slots = custom + ([0] * (CUSTOM_SLOTS - custom.length))

      bytes = +"".b
      bytes << [family_code].pack("V")
      bytes << [version].pack("V")
      bytes << [payload_version].pack("C")
      bytes << [seed].pack("Q<")
      bytes << [len].pack("Q<")
      bytes << [capacity].pack("Q<")
      slots.each { |slot| bytes << [slot].pack("Q<") }
      # Placeholder, overwritten by `finalize` once the body is appended.
      bytes << [0].pack("V")

      raise "header came out #{bytes.bytesize} bytes, expected #{HEADER_BYTES}" \
        unless bytes.bytesize == HEADER_BYTES

      finalize(bytes + body.b)
    end

    # Fills in the CRC-32C over a complete encoding.
    #
    # Mirrors `Header::finalize`. Every hand-built encoding goes through this,
    # and every test that edits a field afterwards calls it again — otherwise
    # the decoder answers on the checksum rather than on the field the test
    # names, and the test silently stops checking anything.
    #
    # The exception is a test deliberately asserting that corruption is caught,
    # which edits a byte and does *not* re-finalize.
    #
    # @param bytes [String]
    # @return [String] a new byte string with the checksum filled in
    def finalize(bytes)
      copy = bytes.dup.b
      covered = copy.byteslice(0, CHECKSUM) +
                copy.byteslice(CHECKSUM + 4, copy.bytesize - CHECKSUM - 4)

      copy[CHECKSUM, 4] = [Crc32c.checksum(covered)].pack("V")
      copy
    end

    # A structurally valid encoding naming an implementation nobody linked.
    #
    # Every field validates; only the family code is unresolvable. That
    # separates "these bytes are malformed" from "these bytes are fine but name
    # a filter this binary does not have", which are different problems with
    # different fixes — and an operator reading the error needs to know which.
    #
    # @return [String]
    def unlinked_family
      header(family_code: UNLINKED_FAMILY_CODE, body: "\x00".b * 8)
    end

    # Reads one field out of an encoding, for tests that assert on the header.
    #
    # @param bytes [String]
    # @param offset [Integer] one of the field constants
    # @param width [Integer] 1, 4, or 8
    # @return [Integer]
    def read_field(bytes, offset, width)
      slice = bytes.byteslice(offset, width)
      case width
      when 1 then slice.unpack1("C")
      when 4 then slice.unpack1("V")
      when 8 then slice.unpack1("Q<")
      else raise ArgumentError, "unsupported field width #{width}"
      end
    end

    # Returns a copy of `bytes` with one header field replaced.
    #
    # For the corruption tests, which change one field and assert the decoder
    # notices.
    #
    # @param bytes [String]
    # @param offset [Integer]
    # @param width [Integer]
    # @param value [Integer]
    # @return [String]
    def with_field(bytes, offset, width, value)
      packed = case width
               when 1 then [value].pack("C")
               when 4 then [value].pack("V")
               when 8 then [value].pack("Q<")
               else raise ArgumentError, "unsupported field width #{width}"
               end

      copy = bytes.dup.b
      copy[offset, width] = packed

      # Re-checksummed so the edit reads as a filter legitimately written that
      # way. A test that wants the corruption *detected* edits bytes directly
      # rather than through here.
      finalize(copy)
    end
  end
end
