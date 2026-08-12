# frozen_string_literal: true

module DmcCheck
  # CRC-32C, written independently of the Rust implementation it checks.
  #
  # The suite needs this to build valid encodings by hand and to re-checksum a
  # field it has deliberately edited. It could have asked `dmc-cli` to compute
  # the value instead — and that would be the one place where a bug in the code
  # under test could hide itself, since a wrong CRC on both sides agrees with
  # itself perfectly.
  #
  # So this is a second implementation, from the specification rather than from
  # the Rust source. `harness_test.rb` pins both against the RFC 3720 check
  # values, which is what makes the independence meaningful: two implementations
  # that agree with each other *and* with a published vector are far more likely
  # right than two that only agree with each other.
  #
  # This is a bitwise implementation. It is slower than the table-driven form in
  # `lib/dmc-core/src/crc32c.rs`, which is fine — the harness checksums headers
  # and small bodies, not gigabyte bit arrays — and the difference in approach
  # is itself useful: a shared transcription error is less likely between two
  # implementations that are not structured the same way.
  module Crc32c
    # Castagnoli's polynomial, reversed for a right-shifting loop.
    #
    # Normal form is 0x1EDC6F41. Chosen over the classic Ethernet polynomial for
    # its better Hamming distance at the message lengths a filter encoding hits:
    # HD=6 out to about 5.2 KB, so every 1-, 2-, and 3-bit error in a small
    # filter is caught with certainty rather than probability.
    POLYNOMIAL = 0x82F6_3B78

    # Mask for 32-bit wraparound. Ruby integers are arbitrary precision, so
    # every shift has to be masked back down by hand.
    MASK32 = 0xFFFF_FFFF

    module_function

    # Returns the CRC-32C of a byte string.
    #
    # @param bytes [String]
    # @return [Integer] a 32-bit value
    def checksum(bytes)
      update(0, bytes)
    end

    # Continues a running CRC-32C over another slice.
    #
    # Pass 0 as the initial value. The pre- and post-inversion the standard
    # requires happen inside, so chaining gives the same result as one pass over
    # the concatenation.
    #
    # @param crc [Integer]
    # @param bytes [String]
    # @return [Integer]
    def update(crc, bytes)
      register = (~crc) & MASK32

      bytes.each_byte do |byte|
        register ^= byte

        # Eight bits of polynomial division, one at a time. The table-driven
        # form does this per byte; doing it per bit here keeps the two
        # implementations structurally different.
        8.times do
          register = if register.anybits?(1)
                       (register >> 1) ^ POLYNOMIAL
                     else
                       register >> 1
                     end
        end
      end

      (~register) & MASK32
    end
  end
end
