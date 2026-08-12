# frozen_string_literal: true

module DmcCheck
  # Deterministic key generators.
  #
  # Every generator is a pure function of its arguments. No system clock, no
  # `SecureRandom`, no `Random.new` without a seed: a statistical failure that
  # cannot be replayed from the test output is a failure nobody can fix.
  #
  # This is the one place the reference suites are weakest. `external/vqf`
  # seeds from `RAND_bytes` and `external/binfuse` seeds `mt19937_64` from
  # `random_device`, so neither can reproduce its own false-positive-rate
  # failures.
  #
  # Keys come back as ASCII-8BIT strings. Most are little-endian `u64`
  # encodings, matching `dmc-core`'s own tests.
  module Generators
    # Mask for 64-bit wraparound. Ruby integers are arbitrary precision, so
    # every shift and multiply has to be masked back down by hand.
    MASK64 = 0xFFFF_FFFF_FFFF_FFFF

    module_function

    # Encodes an integer as a little-endian u64 byte string.
    #
    # @param value [Integer]
    # @return [String]
    def u64_le(value)
      [value & MASK64].pack("Q<").b
    end

    # The testkit's own mixer, deliberately not dmc-core's.
    #
    # `dmc_core::hash::mix` is the SplitMix64 finalizer with the constants
    # 0xbf58476d1ce4e5b9 and 0x94d049bb133111eb. Generating test keys with the
    # same function the filter hashes them with could hide a weak mixer: the
    # two would cancel, and keys that look uniform to the test would look
    # uniform to the filter for the wrong reason.
    #
    # These constants are from `splitmix64` variant "murmurhash3 finalizer",
    # different multipliers with the same avalanche quality. The bijection
    # property is what matters here — distinct counters give distinct outputs,
    # so a key set needs no deduplication pass.
    #
    # @param value [Integer]
    # @return [Integer] a 64-bit value
    def mix64(value)
      z = value & MASK64
      z = ((z ^ (z >> 33)) * 0xFF51_AFD7_ED55_8CCD) & MASK64
      z = ((z ^ (z >> 33)) * 0xC4CE_B9FE_1A85_EC53) & MASK64
      (z ^ (z >> 33)) & MASK64
    end

    # Rotates a 64-bit value left.
    #
    # @param value [Integer]
    # @param count [Integer] 0..63
    # @return [Integer]
    def rotl64(value, count)
      count &= 63
      return value & MASK64 if count.zero?

      ((value << count) | (value >> (64 - count))) & MASK64
    end

    # Reverses the bits of a 64-bit value.
    #
    # @param value [Integer]
    # @return [Integer]
    def reverse_bits64(value)
      # Ruby has no bit-reversal primitive. Formatting to a fixed-width binary
      # string and reversing is slow but obviously correct, and these key sets
      # are thousands of keys, not millions.
      format("%064b", value & MASK64).reverse.to_i(2)
    end

    # Distinct pseudorandom keys.
    #
    # Counter through {mix64}, which is a bijection on u64, so distinct
    # counters give distinct keys with no dedup pass. This is
    # `GenerateRandom64Fast` from
    # `external/fastfilter_cpp/benchmarks/random.h`, with the testkit's own
    # constants for the reason given on {mix64}.
    #
    # @param count [Integer]
    # @param seed [Integer]
    # @return [Array<String>]
    def random_keys(count, seed = 0)
      base = mix64(seed)
      Array.new(count) { |i| u64_le(mix64(base + i)) }
    end

    # Little-endian encodings of 0...count.
    #
    # The realistic worst case for a weak hash: consecutive keys differ in
    # their lowest bits only. Already partly covered by
    # `dmc-core`'s `sequential_integer_keys_do_not_collide`.
    #
    # @param count [Integer]
    # @return [Array<String>]
    def sequential_keys(count)
      Array.new(count) { |i| u64_le(i) }
    end

    # Sequential integers rotated left by a fixed amount.
    #
    # The special seeds 0–63 in
    # `external/fastfilter_cpp/benchmarks/bulk-insert-and-query.cc`. Moves a
    # counter's entropy into a chosen bit position, which finds filters that
    # only look at one end of the hash.
    #
    # @param count [Integer]
    # @param rotate [Integer] 0..63
    # @return [Array<String>]
    def rotated_keys(count, rotate)
      Array.new(count) { |i| u64_le(rotl64(i, rotate)) }
    end

    # Bit-reversed rotated sequential integers.
    #
    # The special seeds 64–127 in the same file, and the nastiest cheap
    # generator in the reference set: consecutive keys differ only in their
    # high bits, so a filter deriving its bucket from the low bits piles every
    # key into one bucket.
    #
    # @param count [Integer]
    # @param rotate [Integer] 0..63
    # @return [Array<String>]
    def reversed_keys(count, rotate = 0)
      Array.new(count) { |i| u64_le(reverse_bits64(rotl64(i, rotate))) }
    end

    # A fixed prefix followed by a counter.
    #
    # `StandardKeyGen` from `external/BuRR/test_helpers.hpp`. Models URLs, S3
    # keys, and namespaced identifiers — the realistic case where a hash that
    # processes bytes in order without a strong finalizer degrades.
    #
    # BuRR multiplies the counter by 0x1500000001 before encoding. That is
    # available through `multiply:`, but defaults off: the unmultiplied form is
    # the more hostile of the two.
    #
    # @param count [Integer]
    # @param prefix [String] a byte string
    # @param multiply [Boolean]
    # @return [Array<String>]
    def prefixed_keys(count, prefix: "https://example.com/resource/", multiply: false)
      prefix = prefix.b
      Array.new(count) do |i|
        value = multiply ? (i * 0x15_0000_0001) & MASK64 : i
        prefix + u64_le(value)
      end
    end

    # A hashed prefix offset plus a sequential counter.
    #
    # `SmallKeyGen` from `external/BuRR/test_helpers.hpp`, added upstream
    # specifically because sequential seeds misbehaved in xxHash (upstream
    # issue 469). Cheap insurance against the same class of bug.
    #
    # @param count [Integer]
    # @param seed [Integer]
    # @return [Array<String>]
    def small_keys(count, seed = 0)
      offset = mix64(seed) & 0xFFFF_FFFF
      Array.new(count) { |i| u64_le(offset + i) }
    end

    # Keys spanning every length that matters to the hash.
    #
    # `dmc_core::hash::hash64` consumes eight bytes at a time with a byte-wise
    # tail, so lengths 0, 1, 7, 8, 9, 63, 64, and 65 take materially different
    # paths. Every length in 0..64 appears at least once; beyond that the
    # lengths grow toward 4 KiB.
    #
    # @param count [Integer]
    # @param seed [Integer]
    # @return [Array<String>]
    def variable_length_keys(count, seed = 0)
      Array.new(count) do |i|
        # The first 65 keys cover 0..64 exactly; later ones spread out.
        length = i <= 64 ? i : 65 + (mix64(seed + i) % 4032)
        filler = mix64(seed ^ (i + 1))

        # Fill from a per-key value so two keys of the same length differ.
        bytes = +""
        while bytes.bytesize < length
          bytes << u64_le(filler + bytes.bytesize)
        end
        bytes.byteslice(0, length).b
      end
    end

    # Non-member keys guaranteed disjoint from a member set.
    #
    # Generated from a counter range that cannot overlap the members', then
    # verified against a Set. `external/fastfilter_cpp` flags this as wrong in
    # its own code — the comment at `bulk-insert-and-query.cc:255` admits the
    # FPR calculation "is obviously technically wrong" because it assumes no
    # overlap, then computes an intersection size to correct for it.
    # Guaranteeing disjointness up front removes the correction entirely.
    #
    # @param members [Array<String>]
    # @param count [Integer]
    # @param seed [Integer]
    # @return [Array<String>]
    def disjoint_probe_keys(members, count, seed = 0)
      member_set = members.to_set(&:b)
      probes = []
      i = 0

      # A different mixing domain from random_keys, so a shared seed does not
      # make the two generators produce the same values.
      base = mix64(seed ^ 0xD1B5_4A32_D192_ED03)

      while probes.length < count
        candidate = u64_le(mix64(base + i))
        probes << candidate unless member_set.include?(candidate)
        i += 1

        raise "could not find #{count} disjoint probes" if i > count * 100
      end

      probes
    end

    # Named pathological key sets, for table-driven tests.
    #
    # Each entry is `[name, keys]`. Every one of these is legal input; none may
    # panic, and all of them must satisfy the invariants in area 020.
    #
    # @return [Array<Array(String, Array<String>)>]
    def degenerate_key_sets
      [
        ["empty set", []],
        ["single empty key", [""]],
        ["single key", ["solitary"]],
        ["many empty keys", [""] * 1_000],
        ["all keys identical", ["same"] * 100],
        ["two keys differing in one bit", ["\x00".b, "\x01".b]],
        ["trailing zero bytes", ["key".b, "key\x00".b, "key\x00\x00".b, "key\x00\x00\x00".b]],
        ["1 KiB identical vs last byte changed", [("a" * 1024).b, ("a" * 1023 + "b").b]],
        ["all zeros at several lengths", [1, 8, 64, 256].map { |n| ("\x00" * n).b }],
        ["all ones at several lengths", [1, 8, 64, 256].map { |n| ("\xFF" * n).b }],
        ["embedded NULs", ["a\x00b".b, "a\x00\x00b".b, "\x00".b, "\x00\x00".b]],
        ["invalid UTF-8", ["\xC3\x28".b, "\xA0\xA1".b, "\xE2\x28\xA1".b, "\xF0\x28\x8C\x28".b]]
      ]
    end

    # Nanosecond-resolution timestamps over a realistic range.
    #
    # High bits constant, low bits varying, and the very lowest bits often zero
    # from clock granularity. A distinct failure mode from plain sequential
    # integers, and one that shows up in production key sets constantly.
    #
    # @param count [Integer]
    # @param start_nanos [Integer]
    # @param granularity [Integer] nanoseconds between ticks
    # @return [Array<String>]
    def timestamp_keys(count, start_nanos: 1_700_000_000_000_000_000, granularity: 1_000)
      Array.new(count) { |i| u64_le(start_nanos + (i * granularity)) }
    end

    # A varying prefix followed by a fixed long suffix.
    #
    # The mirror of {prefixed_keys}. FNV-1a is order-dependent so this should
    # be fine, but the chunked loop means the varying part may fall entirely
    # within the first chunk, leaving the rest of the input to dilute it.
    #
    # @param count [Integer]
    # @param suffix_length [Integer]
    # @return [Array<String>]
    def suffixed_keys(count, suffix_length: 1024)
      suffix = ("s" * suffix_length).b
      Array.new(count) { |i| u64_le(i) + suffix }
    end

    # Keys differing only in how many trailing zero bytes they carry.
    #
    # `hash64` folds `key.len()` in specifically to separate these. The
    # two-key case is covered in `dmc-core`; this scales it to 64.
    #
    # @param count [Integer]
    # @param stem [String]
    # @return [Array<String>]
    def trailing_zero_keys(count, stem: "key")
      Array.new(count) { |i| (stem.b + ("\x00".b * i)) }
    end

    # Every generator that produces a plain distinct key set, by name.
    #
    # Used by the table-driven invariant tests, which run each generator at
    # each size tier. Keyed by name so a failure message says which generator
    # produced the offending keys.
    #
    # @param count [Integer]
    # @param seed [Integer]
    # @return [Hash{String => Array<String>}]
    def standard_suite(count, seed: 0)
      {
        "random" => random_keys(count, seed),
        "sequential" => sequential_keys(count),
        "rotated_21" => rotated_keys(count, 21),
        "rotated_58" => rotated_keys(count, 58),
        "reversed" => reversed_keys(count),
        "reversed_32" => reversed_keys(count, 32),
        "prefixed" => prefixed_keys(count),
        "prefixed_multiplied" => prefixed_keys(count, multiply: true),
        "small" => small_keys(count, seed),
        "variable_length" => variable_length_keys(count, seed),
        "timestamps" => timestamp_keys(count),
        "suffixed" => suffixed_keys(count)
      }
    end
  end
end
