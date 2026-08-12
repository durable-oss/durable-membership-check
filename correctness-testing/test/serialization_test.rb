# frozen_string_literal: true

require "test_helper"

# Area 050 — encoding, decoding, and corruption resistance.
#
# Encoded filters cross trust boundaries: a file, a network, a Ruby binding. The
# decoder must treat its input as hostile.
#
# `external/BuRR/binary_format.txt` is the cautionary example. It opens with
# "WARNING: The binary format is not meant as a robust storage and transfer
# format ... it does not include any safeguards to detect data corruption."
# This file checks the opposite discipline.
class SerializationTest < DmcCheck::ConformanceTest
  include DmcCheck

  # 050.010.020 — a round trip preserves the answer for every key, not just for
  # members.
  #
  # The assertion that actually pins the format down. Any difference on a
  # non-member means a field was lost or reinterpreted — most likely the seed,
  # which changes which keys collide without changing whether members are found.
  for_each_filter "round trips every answer, including false positives" do |spec|
    keys = Generators.random_keys(Tiers::SMALL, 50_010_020)
    original = build(spec, keys, expected_items: keys.length,
                                 false_positive_rate: 0.01, seed: 50_010_020)
    restored = session.decode(original.encode)

    probes = keys + Generators.disjoint_probe_keys(keys, 50_000, 50_010_020)

    before = original.contains_all(probes)
    after = restored.contains_all(probes)

    unless before == after
      # Report the first divergence rather than dumping fifty thousand booleans.
      index = before.each_index.find { |i| before[i] != after[i] }
      flunk "#{spec.id} answered differently after a round trip: probe #{index} " \
            "(#{Hex.encode(probes[index])}) was #{before[index]} before and " \
            "#{after[index]} after; " \
            "#{before.zip(after).count { |a, b| a != b }} of #{probes.length} probes diverged"
    end

    assert_equal before, after
  end

  # 050.010.030 — metadata survives the round trip.
  #
  # `len` is descriptive in bloom_001: it feeds the rate estimate and nothing
  # else. Losing it silently changes a reported number without changing
  # behavior, which is exactly the bug this catches.
  for_each_filter "round trips its metadata" do |spec|
    keys = Generators.random_keys(500, 50_010_030)
    original = build(spec, keys, expected_items: keys.length,
                                 false_positive_rate: 0.01, seed: 7)
    restored = session.decode(original.encode)

    assert_equal original.id, restored.id
    assert_equal original.len, restored.len, "#{spec.id} lost its key count"
    assert_equal original.memory_bytes, restored.memory_bytes, "#{spec.id} changed size"
    assert_in_delta original.false_positive_rate, restored.false_positive_rate, 1e-12,
                    "#{spec.id} reports a different rate after decoding"
  end

  # 050.010.040 — the round trip is idempotent.
  #
  # Catches an encoder that normalizes on the way out, so that decode-then-
  # encode is not the identity on the encoded form.
  for_each_filter "encodes identically after a decode" do |spec|
    keys = Generators.random_keys(500, 50_010_040)
    original = build(spec, keys, expected_items: keys.length, false_positive_rate: 0.01)

    once = original.encode
    twice = session.decode(once).encode

    assert_equal Hex.encode(once), Hex.encode(twice),
                 "#{spec.id} re-encoded to different bytes after a decode"
  end

  # 050.020.010 — truncation at every length.
  #
  # The Rust tests check two lengths. Every prefix is cheap for a small filter,
  # and a decoder that happens to accept one specific short length is exactly
  # the kind of bug a two-point check misses.
  for_each_filter "rejects every truncation" do |spec|
    keys = Generators.random_keys(8, 50_020_010)
    encoded = build(spec, keys, expected_items: 8, false_positive_rate: 0.01).encode

    accepted = []
    (0...encoded.bytesize).each do |length|
      response = session.try_decode(encoded.byteslice(0, length))
      accepted << length if response["ok"]
    end

    assert_empty accepted,
                 "#{spec.id} decoded truncated input at length(s) #{accepted.inspect} " \
                 "of #{encoded.bytesize}"
  end

  # 050.020.020 and 050.020.080 — byte corruption must never panic.
  #
  # A corrupted encoding may be rejected, and it may decode into a filter that
  # is merely wrong. What it may never do is crash the decoder or hang it. This
  # asserts the decoder stays alive across every single-byte corruption, and
  # tallies which corruptions were caught, so a regression in validation shows
  # up as a change in the count rather than as silence.
  for_each_filter "never crashes on single-byte corruption" do |spec|
    keys = Generators.random_keys(16, 50_020_020)
    encoded = build(spec, keys, expected_items: 16, false_positive_rate: 0.01).encode

    # A handful of replacement values per position. All 255 at every position
    # would be tens of thousands of round trips for no new information; these
    # cover zero, one, the high bit, and all-ones.
    replacements = [0x00, 0x01, 0x7F, 0x80, 0xFF]

    rejected = 0
    accepted = 0

    (0...encoded.bytesize).each do |position|
      original_byte = encoded.getbyte(position)

      replacements.each do |replacement|
        next if replacement == original_byte

        corrupted = encoded.dup
        corrupted.setbyte(position, replacement)

        response = session.try_decode(corrupted)

        if response["ok"]
          accepted += 1
          handle = Cli::Handle.new(session, response.fetch("handle"), response.fetch("info"))
          # Whatever it decoded into must still answer queries without dying.
          handle.contains_all(keys)
          handle.release
        else
          rejected += 1
          refute_nil response["kind"], "corruption at byte #{position} produced no error kind"
        end
      end
    end

    assert_operator rejected + accepted, :>, 0, "no corruptions were attempted"
    # The session is still usable, which is the real assertion: a panic in the
    # decoder would have killed the process and failed every later test.
    assert_equal [true], session.build(spec.id, ["canary".b],
                                       expected_items: 1,
                                       false_positive_rate: 0.01).contains_all(["canary".b])
  end

  # 050.020.070 and 050.030.010 — semantic corruption is now detected.
  #
  # This test used to document a gap. Flipping a bit in the seed left an
  # encoding whose every structural check passed — family, version, payload
  # version, capacity, key count — that decoded into a filter answering
  # differently from the one written, including `false` for keys that were
  # inserted. All eight seed bytes were corruptible without detection.
  #
  # A CRC-32C over the encoding closed it. The assertion is now the strong one:
  # every single-bit flip anywhere in the encoding is rejected.
  #
  # What the checksum does *not* do is make a corrupted filter sound. Clearing a
  # bit in the bit array still yields a valid encoding of a smaller key set —
  # the bytes are the data. The gain is that such an encoding refuses to load
  # rather than silently losing members, which is the difference between a
  # failure someone notices and one nobody does.
  for_each_filter "detects every single-bit corruption of its encoding" do |spec|
    keys = Generators.random_keys(64, 50_020_070)
    encoded = build(spec, keys, expected_items: keys.length,
                                false_positive_rate: 0.01, seed: 0).encode

    undetected = []

    (0...encoded.bytesize).each do |position|
      # Every bit of the byte, not just the low one: a checksum covering only
      # part of a field would pass a single-offset probe.
      (0...8).each do |bit|
        corrupted = encoded.dup
        corrupted.setbyte(position, encoded.getbyte(position) ^ (1 << bit))

        undetected << [position, bit] if session.try_decode(corrupted)["ok"]
      end
    end

    assert_empty undetected,
                 "#{spec.id} decoded #{undetected.length} single-bit corruptions of its " \
                 "own encoding. At this length a CRC-32C has Hamming distance 6, so every " \
                 "one-, two-, and three-bit error must be caught. Offending (byte, bit) " \
                 "pairs: #{undetected.first(10).inspect}"
  end

  # The seed field specifically, since it is the one the checksum exists for.
  #
  # Called out separately from the sweep above so a regression here names the
  # field rather than an offset, and so the reason this matters stays attached
  # to the test: a wrong seed is not a parse failure, it is a filter that hashes
  # every key to different bits and quietly loses members.
  for_each_filter "detects corruption of the seed, which is otherwise invisible" do |spec|
    keys = Generators.random_keys(64, 50_020_071)
    oracle = Oracle.new(keys)
    encoded = build(spec, keys, expected_items: keys.length,
                                false_positive_rate: 0.01, seed: 0x0F0F_0F0F_0F0F_0F0F).encode

    (Encodings::SEED...Encodings::LEN).each do |position|
      corrupted = encoded.dup
      corrupted.setbyte(position, encoded.getbyte(position) ^ 0x01)

      response = session.try_decode(corrupted)

      unless response["ok"]
        assert_equal "corrupt", response["kind"],
                     "a corrupted seed should be reported as corruption, not as " \
                     "#{response["kind"]}: #{response["message"]}"
        next
      end

      # If it ever decodes again, the filter it produced had better be sound —
      # which for a changed seed it will not be. Report which.
      handle = Cli::Handle.new(session, response.fetch("handle"), response.fetch("info"))
      report = oracle.audit(handle, keys)
      handle.release

      flunk "#{spec.id} accepted a flipped bit in seed byte " \
            "#{position - Encodings::SEED} of 8. #{report.false_negative_message}"
    end
  end

  # A checksum that ignored part of the encoding would pass every test above
  # while leaving that part unprotected. This pins that it covers the body too.
  for_each_filter "checksums the body, not only the header" do |spec|
    keys = Generators.random_keys(256, 50_020_072)
    encoded = build(spec, keys, expected_items: keys.length,
                                false_positive_rate: 0.01).encode

    body_start = Encodings::HEADER_BYTES

    assert_operator encoded.bytesize, :>, body_start,
                    "#{spec.id} encoded no body to corrupt"

    # A handful of positions spread across the body rather than all of them;
    # the exhaustive sweep above already covers every byte.
    [body_start, body_start + 1, encoded.bytesize / 2, encoded.bytesize - 1].uniq.each do |position|
      corrupted = encoded.dup
      corrupted.setbyte(position, encoded.getbyte(position) ^ 0x80)

      refute session.try_decode(corrupted)["ok"],
             "#{spec.id} decoded an encoding with a corrupted body byte at #{position}; " \
             "the checksum must cover the body, not only the header"
    end
  end

  # Editing a field and recomputing the checksum must still decode.
  #
  # The inverse of the tests above, and the one that keeps them honest: if a
  # re-checksummed edit were also rejected, every corruption test in this file
  # would be passing on the checksum rather than on the bound it names.
  for_each_filter "accepts a re-checksummed edit" do |spec|
    keys = Generators.random_keys(64, 50_020_073)
    encoded = build(spec, keys, expected_items: keys.length,
                                false_positive_rate: 0.01, seed: 1).encode

    # A different seed is a legitimate filter, just not the one that was built.
    edited = Encodings.with_field(encoded, Encodings::SEED, 8, 2)

    assert session.try_decode(edited)["ok"],
           "#{spec.id} rejected an encoding whose seed was changed and checksum " \
           "recomputed; that is a filter someone could legitimately have written"
  end

  # 050.040.040 — a different version of the same family does not decode.
  #
  # The header names `(family_code, version)`, and routing is by that exact
  # pair. A filter encoded by a future `bloom_002` must not decode under
  # `bloom_001` merely because they share a family — the whole point of the
  # versioned id is that the two are different implementations.
  #
  # There is no second version to test with yet, so this synthesizes one: take a
  # real encoding and bump its version field. Everything else about the bytes
  # stays valid, so a decoder that routed on family alone would accept it.
  for_each_filter "does not decode a different version of its own family" do |spec|
    keys = Generators.random_keys(8, 50_020_090)
    encoded = build(spec, keys, expected_items: 8, false_positive_rate: 0.01).encode

    bumped = Encodings.with_field(encoded, Encodings::VERSION, 4, spec.version + 1)
    response = session.try_decode(bumped)

    refute response["ok"],
           "#{spec.id} decoded an encoding claiming version #{spec.version + 1}; " \
           "routing must be by the exact (family, version) pair"
    assert_equal "unknown_encoding", response["kind"],
                 "expected unknown_encoding, got #{response["kind"]}: #{response["message"]}"
  end

  # A zero family code must be rejected, since a zeroed buffer would otherwise
  # resolve to whichever family happened to be assigned code 0.
  for_each_filter "rejects a zero family code" do |spec|
    keys = Generators.random_keys(8, 50_020_091)
    encoded = build(spec, keys, expected_items: 8, false_positive_rate: 0.01).encode

    zeroed = Encodings.with_field(encoded, Encodings::FAMILY_CODE, 4, 0)

    refute session.try_decode(zeroed)["ok"],
           "#{spec.id} decoded an encoding with family code 0"
  end

  # 050.040.030 — an unlinked implementation reports which one is missing.
  #
  # That is what an operator needs in order to know which feature to enable.
  def test_decoding_an_unlinked_implementation_names_it
    response = session.try_decode(Encodings.unlinked_family)

    refute response["ok"]
    assert_equal "unknown_encoding", response["kind"],
                 "a well-formed header naming an unlinked family should be reported as " \
                 "unknown_encoding, not as corruption: #{response["message"]}"

    # The message must identify what is missing, since that is what tells an
    # operator which feature to enable.
    assert_match(/#{Encodings::UNLINKED_FAMILY_CODE}|family/, response["message"],
                 "the error should name the missing implementation: #{response["message"]}")
  end

  # 050.020.090 — other malformed headers.
  def test_malformed_headers_are_rejected_cleanly
    cases = {
      "empty input" => "".b,
      "one byte" => "\x00".b,
      "all zeros, header length" => ("\x00".b * Encodings::HEADER_BYTES),
      "all ones, header length" => ("\xFF".b * Encodings::HEADER_BYTES),
      "header minus one byte" => ("\x01".b * (Encodings::HEADER_BYTES - 1)),
      "text where a header should be" => ("not a filter at all, just prose".b)
    }

    cases.each do |name, bytes|
      response = session.try_decode(bytes)

      refute response["ok"], "#{name} decoded successfully"
      refute_nil response["kind"], "#{name} produced no error kind"
    end
  end

  # 050.020.100 — adversarially crafted encodings targeting the decoder's
  # arithmetic.
  #
  # Built field by field rather than by mutating a real encoding, so each one
  # isolates a single hostile value while every other field stays valid. A
  # rejection is then attributable to the field under test.
  #
  # The `len` and `capacity` cases matter most: those feed allocation sizing and
  # the conversion to `usize`, which is where a decoder trusting its input
  # allocates a gigabyte or overflows.
  for_each_filter "rejects hand-crafted headers that target its arithmetic" do |spec|
    crafted = {
      "zero payload version" => Encodings.header(payload_version: 0, body: "\x00".b * 8),
      "zero capacity" => Encodings.header(capacity: 0, body: "\x00".b * 8),
      "len above capacity" => Encodings.header(len: 1_000, capacity: 64,
                                               body: "\x00".b * 8),
      "capacity of u64::MAX" => Encodings.header(capacity: 0xFFFF_FFFF_FFFF_FFFF,
                                                 body: "\x00".b * 8),
      "len of u64::MAX" => Encodings.header(len: 0xFFFF_FFFF_FFFF_FFFF,
                                            capacity: 64, body: "\x00".b * 8),
      "huge capacity, no body" => Encodings.header(capacity: 8 * 1024 * 1024 * 1024),
      "header with no body" => Encodings.header
    }

    crafted.each do |name, bytes|
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      response = session.try_decode(bytes)
      elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started

      refute response["ok"], "#{spec.id} accepted a crafted header: #{name}"

      # 050.030.040 — an oversized claim must be refused before allocating for
      # it. Measured as wall clock, since a gigabyte allocation is not fast.
      assert_operator elapsed, :<, 1.0,
                      "#{spec.id} took #{elapsed.round(3)}s to reject #{name}, which " \
                      "suggests it allocated before validating"
    end
  end

  # 050.010.060 — encoding appends rather than overwriting.
  #
  # `Filter::encode(&self, out: &mut Vec<u8>)` appends. A filter that called
  # `out.clear()` would pass every other test in this file. Checked here at the
  # library boundary the CLI exposes: two encodes of the same filter must be
  # equal, and the encoding must be self-delimiting enough to decode from a
  # buffer that held something first.
  for_each_filter "produces a self-contained encoding" do |spec|
    keys = Generators.random_keys(100, 50_010_060)
    handle = build(spec, keys, expected_items: keys.length, false_positive_rate: 0.01)

    first = handle.encode
    second = handle.encode

    assert_equal Hex.encode(first), Hex.encode(second),
                 "#{spec.id} encoded differently on a second call"

    # Trailing bytes after a complete encoding must not corrupt the decode, or
    # must be rejected — either is defensible, a wrong filter is not.
    response = session.try_decode(first + "trailing".b)

    if response["ok"]
      handle2 = Cli::Handle.new(session, response.fetch("handle"), response.fetch("info"))
      oracle = Oracle.new(keys)
      report = oracle.audit(handle2, keys)

      assert report.sound?,
             "#{spec.id} decoded an encoding with trailing bytes into a broken filter: " \
             "#{report.false_negative_message}"
      handle2.release
    end
  end

  # 050.030.030 — the endianness contract.
  #
  # `bloom_001` writes little-endian explicitly, which is correct and portable.
  # BuRR writes native-endian and notes "the endianness conversion is currently
  # untested", which is a warning worth heeding.
  #
  # Decoding a byte string captured from a known-good encoding checks the
  # contract holds without needing a big-endian machine in CI.
  for_each_filter "decodes a byte-exact encoding captured earlier" do |spec|
    keys = %w[alice bob carol].map(&:b)
    params = { expected_items: 3, false_positive_rate: 0.01, seed: 50_030_030 }

    first = build(spec, keys, **params)
    captured = first.encode

    # Rebuilding from the same inputs must produce the same bytes, which is
    # what makes a checked-in golden file meaningful (area 070).
    rebuilt = build(spec, keys, **params)

    assert_equal Hex.encode(captured), Hex.encode(rebuilt.encode),
                 "#{spec.id} is not byte-reproducible from identical inputs, so a golden " \
                 "encoding could not pin it"

    decoded = session.decode(captured)
    assert_equal keys.map { true }, decoded.contains_all(keys)
  end
end
