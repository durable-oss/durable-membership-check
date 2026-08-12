# frozen_string_literal: true

require "test_helper"

# Tests for the test harness.
#
# Not vanity. A harness bug produces filter failures that are not filter
# failures, and — worse — filter successes that are not successes. Both happened
# while this suite was being written:
#
# - The probe mixer clamped a 25% member fraction to 5% and the sweep reported
#   the resulting mismatch as a bloom defect.
# - A grep meant to catch unseeded RNGs matched its own documentation.
#
# Plan step 010.030.050 makes the general point: "A test harness that silently
# produces a 0.6 mix when asked for 0.5 will report false positive rates that
# are wrong in a direction nobody notices."
class HarnessTest < Minitest::Test
  include DmcCheck

  # Hex must survive every byte, since keys are arbitrary bytes and the ones
  # worth testing are exactly the ones that are not text.
  def test_hex_round_trips_every_byte_value
    original = (0..255).map(&:chr).join.b

    assert_equal original, Hex.decode(Hex.encode(original))
  end

  def test_hex_returns_binary_encoded_strings
    # A decoded key that differs from its source by encoding alone would compare
    # unequal in the oracle while being byte-identical.
    decoded = Hex.decode(Hex.encode("key".b))

    assert_equal Encoding::BINARY, decoded.encoding
  end

  # Every generator must produce the count it was asked for, and the ones that
  # promise distinctness must deliver it. A generator that silently returns
  # fewer keys would weaken every test built on it.
  def test_generators_produce_the_requested_count
    counts = [0, 1, 7, 100, 1_000]

    counts.each do |count|
      Generators.standard_suite(count, seed: 1).each do |name, keys|
        assert_equal count, keys.length, "#{name} produced #{keys.length} keys, asked for #{count}"
      end
    end
  end

  # The generators that claim distinct keys must actually give them. A
  # duplicate-bearing "distinct" set would make a peeling filter fail
  # construction and look like a filter bug.
  def test_distinct_generators_produce_distinct_keys
    # `variable_length_keys` deliberately includes short keys, where the space
    # of possible values is small enough that collisions are expected.
    expected_distinct = %w[random sequential rotated_21 rotated_58 reversed reversed_32
                           prefixed prefixed_multiplied small timestamps suffixed]

    Generators.standard_suite(2_000, seed: 2).each do |name, keys|
      next unless expected_distinct.include?(name)

      assert_equal keys.length, keys.uniq.length,
                   "#{name} produced #{keys.length - keys.uniq.length} duplicate keys"
    end
  end

  # 010.020.090 — probe keys must be disjoint from the member set.
  #
  # This is the step `external/fastfilter_cpp` flags as wrong in its own code:
  # its FPR calculation "is obviously technically wrong" because it assumes no
  # overlap. Guaranteeing disjointness removes the correction entirely — but
  # only if the guarantee holds.
  def test_disjoint_probes_are_actually_disjoint
    [0, 1, 100, 5_000].each do |member_count|
      members = Generators.random_keys(member_count, 3)
      probes = Generators.disjoint_probe_keys(members, 2_000, 3)

      assert_equal 2_000, probes.length
      assert_empty (members & probes),
                   "#{(members & probes).length} probe keys were also members"
      assert_equal probes.length, probes.uniq.length, "probe keys were not distinct"
    end
  end

  # The testkit's mixer must not be dmc-core's.
  #
  # Plan step 010.020.010 flags this as a hazard rather than a convenience:
  # feeding a filter keys produced by its own finalizer could mask a weak mixer,
  # since the two would cancel.
  def test_the_testkit_mixer_differs_from_the_one_under_test
    # dmc_core::hash::mix, restated here so a change to it is caught by a
    # difference rather than by both sides moving together.
    core_mix = lambda do |value|
      mask = Generators::MASK64
      z = value & mask
      z = ((z ^ (z >> 30)) * 0xBF58_476D_1CE4_E5B9) & mask
      z = ((z ^ (z >> 27)) * 0x94D0_49BB_1331_11EB) & mask
      (z ^ (z >> 31)) & mask
    end

    trials = 10_000
    agreeing = (0...trials).count { |i| Generators.mix64(i) == core_mix.call(i) }

    # Not zero: two independent bijections over u64 will coincide occasionally
    # by chance, and demanding perfect disagreement would be asserting something
    # neither function promises. What matters is that they are not the same
    # function, which a handful of coincidences does not threaten.
    assert_operator agreeing, :<, 10,
                    "the testkit mixer agrees with dmc-core's on #{agreeing} of #{trials} " \
                    "inputs; they must be independent, or feeding a filter keys made by its " \
                    "own finalizer could let a weak mixer mask itself"
  end

  # The testkit mixer must still be a bijection, which is what lets
  # `random_keys` skip a deduplication pass.
  def test_the_testkit_mixer_is_injective_over_a_large_range
    outputs = (0...50_000).map { |i| Generators.mix64(i) }

    assert_equal outputs.length, outputs.uniq.length,
                 "the testkit mixer collided, so random_keys cannot promise distinct keys"
  end

  def test_rotation_and_bit_reversal_are_correct
    assert_equal 0b1010, Generators.rotl64(0b0101, 1)
    assert_equal 1, Generators.rotl64(1, 0)
    # Rotating left by 63 moves bit 0 to bit 63.
    assert_equal 1 << 63, Generators.rotl64(1, 63)
    # Rotating by 64 is a full turn.
    assert_equal 0xDEAD, Generators.rotl64(0xDEAD, 64)

    assert_equal 1 << 63, Generators.reverse_bits64(1)
    assert_equal 1, Generators.reverse_bits64(1 << 63)
    assert_equal Generators::MASK64, Generators.reverse_bits64(Generators::MASK64)
    assert_equal 0, Generators.reverse_bits64(0)
  end

  # The degenerate sets must actually be degenerate in the way each name claims.
  def test_degenerate_sets_are_what_they_say
    sets = Generators.degenerate_key_sets.to_h

    assert_empty sets.fetch("empty set")
    assert_equal [""], sets.fetch("single empty key")
    assert_equal 1, sets.fetch("all keys identical").uniq.length
    assert_equal 1_000, sets.fetch("many empty keys").length

    one_bit = sets.fetch("two keys differing in one bit")
    assert_equal 2, one_bit.length
    assert_equal 1, (one_bit[0].getbyte(0) ^ one_bit[1].getbyte(0)).digits(2).sum

    trailing = sets.fetch("trailing zero bytes")
    assert_equal trailing.length, trailing.uniq.length
    assert_equal trailing.map(&:bytesize).sort, trailing.map(&:bytesize)

    # The invalid-UTF-8 set must genuinely be invalid, or it tests nothing.
    sets.fetch("invalid UTF-8").each do |key|
      refute key.dup.force_encoding(Encoding::UTF_8).valid_encoding?,
             "#{key.inspect} is valid UTF-8, so it does not test the byte-key path"
    end
  end

  # The oracle must classify all four cases correctly, since every membership
  # assertion in the suite routes through it.
  def test_oracle_classifies_all_four_cases
    oracle = Oracle.new(%w[a b])

    assert_equal :true_positive, oracle.classify("a", true)
    assert_equal :false_negative, oracle.classify("a", false)
    assert_equal :false_positive, oracle.classify("z", true)
    assert_equal :true_negative, oracle.classify("z", false)
  end

  def test_oracle_reports_the_first_offender
    report = AuditReport.new(3)
    report.record("first".b, :true_positive, 0)
    report.record("bad".b, :false_negative, 1)
    report.record("worse".b, :false_negative, 2)
    report.advance(3)

    assert_equal 2, report.false_negatives
    refute_predicate report, :sound?
    assert_includes report.false_negative_message, "index 1"
    assert_includes report.false_negative_message, Hex.encode("bad".b)
  end

  def test_oracle_rate_is_measured_against_non_members_only
    report = AuditReport.new(4)
    report.record("m".b, :true_positive, 0)
    report.record("n1".b, :false_positive, 1)
    report.record("n2".b, :true_negative, 2)
    report.record("n3".b, :true_negative, 3)
    report.advance(4)

    # One false positive out of three non-members, not out of four probes.
    assert_in_delta 1.0 / 3, report.false_positive_rate, 1e-12
    assert_in_delta 0.5, report.positive_rate, 1e-12
  end

  # 010.040.010 — the Poisson bound, ported verbatim from BuRR.
  #
  # The trailing `+ 1.0` matters at small expected counts, where the tail is
  # fat, so it is checked explicitly rather than assumed.
  def test_poisson_upper_bound_matches_the_reference_formula
    [[0.0, 1], [1.0, 5], [100.0, 131], [10_000.0, 10_301]].each do |expected, bound|
      assert_equal bound, Tolerance.poisson_upper_bound(expected, 3.0),
                   "PoissonUpperBound(#{expected}, 3.0) should be #{bound}"
    end
  end

  def test_poisson_bounds_are_ordered_and_non_negative
    [0.0, 0.5, 10.0, 1_000.0].each do |expected|
      low = Tolerance.poisson_lower_bound(expected)
      high = Tolerance.poisson_upper_bound(expected)

      assert_operator low, :>=, 0
      assert_operator low, :<=, high
    end
  end

  # The bound must tighten as the trial count grows. That is the whole reason
  # for deriving it rather than using a fixed threshold: a 28% margin that never
  # shrinks would not catch a slow regression at any scale.
  def test_the_bound_tightens_as_trials_grow
    margins = [1_000, 10_000, 100_000, 1_000_000].map do |trials|
      bound = Tolerance.binomial_bounds(trials, 0.01)
      (bound.last - (trials * 0.01)) / (trials * 0.01)
    end

    margins.each_cons(2) do |wider, tighter|
      assert_operator tighter, :<, wider,
                      "the bound did not tighten with more trials: #{margins.inspect}"
    end

    assert_operator margins.last, :<, 0.05,
                    "at a million trials the bound should be within a few percent, " \
                    "got #{margins.last.round(4)}"
  end

  # 010.040.020 — the normal approximation guard.
  def test_binomial_bounds_guard_the_normal_approximation
    refute Tolerance.normal_approximation_valid?(100, 0.01), "1 expected success is too few"
    refute Tolerance.normal_approximation_valid?(100, 0.999), "0.1 expected failures is too few"
    assert Tolerance.normal_approximation_valid?(10_000, 0.01)
    assert Tolerance.normal_approximation_valid?(1_000, 0.5)

    # Where the approximation does not hold the bound must still be usable, and
    # wider rather than narrower.
    narrow = Tolerance.binomial_bounds(100, 0.01)

    assert_includes narrow, 1
    assert_operator narrow.last, :>=, 1
  end

  # A two-sided bound must actually bound both sides. A lower bound that is
  # always zero would silently drop half the check.
  def test_binomial_bounds_are_two_sided_where_it_matters
    bound = Tolerance.binomial_bounds(100_000, 0.1)

    assert_operator bound.first, :>, 0,
                    "at 10000 expected successes the lower bound should not be zero"
    assert_includes bound, 10_000
    refute_includes bound, 5_000, "a rate half the target should fall outside the bound"
    refute_includes bound, 20_000, "a rate double the target should fall outside the bound"
  end

  # The independently written bloom formulas must agree with the implementation
  # they are used to check. If they drifted, area 030's space assertions would
  # be checking the implementation against a different implementation's bug.
  def test_the_bloom_closed_forms_are_self_consistent
    [[1_000, 0.01], [10_000, 0.001], [100, 0.1]].each do |keys, rate|
      bits = Tolerance.bloom_optimal_bits(keys, rate)
      hashes = Tolerance.bloom_optimal_hashes(bits, keys)
      achieved = Tolerance.bloom_false_positive_rate(bits: bits, keys: keys, hashes: hashes)

      assert_in_delta rate, achieved, rate * 0.15,
                      "optimal sizing for #{keys} keys at #{rate} achieves #{achieved.round(6)}, " \
                      "which is not close to the request"
    end
  end

  # The harness's CRC-32C must match the published vectors, not merely the Rust
  # implementation it checks.
  #
  # Two implementations that agree only with each other prove nothing: a shared
  # misreading of the spec agrees with itself perfectly. Agreeing with RFC 3720
  # is what makes the independence worth having.
  def test_crc32c_matches_the_rfc_3720_check_values
    {
      "" => 0x0000_0000,
      "123456789" => 0xE306_9283,
      ("\x00" * 32) => 0x8A91_36AA,
      ("\xFF" * 32) => 0x62A8_AB43
    }.each do |input, expected|
      assert_equal expected, Crc32c.checksum(input.b),
                   "CRC-32C of #{input.bytesize} bytes disagreed with RFC 3720 appendix B"
    end
  end

  # And it must agree with the Rust side on real encodings.
  #
  # Checked by round trip rather than by comparing numbers: a filter this
  # harness re-checksums must still decode, which is the property every
  # corruption test in the suite depends on.
  def test_the_harness_checksum_agrees_with_the_implementation
    spec = FilterSpec.all.first
    keys = Generators.random_keys(64, 7)
    encoded = Cli::Session.open do |s|
      s.build(spec.id, keys, expected_items: keys.length, false_positive_rate: 0.01).encode
    end

    # Recomputing over unmodified bytes must reproduce the value already there.
    assert_equal Hex.encode(encoded), Hex.encode(Encodings.finalize(encoded)),
                 "the harness computed a different checksum than the implementation wrote"

    # And an edit the harness re-checksums must be accepted.
    edited = Encodings.with_field(encoded, Encodings::SEED, 8, 99)

    Cli::Session.open do |s|
      assert s.try_decode(edited)["ok"],
             "an encoding the harness re-checksummed was rejected, which would make " \
             "every corruption test in the suite pass for the wrong reason"
    end
  end

  # Chaining must match a single pass, since the implementation checksums a
  # header and a body without concatenating them.
  def test_crc32c_chaining_matches_one_pass
    whole = (0..255).map(&:chr).join.b

    [0, 1, 17, 128, 255, 256].each do |split|
      head = whole.byteslice(0, split)
      tail = whole.byteslice(split, whole.bytesize - split)

      assert_equal Crc32c.checksum(whole),
                   Crc32c.update(Crc32c.update(0, head), tail),
                   "chaining disagreed at a #{split}-byte split"
    end
  end

  # The size tiers must respond to the environment variable rather than to a
  # build flag, so a slow run needs no recompilation.
  def test_slow_tier_gate_reads_the_environment
    original = ENV.fetch("DMC_SLOW_TESTS", nil)

    ENV["DMC_SLOW_TESTS"] = nil
    refute_predicate Tiers, :slow?
    assert_equal [Tiers::SMALL], Tiers.sizes

    ENV["DMC_SLOW_TESTS"] = "0"
    refute_predicate Tiers, :slow?, "0 should mean off, not merely set"

    ENV["DMC_SLOW_TESTS"] = "1"
    assert_predicate Tiers, :slow?
    assert_includes Tiers.sizes, Tiers::MEDIUM
    assert_equal Tiers::STATISTICAL_PROBES_SLOW, Tiers.statistical_probes
  ensure
    ENV["DMC_SLOW_TESTS"] = original
  end

  # The CLI transport must report a missing binary usefully rather than raising
  # a bare file-not-found, since that is the most likely first-run failure.
  def test_a_missing_binary_is_reported_with_instructions
    original = ENV.fetch("DMC_CLI", nil)
    ENV["DMC_CLI"] = "/nonexistent/dmc-cli"

    error = assert_raises(Cli::TransportError) { Cli.assert_available! }

    assert_includes error.message, "cargo build -p dmc-cli"
    assert_includes error.message, "DMC_CLI"
  ensure
    ENV["DMC_CLI"] = original
  end

  # A filter spec must reflect what the registry declared, not a default.
  def test_filter_specs_carry_every_declared_capability
    expected_axes = %w[
      tolerates_duplicate_keys order_independent_construction len_counts_duplicates
      honors_target_fpr supports_deletion is_adaptive max_practical_keys
      supports_union supports_intersection estimates_cardinality
    ]

    FilterSpec.all.each do |spec|
      expected_axes.each do |axis|
        assert_includes spec.capabilities.keys, axis,
                        "#{spec.id} did not report #{axis}; the suite would silently skip " \
                        "or misapply the checks gated on it"
      end
    end
  end
end
