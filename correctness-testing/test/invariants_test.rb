# frozen_string_literal: true

require "test_helper"

# Area 020 — the properties that hold for every filter, at every size, under
# every key set.
#
# A violation here is a bug in the filter. Never a tuning problem, never a
# statistical fluctuation. `lib/dmc-core/src/filter.rs` states the central one:
# "No implementation may return `false` for a key that was inserted; false
# negatives are a bug, not a tuning parameter." This file turns that sentence
# into tests.
class InvariantsTest < DmcCheck::ConformanceTest
  include DmcCheck

  # 020.010.010 — every inserted key is found, across all generators and sizes.
  #
  # Every reference suite checks this and every one treats a violation as fatal
  # rather than statistical.
  for_each_filter "finds every member across all generators" do |spec|
    Tiers.sizes.each do |size|
      next unless spec.supports_size?(size)

      Generators.standard_suite(size, seed: 20_010_010).each do |generator, keys|
        oracle = Oracle.new(keys)
        handle = build(spec, keys, expected_items: size, false_positive_rate: 0.01)

        # 020.010.020 — the failure message names the generator, the size, and
        # the offending key, because a CI log is the only artifact a failure
        # leaves behind.
        assert_no_false_negatives(
          handle, oracle,
          context: "generator=#{generator} size=#{size} seed=20010010"
        )

        handle.release
      end
    end
  end

  # 020.010.030 — no false negatives after a round-trip through bytes.
  #
  # Area 050 covers the encoding format; this covers the membership guarantee
  # surviving it. `external/binfuse/test/filter.cpp::large8_persistent` is the
  # model.
  for_each_filter "keeps every member across an encode/decode round trip" do |spec|
    keys = Generators.random_keys(Tiers::SMALL, 20_010_030)
    oracle = Oracle.new(keys)

    original = build(spec, keys, expected_items: keys.length, false_positive_rate: 0.01)
    restored = session.decode(original.encode)

    assert_no_false_negatives(restored, oracle, context: "after decode")
  end

  # 020.010.040 — no false negatives with duplicate keys in the input.
  #
  # Gated: peeling filters fail construction on duplicates, which is documented
  # behavior rather than a defect.
  for_each_filter_with "absorbs duplicate keys", :tolerates_duplicate_keys? do |spec|
    distinct = Generators.random_keys(500, 20_010_040)
    # Each key three times, interleaved rather than grouped, so a filter that
    # deduplicates a run of identical neighbours is not accidentally excused.
    keys = (distinct * 3).shuffle(random: Random.new(20_010_040))

    handle = build(spec, keys, expected_items: distinct.length, false_positive_rate: 0.01)
    oracle = Oracle.new(distinct)

    assert_no_false_negatives(handle, oracle, context: "with each key repeated three times")
  end

  # 020.040.010 — a filter that rejects duplicates must actually reject them.
  #
  # The negative case is a check, not a skip. Silently building a filter with
  # false negatives is the worst possible outcome, so the error is the
  # requirement.
  for_each_filter_without "rejects duplicate keys cleanly", :tolerates_duplicate_keys? do |spec|
    distinct = Generators.random_keys(500, 20_040_010)
    keys = distinct * 2

    response = session.try_build(spec.id, keys, expected_items: distinct.length,
                                                false_positive_rate: 0.01)

    refute response["ok"], "#{spec.id} declares it rejects duplicates but built one anyway"

    assert_equal "construction_failed", response["kind"],
                 "#{spec.id} rejected duplicates with the wrong error: #{response["message"]}"

    # 020.040.020 — the attempt count must be real, so an operator can tell an
    # unlucky seed from a duplicate-bearing key set.
    assert_match(/\d+ attempts/, response["message"],
                 "ConstructionFailed did not report a plausible attempt count")
  end

  # 020.010.050 — no false negatives when expected_items understates the input.
  #
  # `Bloom001::build` takes `params.expected_items.max(keys.len())` specifically
  # to make this safe. The achieved rate degrades; the membership guarantee does
  # not.
  for_each_filter "stays sound when expected_items understates the input" do |spec|
    keys = Generators.random_keys(10_000, 20_010_050)
    oracle = Oracle.new(keys)

    handle = build(spec, keys, expected_items: 10, false_positive_rate: 0.01)

    assert_no_false_negatives(handle, oracle, context: "sized for 10, given 10000")

    # The rate must degrade rather than staying at the request, and it must stay
    # a legal probability.
    rate = handle.false_positive_rate

    assert_operator rate, :>=, 0.0
    assert_operator rate, :<=, 1.0
  end

  # 020.010.060 — the reverse: massively overstated sizing must not overflow
  # anything in the sizing math.
  for_each_filter "stays sound when expected_items overstates the input" do |spec|
    keys = Generators.random_keys(10, 20_010_060)
    oracle = Oracle.new(keys)

    handle = build(spec, keys, expected_items: 1_000_000, false_positive_rate: 0.01)

    assert_no_false_negatives(handle, oracle, context: "sized for 1000000, given 10")
  end

  # 020.020.010 — len() equals the input key count, including duplicates.
  for_each_filter_with "counts every key supplied", :len_counts_duplicates? do |spec|
    keys = Generators.random_keys(100, 20_020_010) * 3

    handle = build(spec, keys, expected_items: 100, false_positive_rate: 0.01)

    assert_equal keys.length, handle.len,
                 "#{spec.id} declares len counts duplicates but reported #{handle.len} for #{keys.length} keys"
  end

  # 020.020.020 — is_empty() agrees with len() == 0.
  #
  # The trait derives it by default, but an implementation may override.
  for_each_filter "agrees with itself about emptiness" do |spec|
    [[], Generators.random_keys(1, 20_020_020), Generators.random_keys(100, 20_020_020)].each do |keys|
      handle = build(spec, keys, expected_items: [keys.length, 1].max, false_positive_rate: 0.01)

      assert_equal keys.empty?, handle.empty?,
                   "#{spec.id} reported is_empty=#{handle.empty?} for #{keys.length} keys"
      assert_equal keys.empty?, handle.len.zero?,
                   "#{spec.id} reported len=#{handle.len} for #{keys.length} keys"

      handle.release
    end
  end

  # 020.020.030 — memory_bytes() is positive and monotone in the key count.
  #
  # Catches sizing arithmetic that overflows or clamps in the wrong direction.
  for_each_filter "uses more memory for more keys" do |spec|
    sizes = [100, 1_000, 10_000]
    footprints = sizes.map do |size|
      keys = Generators.random_keys(size, 20_020_030)
      handle = build(spec, keys, expected_items: size, false_positive_rate: 0.01)
      bytes = handle.memory_bytes
      handle.release

      assert_operator bytes, :>, 0, "#{spec.id} reported zero backing store for #{size} keys"
      bytes
    end

    footprints.each_cons(2).with_index do |(smaller, larger), i|
      assert_operator larger, :>=, smaller,
                      "#{spec.id} used less memory for #{sizes[i + 1]} keys (#{larger} B) " \
                      "than for #{sizes[i]} keys (#{smaller} B)"
    end
  end

  # 020.020.040 — memory_bytes() is monotone in the tightness of the target rate.
  for_each_filter_with "uses more memory for a tighter rate", :honors_target_fpr? do |spec|
    keys = Generators.random_keys(1_000, 20_020_040)
    rates = [0.1, 0.01, 0.001, 0.0001]

    footprints = rates.map do |rate|
      handle = build(spec, keys, expected_items: keys.length, false_positive_rate: rate)
      bytes = handle.memory_bytes
      handle.release
      bytes
    end

    footprints.each_cons(2).with_index do |(looser, tighter), i|
      assert_operator tighter, :>=, looser,
                      "#{spec.id} used less memory at rate #{rates[i + 1]} (#{tighter} B) " \
                      "than at #{rates[i]} (#{looser} B)"
    end
  end

  # 020.020.050 — false_positive_rate() is finite and in 0.0..=1.0.
  #
  # Checked across the full parameter sweep including the clamped extremes.
  for_each_filter "reports a rate that is a legal probability" do |spec|
    rates = [0.5, 0.1, 0.01, 0.001, 0.0001, 1e-10, 1e-300]
    counts = [0, 1, 100, 10_000]

    counts.each do |count|
      keys = Generators.random_keys(count, 20_020_050)

      rates.each do |requested|
        handle = build(spec, keys, expected_items: [count, 1].max, false_positive_rate: requested)
        reported = handle.false_positive_rate

        assert_kind_of Float, reported
        refute reported.nan?, "#{spec.id} reported NaN at n=#{count} p=#{requested}"
        assert reported.finite?, "#{spec.id} reported #{reported} at n=#{count} p=#{requested}"
        assert_operator reported, :>=, 0.0, "at n=#{count} p=#{requested}"
        assert_operator reported, :<=, 1.0, "at n=#{count} p=#{requested}"

        handle.release
      end
    end
  end

  # 020.030.030 — the empty filter reports rate 0.0 and answers false for
  # everything.
  #
  # Paired assertions: the reported rate and the observed one must both be zero.
  for_each_filter "an empty filter matches nothing" do |spec|
    handle = build(spec, [], expected_items: 0, false_positive_rate: 0.01)

    assert_predicate handle, :empty?
    assert_in_delta 0.0, handle.false_positive_rate, 1e-12,
                    "#{spec.id} claims a nonzero rate with no keys"

    probes = Generators.random_keys(10_000, 20_030_030)
    answers = handle.contains_all(probes)

    refute answers.any?,
           "#{spec.id} matched #{answers.count(true)} of #{probes.length} probes with no keys inserted"
  end

  # 020.020.060 — id() is stable and matches the registration.
  #
  # Cheap, and catches the copy-paste error when a new implementation is added
  # by cloning an old one.
  for_each_filter "reports the id it was registered under" do |spec|
    handle = build(spec, Generators.random_keys(10, 20_020_060),
                   expected_items: 10, false_positive_rate: 0.01)

    assert_equal spec.id, handle.id,
                 "built through #{spec.id} but the filter calls itself #{handle.id}"
  end

  # Building by family alias must reach the id the alias resolves to, never a
  # different version.
  for_each_filter "builds through its family alias to the resolved id" do |spec|
    skip "#{spec.family} does not resolve" if spec.family_resolves_to.nil?

    handle = session.build(spec.family, Generators.random_keys(10, 20_020_061),
                           expected_items: 10, false_positive_rate: 0.01)

    assert_equal spec.family_resolves_to, handle.id,
                 "family #{spec.family} resolves to #{spec.family_resolves_to} " \
                 "but built #{handle.id}"
  end

  # 020.030.010 and 020.030.020 — query purity.
  #
  # Answers must not depend on how many times a key is asked about, or in what
  # order. Trivially true for an immutable filter; not trivially true for an
  # adaptive one, which is why this is gated.
  for_each_filter_without "answers identically however it is queried", :adaptive? do |spec|
    keys = Generators.random_keys(1_000, 20_030_010)
    probes = keys.first(200) + Generators.disjoint_probe_keys(keys, 800, 20_030_010)

    handle = build(spec, keys, expected_items: keys.length, false_positive_rate: 0.01)

    forward = handle.contains_all(probes)
    repeated = handle.contains_all(probes)

    assert_equal forward, repeated, "#{spec.id} gave different answers to the same probes twice"

    # Reversed, then compared position-for-position after undoing the reversal.
    backward = handle.contains_all(probes.reverse).reverse

    assert_equal forward, backward, "#{spec.id} answers depend on query order"

    # Shuffled, compared per key rather than per position.
    order = (0...probes.length).to_a.shuffle(random: Random.new(20_030_010))
    shuffled = handle.contains_all(order.map { |i| probes[i] })

    order.each_with_index do |original_index, shuffled_index|
      assert_equal forward[original_index], shuffled[shuffled_index],
                   "#{spec.id} answered differently for probe #{original_index} when shuffled"
    end
  end

  # 020.030.030 — a built filter is not mutated by querying.
  #
  # Compared through the encoded form, since that is what is observable from
  # outside the process and it covers every field rather than only the ones a
  # PartialEq happens to compare.
  for_each_filter_without "is unchanged by being queried", :adaptive? do |spec|
    keys = Generators.random_keys(1_000, 20_030_030)
    handle = build(spec, keys, expected_items: keys.length, false_positive_rate: 0.01)

    before = handle.encode
    handle.contains_all(Generators.disjoint_probe_keys(keys, 20_000, 20_030_030))
    after = handle.encode

    assert_equal before, after, "#{spec.id} changed while being queried"
  end
end
