# frozen_string_literal: true

require "test_helper"

# Area 030 — false positive rate measurement and bounds.
#
# False positives are the product, not the defect. This checks the rate is what
# the filter claims, that `false_positive_rate()` does not lie, and that the
# space/accuracy tradeoff lands where the papers under `RESEARCH/` say it
# should.
#
# Every assertion here is seeded and deterministic. Every bound is derived from
# the trial count rather than picked to make a run pass — see the note on seed
# shopping in `DmcCheck::Tolerance`.
class StatisticalTest < DmcCheck::ConformanceTest
  include DmcCheck

  # 030.010.030 — the rate is bounded by the trial count, not by a threshold.
  #
  # `external/binfuse/test/filter.cpp` asserts `fpr <= 0.005` against a nominal
  # 0.0039: a 28% margin with no derivation, which passes a filter that is
  # meaningfully worse than advertised. The Rust test it replaces conceded the
  # same thing in a comment — "catches a broken filter, not a mildly mistuned
  # one".
  #
  # A three-sigma Poisson bound at 100,000 probes and a 0.01 target allows 1.9%
  # above expectation, and tightens as the trial count grows.
  for_each_filter_with "achieves the rate it was asked for", :honors_target_fpr? do |spec|
    keys = Generators.random_keys(10_000, 30_010_030)
    probes = Tiers.statistical_probes

    [0.1, 0.01, 0.001].each do |target|
      handle = build(spec, keys, expected_items: keys.length, false_positive_rate: target)
      probe_keys = Generators.disjoint_probe_keys(keys, probes, 30_010_030)

      oracle = Oracle.new(keys)
      report = oracle.audit(handle, probe_keys)

      # 030.010.010 — the probe set is disjoint by construction, so no
      # intersection correction is needed. Assert that rather than assume it.
      assert_equal 0, report.actual_members,
                   "the probe set was supposed to be disjoint from the members"

      # The filter's own claim about itself is the reference, not the request:
      # sizing rounds, so the achieved rate legitimately differs from what was
      # asked for. 030.030.010 is the check that the claim is honest.
      claimed = handle.false_positive_rate
      expected_count = probes * claimed

      # 030.010.040 — two-sided. A rate far below target is also a defect,
      # most likely a filter sized far larger than requested.
      bound = Tolerance.binomial_bounds(probes, claimed)

      assert_includes bound, report.false_positives,
                      Tolerance.explain(
                        observed: report.false_positives,
                        expected: expected_count,
                        bound: bound,
                        trials: probes,
                        seed: 30_010_030,
                        label: "#{spec.id} false positives at a #{target} request " \
                               "(the filter claims #{claimed.round(6)})"
                      )

      handle.release
    end
  end

  # 030.030.010 — the reported rate predicts the observed rate.
  #
  # `Filter::false_positive_rate` is documented as derived from the filter's
  # actual size and key count, so it may differ from the request. This asserts
  # the *reported* value predicts the *observed* one, which is the check that
  # catches a filter clamped by MAX_BITS: it cannot honor the request, but it
  # must still describe itself honestly.
  #
  # Not gated on honors_target_fpr: a filter that ignores the request must still
  # report accurately, which is exactly when this matters most.
  for_each_filter "reports a rate that predicts what it does" do |spec|
    keys = Generators.random_keys(5_000, 30_030_010)
    probes = Tiers.statistical_probes

    handle = build(spec, keys, expected_items: keys.length, false_positive_rate: 0.01)
    claimed = handle.false_positive_rate

    probe_keys = Generators.disjoint_probe_keys(keys, probes, 30_030_010)
    oracle = Oracle.new(keys)
    report = oracle.audit(handle, probe_keys)

    bound = Tolerance.binomial_bounds(probes, claimed)

    assert_includes bound, report.false_positives,
                    Tolerance.explain(
                      observed: report.false_positives,
                      expected: probes * claimed,
                      bound: bound,
                      trials: probes,
                      seed: 30_030_010,
                      label: "#{spec.id} reported #{claimed.round(6)} but observed " \
                             "#{report.false_positive_rate.round(6)}"
                    )
  end

  # 030.020.010 through .030 — the found-probability sweep.
  #
  # The core methodology of
  # `external/fastfilter_cpp/benchmarks/bulk-insert-and-query.cc`. One filter,
  # five probe sets at known member fractions.
  #
  # At found-probability f with false positive rate p, the expected positive
  # fraction is `f + (1-f) * p`. Asserting each point against that prediction is
  # the strongest single statistical check available: it constrains the rate and
  # the membership guarantee simultaneously.
  for_each_filter "matches its prediction across the found-probability sweep" do |spec|
    keys = Generators.random_keys(5_000, 30_020_010)
    probes = Tiers.statistical_probes

    handle = build(spec, keys, expected_items: keys.length, false_positive_rate: 0.01)
    claimed = handle.false_positive_rate
    oracle = Oracle.new(keys)

    non_members = Generators.disjoint_probe_keys(keys, probes, 30_020_010)

    positive_rates = {}

    [0.0, 0.25, 0.5, 0.75, 1.0].each do |found_probability|
      member_count = (probes * found_probability).round
      mixed = build_mix(keys, non_members, member_count, probes, seed: 30_020_010)

      report = oracle.audit(handle, mixed)

      # 030.020.020 — the positive count may never fall below the true member
      # count. `bulk-insert-and-query.cc` reports this as a printed warning;
      # here it is a hard assertion, because it detects a false negative
      # without needing to know which key failed.
      assert_operator report.true_positives + report.false_positives, :>=,
                      report.actual_members,
                      "#{spec.id} returned fewer positives (#{report.true_positives +
                        report.false_positives}) than there were genuine members " \
                      "(#{report.actual_members}) at found-probability #{found_probability}"

      assert report.sound?,
             "#{spec.id} at found-probability #{found_probability}: " \
             "#{report.false_negative_message}"

      # 030.020.030 — the predicted positive fraction.
      predicted = found_probability + ((1 - found_probability) * claimed)
      observed_positives = report.true_positives + report.false_positives
      bound = Tolerance.binomial_bounds(probes, predicted)

      assert_includes bound, observed_positives,
                      Tolerance.explain(
                        observed: observed_positives,
                        expected: probes * predicted,
                        bound: bound,
                        trials: probes,
                        seed: 30_020_010,
                        label: "#{spec.id} positives at found-probability " \
                               "#{found_probability} (predicted f + (1-f)p = " \
                               "#{predicted.round(6)})"
                      )

      positive_rates[found_probability] = report.positive_rate
    end

    # 030.020.010 — the intermediate points must increase monotonically. A
    # filter correct at 0% and 100% but nonlinear between them has a bug that
    # neither endpoint catches.
    sorted = positive_rates.keys.sort
    sorted.each_cons(2) do |lower, higher|
      assert_operator positive_rates[higher], :>=, positive_rates[lower],
                      "#{spec.id} positive rate fell from #{positive_rates[lower].round(5)} " \
                      "at found-probability #{lower} to #{positive_rates[higher].round(5)} " \
                      "at #{higher}"
    end
  end

  # 030.030.020 — sweep the target rate across four orders of magnitude.
  #
  # At 0.5 the Poisson approximation fails and a binomial bound is required,
  # which is why `Tolerance.binomial_bounds` exists.
  for_each_filter_with "tracks its request across four orders of magnitude",
                       :honors_target_fpr? do |spec|
    keys = Generators.random_keys(2_000, 30_030_020)
    probes = Tiers.statistical_probes

    [0.5, 0.1, 0.01, 0.001, 0.0001].each do |target|
      handle = build(spec, keys, expected_items: keys.length, false_positive_rate: target)
      claimed = handle.false_positive_rate

      # Where not clamped, the claim should be near the request. A factor of
      # four either way is loose enough to absorb sizing rounding, which is
      # coarse at small key counts, and tight enough to catch a filter that
      # ignores the request entirely.
      assert_operator claimed, :<=, target * 4,
                      "#{spec.id} claims #{claimed.round(8)} for a #{target} request"

      probe_keys = Generators.disjoint_probe_keys(keys, probes, 30_030_020)
      oracle = Oracle.new(keys)
      report = oracle.audit(handle, probe_keys)

      bound = Tolerance.binomial_bounds(probes, claimed)

      assert_includes bound, report.false_positives,
                      Tolerance.explain(
                        observed: report.false_positives,
                        expected: probes * claimed,
                        bound: bound,
                        trials: probes,
                        seed: 30_030_020,
                        label: "#{spec.id} at a #{target} request"
                      )

      handle.release
    end
  end

  # 030.030.040 — an undersized request degrades gracefully.
  #
  # The promise in `Bloom001::build`'s doc comment, tested rather than asserted
  # in prose: passing more keys than `expected_items` "degrades the false
  # positive rate gracefully instead of catastrophically."
  #
  # Note what the implementation actually does. `build` takes
  # `expected_items.max(keys.len())`, so a filter cannot be overfilled through
  # the public constructor at all — asking for 1,000 and passing 10,000 sizes
  # for 10,000. The degradation is therefore in *memory used*, not in the rate:
  # the caller gets a correctly sized filter rather than a cramped one.
  #
  # An earlier version of this test asserted the rate would rise, and failed for
  # exactly that reason. The promise is real; the mechanism is not the one the
  # phrase "degrades gracefully" suggests.
  for_each_filter "honors its request when expected_items understates the input" do |spec|
    keys = Generators.random_keys(10_000, 30_030_040)
    probes = Tiers.statistical_probes
    oracle = Oracle.new(keys)

    understated = build(spec, keys, expected_items: 10, false_positive_rate: 0.01)
    accurate = build(spec, keys, expected_items: keys.length, false_positive_rate: 0.01)

    assert_no_false_negatives(understated, oracle, context: "sized for 10, given 10000")

    # The sizing hint is a floor, not a cap: understating it must not produce a
    # smaller filter, or the rate would collapse silently.
    assert_equal accurate.memory_bytes, understated.memory_bytes,
                 "#{spec.id} built a different filter when the sizing hint understated the " \
                 "input; `expected_items.max(keys.len())` should make the two identical"

    claimed = understated.false_positive_rate
    probe_keys = Generators.disjoint_probe_keys(keys, probes, 30_030_040)
    report = oracle.audit(understated, probe_keys)
    bound = Tolerance.binomial_bounds(probes, claimed)

    assert_includes bound, report.false_positives,
                    Tolerance.explain(
                      observed: report.false_positives,
                      expected: probes * claimed,
                      bound: bound,
                      trials: probes,
                      seed: 30_030_040,
                      label: "#{spec.id} with an understated sizing hint " \
                             "(claims #{claimed.round(6)})"
                    )
  end

  # The genuinely overfilled case, reached by decoding rather than building.
  #
  # A filter that really does hold more keys than its bit array was sized for
  # has to report the higher rate. That state is not reachable through `build`,
  # but it is reachable through a union — which is exactly how a sharded
  # deployment gets there.
  for_each_filter_with "reports a higher rate once genuinely overfilled",
                       :supports_union? do |spec|
    params = { expected_items: 2_000, false_positive_rate: 0.01, seed: 30_030_041 }

    left_keys = Generators.random_keys(2_000, 30_030_041)
    right_keys = Generators.random_keys(2_000, 30_030_042)
    all_keys = left_keys + right_keys

    left = build(spec, left_keys, **params)
    both = left.union(build(spec, right_keys, **params))

    # Same bits, twice the keys, so the rate must rise.
    assert_equal left.memory_bytes, both.memory_bytes
    assert_operator both.false_positive_rate, :>, left.false_positive_rate,
                    "#{spec.id} claims the same rate holding twice the keys in the same bits"

    assert_no_false_negatives(both, Oracle.new(all_keys), context: "after a union")

    probes = Tiers.statistical_probes
    probe_keys = Generators.disjoint_probe_keys(all_keys, probes, 30_030_042)
    report = Oracle.new(all_keys).audit(both, probe_keys)
    claimed = both.false_positive_rate
    bound = Tolerance.binomial_bounds(probes, claimed)

    assert_includes bound, report.false_positives,
                    Tolerance.explain(
                      observed: report.false_positives,
                      expected: probes * claimed,
                      bound: bound,
                      trials: probes,
                      seed: 30_030_042,
                      label: "#{spec.id} genuinely overfilled (claims #{claimed.round(6)})"
                    )
  end

  # 030.040.010 and .020 — bits per item against the family's published bound.
  #
  # Not correctness exactly, but a regression here means the filter is not the
  # algorithm it claims to be. The information-theoretic lower bound for rate ε
  # is log2(1/ε) bits per item; each family's overhead above that is published.
  for_each_filter "stays within its family's published space overhead" do |spec|
    overhead = spec.published_overhead

    if overhead.nil?
      skip "no published space bound recorded for family #{spec.family}; " \
           "add one to FilterSpec#published_overhead"
    end

    keys = Generators.random_keys(10_000, 30_040_010)

    [0.1, 0.01, 0.001].each do |target|
      handle = build(spec, keys, expected_items: keys.length, false_positive_rate: target)
      claimed = handle.false_positive_rate

      bits_per_item = handle.memory_bytes * 8.0 / handle.len
      optimal = Math.log2(1.0 / claimed)

      # Slack above the published figure, since the published number is an
      # asymptotic and a real filter rounds up to whole words. A further
      # relative epsilon absorbs float round-trip noise: a filter landing
      # exactly on the nominal ceiling (e.g. a binary fuse filter at a
      # segment count that gives precisely 1.25x overhead) must not fail
      # only because `optimal * (1 + overhead + 0.15)` and the measured
      # `bits_per_item` round to adjacent floats.
      ceiling = optimal * (1 + overhead + 0.15) * (1 + 1e-9)

      assert_operator bits_per_item, :<=, ceiling,
                      "#{spec.id} uses #{bits_per_item.round(2)} bits/item at an achieved " \
                      "rate of #{claimed.round(6)}, where the information-theoretic bound " \
                      "is #{optimal.round(2)} and family #{spec.family} publishes " \
                      "#{(overhead * 100).round}% overhead (ceiling #{ceiling.round(2)})"

      handle.release
    end
  end

  # 030.050.020 — bit occupancy near the theoretical optimum.
  #
  # At optimal sizing roughly half the bits should be set. A filter at 5% or 95%
  # occupancy is mis-sized regardless of what its rate measurement says.
  #
  # Measured through the encoded form, since that is what is observable from
  # outside the process.
  for_each_filter_with "sets about half its bits at design capacity",
                       :honors_target_fpr? do |spec|
    skip "occupancy is only meaningful for a bit-array filter" unless spec.family == "bloom"

    keys = Generators.random_keys(10_000, 30_050_020)
    handle = build(spec, keys, expected_items: keys.length, false_positive_rate: 0.01)

    encoded = handle.encode
    # Everything past the fixed header is the bit array.
    bit_array = encoded.byteslice(Encodings::HEADER_BYTES,
                                  encoded.bytesize - Encodings::HEADER_BYTES)

    set_bits = bit_array.each_byte.sum { |byte| byte.digits(2).sum }
    occupancy = set_bits.to_f / (bit_array.bytesize * 8)

    assert_operator occupancy, :>=, 0.4,
                    "#{spec.id} set only #{(occupancy * 100).round(1)}% of its bits at design " \
                    "capacity, which suggests it is sized far larger than needed"
    assert_operator occupancy, :<=, 0.6,
                    "#{spec.id} set #{(occupancy * 100).round(1)}% of its bits at design " \
                    "capacity, which suggests it is undersized"
  end

  # 030.050.010 — no key has a far-above-average false positive rate.
  #
  # `RESEARCH/02-bloom-variants/almeida-2022-case-for-partitioned-bloom-filters.pdf`
  # argues standard Bloom filters have "weak spots" — elements whose individual
  # rate is far above the average — and that naive double hashing makes this
  # worse. `bloom_001` uses Kirsch-Mitzenmacher double hashing, so it is exactly
  # the construction that paper criticizes.
  #
  # No reference suite checks this. Measuring each candidate key's rate across
  # many independently seeded filters over the same member set is what turns the
  # paper's claim into a number for this implementation.
  for_each_filter "has no key with a far-above-average false positive rate" do |spec|
    members = Generators.random_keys(2_000, 30_050_010)
    candidates = Generators.disjoint_probe_keys(members, 400, 30_050_010)

    # 200 seeds was calibrated against Bloom's ~1% nominal rate, where a
    # candidate accumulates ~2 hits on average and the max over 400
    # candidates is a reasonably tight statistic. xor and fuse run at a
    # fixed ~0.4% rate (1/256): at 200 seeds a candidate averages under one
    # hit, so the max-of-400 order statistic swings past 4x the mean from
    # pure sampling noise alone — confirmed by re-running at 2,000 seeds,
    # where the same filters settle to a worst/mean ratio around 2.5-2.7x.
    # Scaling seeds to keep the expected hit count roughly constant across
    # families keeps the statistical power — and therefore the 4x
    # threshold's validity — comparable regardless of the filter's nominal
    # rate.
    target_rate = spec.honors_target_fpr? ? 0.01 : 1.0 / 256.0
    seeds = [(200 * 0.01 / target_rate).round, 200].max

    # For each candidate, how many of the independently seeded filters call it
    # a member.
    hits = Array.new(candidates.length, 0)

    seeds.times do |seed|
      handle = build(spec, members, expected_items: members.length,
                                    false_positive_rate: 0.01, seed: seed)
      handle.contains_all(candidates).each_with_index do |answer, i|
        hits[i] += 1 if answer
      end
      handle.release
    end

    rates = hits.map { |count| count.to_f / seeds }
    mean = rates.sum / rates.length
    worst = rates.max

    skip "no false positives observed across #{seeds} seeds; raise the rate or the seed count" \
      if mean.zero?

    # A factor of four above the mean. The paper's concern is keys whose
    # individual rate is far above average; four times is well past sampling
    # noise at this seed count while still catching a genuine weak spot.
    ceiling = mean * 4

    assert_operator worst, :<=, ceiling,
                    "#{spec.id}: the worst key was a false positive in #{(worst * 100).round(1)}% " \
                    "of #{seeds} independently seeded filters, against a mean of " \
                    "#{(mean * 100).round(1)}%. That is the weak-spot behavior " \
                    "almeida-2022 attributes to double hashing; see plan step 030.050.010."
  end

  # 030.050.040 — different seeds give independent-looking filters.
  #
  # For a fixed non-member key, the fraction of seeds under which it is a false
  # positive should be close to the filter's rate. Catches a seed that fails to
  # propagate into the hash, which would leave every filter in a supposedly
  # randomized deployment identically vulnerable.
  for_each_filter "randomizes across seeds" do |spec|
    members = Generators.random_keys(2_000, 30_050_040)
    candidates = Generators.disjoint_probe_keys(members, 2_000, 30_050_040)
    seeds = 50

    per_seed_rates = seeds.times.map do |seed|
      handle = build(spec, members, expected_items: members.length,
                                    false_positive_rate: 0.05, seed: seed)
      rate = handle.contains_all(candidates).count(true).to_f / candidates.length
      handle.release
      rate
    end

    # Every seed should land near the same rate. A seed that does not reach the
    # hash would produce an identical filter each time, which shows up as zero
    # variance across seeds — so check the filters actually differ.
    distinct = per_seed_rates.uniq.length

    assert_operator distinct, :>, 1,
                    "#{spec.id} produced the same false positive rate under all #{seeds} " \
                    "seeds, which suggests the seed does not reach the hash"

    mean = per_seed_rates.sum / per_seed_rates.length
    bound = Tolerance.binomial_bounds(candidates.length, mean)

    outliers = per_seed_rates.each_with_index.reject do |rate, _|
      bound.include?((rate * candidates.length).round)
    end

    # At three sigma and fifty seeds, roughly one outlier is expected by chance.
    assert_operator outliers.length, :<=, 3,
                    "#{spec.id}: #{outliers.length} of #{seeds} seeds produced a rate outside " \
                    "the three-sigma band around the mean of #{mean.round(5)}: " \
                    "#{outliers.map { |r, i| "seed #{i} => #{r.round(5)}" }.inspect}"
  end

  private

  # Builds a probe set with a known fraction of genuine members.
  #
  # After `DuplicateFreeMixIn` from
  # `external/fastfilter_cpp/benchmarks/random.h`, with one deliberate
  # difference: where the requested member count exceeds the member set, members
  # are cycled rather than the request being silently clamped.
  #
  # Clamping is what this method did first, and it produced a 5% mix when asked
  # for 25% — which the sweep then measured faithfully and reported as a filter
  # defect. That is exactly the failure plan step 010.030.050 exists to prevent:
  # "a test harness that silently produces a 0.6 mix when asked for 0.5 will
  # report false positive rates that are wrong in a direction nobody notices."
  #
  # Repeated members are harmless here. The sweep counts positives against the
  # oracle's classification of each probe, and a member probed twice is a member
  # both times.
  #
  # @return [Array<String>]
  def build_mix(members, non_members, member_count, total, seed:)
    non_member_count = total - member_count

    raise "not enough non-members: need #{non_member_count}, have #{non_members.length}" \
      if non_member_count > non_members.length

    # Cycle rather than clamp, so the realized ratio is the requested one.
    chosen_members = Array.new(member_count) { |i| members[i % members.length] }
    mixed = (chosen_members + non_members.first(non_member_count))
            .shuffle(random: Random.new(seed))

    # 010.030.050 — verify the mixer hit its target before trusting anything
    # measured through it. Counted against an oracle over the member set rather
    # than against the arithmetic above, so a bug in the construction shows up
    # here instead of surfacing later as a filter defect.
    #
    # The reference harness checks its own mixer and aborts if the realized
    # found-probability is off by more than 0.01. This is that check.
    truth = Oracle.new(members)
    realized = mixed.count { |key| truth.contains?(key) }.to_f / mixed.length
    requested = member_count.to_f / total

    assert_equal total, mixed.length, "the probe mixer produced the wrong probe count"
    assert_in_delta requested, realized, 0.01,
                    "the probe mixer produced a #{realized.round(4)} member fraction when " \
                    "asked for #{requested.round(4)}; every rate measured through it would " \
                    "be wrong in a direction nobody notices"

    mixed
  end
end
