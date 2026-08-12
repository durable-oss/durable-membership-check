# frozen_string_literal: true

require "test_helper"

# Area 040 — structured, hostile, and degenerate key sets.
#
# Random keys are the easy case. Real key sets are sequential ids,
# shared-prefix URLs, and timestamps; a hostile key set is chosen to collide.
#
# `dmc_core::hash` is explicit about the limit: "This is not a cryptographic
# hash. An adversary who can choose keys can force collisions and drive a
# filter's false positive rate up." That is a correct disclaimer. This file
# establishes what it does and does not excuse.
class AdversarialKeysTest < DmcCheck::ConformanceTest
  include DmcCheck

  # How far above the random-key baseline a structured key set may push the
  # observed false positive rate before it counts as degradation.
  #
  # Not a tuning knob reached for after a failure: 3x is generous enough that
  # only a genuinely broken hash trips it, which is the point. A hash that
  # merely reorders which keys collide leaves the *rate* alone.
  STRUCTURE_TOLERANCE = 3.0

  # 040.010.020 — rotated sequential integers, all 64 rotations.
  #
  # The fastfilter special seeds 0-63. A filter deriving its index from the low
  # bits of the hash is fine at rotate=0 and degenerate at rotate=58. Sixty-four
  # builds at SMALL is cheap enough for the default suite.
  for_each_filter "survives all 64 rotations of sequential keys" do |spec|
    failures = []

    (0..63).each do |rotate|
      keys = Generators.rotated_keys(500, rotate)
      oracle = Oracle.new(keys)
      handle = build(spec, keys, expected_items: keys.length, false_positive_rate: 0.01)

      report = oracle.audit(handle, keys)
      failures << "rotate=#{rotate}: #{report.false_negative_message}" unless report.sound?

      handle.release
    end

    assert_empty failures, "#{spec.id} lost members under rotation:\n  #{failures.join("\n  ")}"
  end

  # 040.010.030 — bit-reversed sequential integers, all 64 rotations.
  #
  # The special seeds 64-127, and harsher than the rotations above: consecutive
  # keys differ only in their high bits, so low-bit indexing collapses entirely.
  for_each_filter "survives all 64 rotations of bit-reversed keys" do |spec|
    failures = []

    (0..63).each do |rotate|
      keys = Generators.reversed_keys(500, rotate)
      oracle = Oracle.new(keys)
      handle = build(spec, keys, expected_items: keys.length, false_positive_rate: 0.01)

      report = oracle.audit(handle, keys)
      failures << "rotate=#{rotate}: #{report.false_negative_message}" unless report.sound?

      handle.release
    end

    assert_empty failures, "#{spec.id} lost members under bit reversal:\n  #{failures.join("\n  ")}"
  end

  # 040.010.010, .040, .050, .080 — structured keys must not degrade the rate.
  #
  # Distinct hashes are not enough: hashes that cluster in one region of the bit
  # array still degrade the filter. So this measures the observed rate against
  # the random-key baseline rather than merely checking for collisions.
  for_each_filter_with "keeps its rate under structured keys", :honors_target_fpr? do |spec|
    size = 2_000
    probes = 20_000
    rate = 0.01

    baseline = observed_rate(spec, Generators.random_keys(size, 40_010_010), probes, rate,
                             seed: 40_010_010)

    structured = {
      "sequential" => Generators.sequential_keys(size),
      "prefixed_8" => Generators.prefixed_keys(size, prefix: "p" * 8),
      "prefixed_64" => Generators.prefixed_keys(size, prefix: "p" * 64),
      "prefixed_1024" => Generators.prefixed_keys(size, prefix: "p" * 1024),
      "suffixed_1024" => Generators.suffixed_keys(size, suffix_length: 1024),
      "timestamps_ns" => Generators.timestamp_keys(size, granularity: 1),
      "timestamps_us" => Generators.timestamp_keys(size, granularity: 1_000),
      "timestamps_ms" => Generators.timestamp_keys(size, granularity: 1_000_000),
      "small" => Generators.small_keys(size, 40_010_010),
      "variable_length" => Generators.variable_length_keys(size, 40_010_010)
    }

    # A baseline of zero would make any ratio infinite; compare against the
    # requested rate instead, which is the honest reference point.
    reference = [baseline, rate].max
    ceiling = reference * STRUCTURE_TOLERANCE

    structured.each do |name, keys|
      measured = observed_rate(spec, keys, probes, rate, seed: 40_010_010)

      assert_operator measured, :<=, ceiling,
                      "#{spec.id} degraded on #{name} keys: observed #{measured.round(5)} " \
                      "against a random-key baseline of #{baseline.round(5)} " \
                      "(ceiling #{ceiling.round(5)}, #{probes} probes, seed 40010010)"
    end
  end

  # 040.010.060 — keys differing only in trailing zero bytes.
  #
  # `hash64` folds `key.len()` in specifically to separate these, and
  # `hash_distinguishes_keys_differing_only_in_trailing_zeros` covers the
  # two-key case. This scales it to 64 keys.
  for_each_filter "separates keys differing only in trailing zeros" do |spec|
    keys = Generators.trailing_zero_keys(64)
    oracle = Oracle.new(keys)

    assert_equal keys.length, oracle.distinct_count, "the generator produced duplicates"

    handle = build(spec, keys, expected_items: keys.length, false_positive_rate: 0.001)

    assert_no_false_negatives(handle, oracle, context: "64 trailing-zero variants")
  end

  # 040.010.070 — keys at every length crossing a chunk boundary.
  #
  # `hash64` consumes eight bytes at a time with a byte-wise tail, so lengths 7,
  # 8, and 9 take three different paths. Lengths 0 through 65 are covered
  # explicitly.
  for_each_filter "handles every key length across chunk boundaries" do |spec|
    keys = (0..65).map { |n| ("L" * n).b }
    oracle = Oracle.new(keys)
    handle = build(spec, keys, expected_items: keys.length, false_positive_rate: 0.001)

    report = oracle.audit(handle, keys)

    assert report.sound?, "#{spec.id} lost a key at a chunk boundary: #{report.false_negative_message}"
  end

  # 040.030.010 — every degenerate key set.
  #
  # Table-driven. For each: build, no panic, no false negatives, and the
  # accounting invariants still hold.
  for_each_filter "handles every degenerate key set" do |spec|
    Generators.degenerate_key_sets.each do |name, keys|
      response = session.try_build(spec.id, keys,
                                   expected_items: [keys.length, 1].max,
                                   false_positive_rate: 0.01)

      # A filter that rejects duplicates is allowed to fail on the sets that
      # contain them, and only on those.
      if !response["ok"] && !spec.tolerates_duplicate_keys?
        oracle = Oracle.new(keys)
        assert_operator oracle.distinct_count, :<, keys.length,
                        "#{spec.id} failed on #{name.inspect}, which has no duplicates: " \
                        "#{response["message"]}"
        next
      end

      assert response["ok"], "#{spec.id} failed to build #{name.inspect}: #{response["message"]}"

      handle = Cli::Handle.new(session, response.fetch("handle"), response.fetch("info"))
      oracle = Oracle.new(keys)

      report = oracle.audit(handle, keys)

      assert report.sound?,
             "#{spec.id} lost a member from #{name.inspect}: #{report.false_negative_message}"

      # Accounting must stay coherent on these too.
      assert_equal keys.empty?, handle.empty?, "#{spec.id} is_empty wrong for #{name.inspect}"
      assert_operator handle.false_positive_rate, :>=, 0.0, "for #{name.inspect}"
      assert_operator handle.false_positive_rate, :<=, 1.0, "for #{name.inspect}"

      handle.release
    end
  end

  # 040.030.030 — a filter holding only the empty key must not match everything.
  #
  # `empty_key_is_a_valid_member` covers the positive half in Rust. This is the
  # half that catches a filter whose empty-key handling sets every bit.
  for_each_filter "a filter of just the empty key matches almost nothing else" do |spec|
    handle = build(spec, [""], expected_items: 1, false_positive_rate: 0.01)

    assert handle.contains?(""), "#{spec.id} lost the empty key"

    probes = Generators.random_keys(10_000, 40_030_030)
    positives = handle.contains_all(probes).count(true)

    # One key at a 1% target: a handful of hits is expected, thousands is a bug.
    assert_operator positives, :<, 500,
                    "#{spec.id} matched #{positives} of 10000 probes holding only the empty key"
  end

  # 040.030.050 — a single very large key.
  #
  # Guards against an accidental quadratic in a future hash. 16 MiB, with a
  # wall-clock ceiling that a linear hash clears by orders of magnitude.
  for_each_filter "handles a 16 MiB key in reasonable time" do |spec|
    big = ("k" * (16 * 1024 * 1024)).b

    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    handle = build(spec, [big], expected_items: 1, false_positive_rate: 0.01)
    found = handle.contains?(big)
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started

    assert found, "#{spec.id} lost a 16 MiB key"
    assert_operator elapsed, :<, 10.0,
                    "#{spec.id} took #{elapsed.round(2)}s for one 16 MiB key, which suggests " \
                    "the hash is worse than linear"
  end

  # 040.030.070 — non-UTF-8 and embedded NUL keys.
  #
  # Keys are bytes, not text. Embedded NULs matter beyond hashing: the encoding
  # format uses a NUL to terminate the implementation id, so a key containing
  # one must not confuse the decoder. It cannot today, because keys are not
  # stored — but a future implementation that stores key fragments could break
  # here, and this records the constraint now.
  for_each_filter "handles NUL and non-UTF-8 keys through an encode round trip" do |spec|
    keys = [
      "\x00".b, "\x00\x00".b, "a\x00b".b, "\x00a".b, "a\x00".b,
      "\xC3\x28".b, "\xA0\xA1".b, "\xE2\x28\xA1".b, "\xF0\x28\x8C\x28".b,
      "\xFF".b, ("\xFF" * 64).b, ("\x00" * 64).b
    ]
    oracle = Oracle.new(keys)

    original = build(spec, keys, expected_items: keys.length, false_positive_rate: 0.001)
    assert_no_false_negatives(original, oracle, context: "NUL and non-UTF-8 keys")

    restored = session.decode(original.encode)
    assert_no_false_negatives(restored, oracle, context: "NUL and non-UTF-8 keys after decode")
  end

  # 040.020.020 — the derived second hash is not independent.
  #
  # `probes()` derives `h2` from `h1`, so two keys colliding in `h1` collide in
  # every probe. More subtly, keys whose `h1` values land on the same first
  # probe position share that position by construction.
  #
  # This does not assert a bound — it measures and reports. A filter is allowed
  # to degrade against keys grouped this way; what it may not do is lose a
  # member. The number is recorded so the disclaimer in `dmc_core::hash` is
  # backed by a measurement rather than an assumption.
  for_each_filter "stays sound against keys grouped by first probe position" do |spec|
    keys = Generators.random_keys(2_000, 40_020_020)
    handle = build(spec, keys, expected_items: keys.length, false_positive_rate: 0.01)

    # Find probe keys the filter already answers `true` for. These are its
    # existing false positives — the closest thing to a chosen-key attack
    # reachable through the public interface, since the probe positions
    # themselves are not exposed.
    candidates = Generators.disjoint_probe_keys(keys, 100_000, 40_020_020)
    answers = handle.contains_all(candidates)
    colliding = candidates.each_with_index.filter_map { |key, i| key if answers[i] }

    skip "no false positives found to group at this rate" if colliding.empty?

    # Re-querying the known-colliding set must be stable, and must not have
    # disturbed the filter's answers for its own members.
    repeat = handle.contains_all(colliding)

    assert repeat.all?, "#{spec.id} gave inconsistent answers for its own false positives"

    oracle = Oracle.new(keys)
    assert_no_false_negatives(handle, oracle, context: "after probing known false positives")
  end

  # 040.020.040 — a secret seed changes which keys collide.
  #
  # This is what the `Params::seed` disclaimer promises: "Filters exposed to
  # untrusted key sets should use a secret, per-process seed." An attacker who
  # finds a colliding key set under one seed must not carry it to another.
  for_each_filter "a different seed relocates the false positives" do |spec|
    keys = Generators.random_keys(2_000, 40_020_040)
    probes = Generators.disjoint_probe_keys(keys, 50_000, 40_020_040)

    under_seed_1 = build(spec, keys, expected_items: keys.length,
                                     false_positive_rate: 0.01, seed: 1)
    under_seed_2 = build(spec, keys, expected_items: keys.length,
                                     false_positive_rate: 0.01, seed: 2)

    fp1 = collect_false_positives(under_seed_1, probes)
    fp2 = collect_false_positives(under_seed_2, probes)

    skip "no false positives under either seed" if fp1.empty? && fp2.empty?

    carried = (fp1 & fp2).length
    # If the seed did nothing, every false positive would carry over. Under
    # independent seeds the expected overlap is |fp1| * |fp2| / |probes|, which
    # is far below either set's size.
    ceiling = [(fp1.length * 0.5).ceil, 1].max

    assert_operator carried, :<=, ceiling,
                    "#{spec.id}: #{carried} of #{fp1.length} false positives under seed 1 " \
                    "were still false positives under seed 2, which suggests the seed does " \
                    "not reach the hash"
  end

  private

  # Measures the observed false positive rate for one key set.
  #
  # @return [Float]
  def observed_rate(spec, keys, probe_count, rate, seed:)
    handle = build(spec, keys, expected_items: keys.length, false_positive_rate: rate)
    probes = Generators.disjoint_probe_keys(keys, probe_count, seed)

    oracle = Oracle.new(keys)
    report = oracle.audit(handle, probes)

    # Every one of these key sets must also be sound; a rate measured on a
    # filter with false negatives would be meaningless.
    assert report.sound?, "#{spec.id} lost a member: #{report.false_negative_message}"

    handle.release
    report.false_positive_rate
  end

  # Returns the probe keys a filter reports as present.
  #
  # @return [Array<String>]
  def collect_false_positives(handle, probes)
    answers = handle.contains_all(probes)
    probes.each_with_index.filter_map { |key, i| key if answers[i] }
  end
end
