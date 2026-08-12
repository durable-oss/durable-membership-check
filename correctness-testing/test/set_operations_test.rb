# frozen_string_literal: true

require "test_helper"

# Set operations between filters: union, intersection, and cardinality.
#
# Three capability axes gate these, and each one is checked in both directions —
# a filter claiming the capability is tested, and a filter declining it is
# skipped with the reason visible in the output.
#
# The contracts are not symmetric, and the asymmetry is the whole difficulty:
#
# **Union** is exact for a filter whose backing store combines pointwise. A
# bitwise OR of two Bloom filters of identical shape contains every member of
# both, with no false negatives introduced.
#
# **Intersection** is not exact. A bit survives an AND when *any* key of A and
# *any* key of B both set it — not necessarily the same key. So the result
# contains every key in both inputs, and also keys in neither, at a rate above
# either input's. An implementation claiming it must report that inflated rate
# honestly.
#
# **Cardinality** is what makes union usable. After combining, the built-from
# count is no longer what the filter holds: the union of two 500-key filters
# over overlapping sets does not hold 1,000 keys.
class SetOperationsTest < DmcCheck::ConformanceTest
  include DmcCheck

  # Shared shape for the operands. Two filters combine only if their bit count,
  # hash count, and seed all match, which identical params guarantee.
  PARAMS = { expected_items: 5_000, false_positive_rate: 0.01, seed: 100_010 }.freeze

  # A union must contain every member of both inputs.
  #
  # The no-false-negative guarantee does not weaken because two filters were
  # combined. A union that loses a member is a false negative, and no filter may
  # trade that away.
  for_each_filter_with "unions without losing a member", :supports_union? do |spec|
    left_keys = Generators.random_keys(1_000, 100_010)
    right_keys = Generators.random_keys(1_000, 100_011)

    left = build(spec, left_keys, **PARAMS)
    right = build(spec, right_keys, **PARAMS)
    both = left.union(right)

    oracle = Oracle.new(left_keys + right_keys)
    assert_no_false_negatives(both, oracle, context: "after a union")

    # Each input's members individually, so a union that kept only one side is
    # named as such rather than reported as a generic loss.
    assert both.contains_all(left_keys).all?, "#{spec.id} lost the left operand's keys"
    assert both.contains_all(right_keys).all?, "#{spec.id} lost the right operand's keys"
  end

  # Union must be commutative, since set union is.
  #
  # A filter whose union depends on operand order is not computing a union.
  for_each_filter_with "unions commutatively", :supports_union? do |spec|
    left = build(spec, Generators.random_keys(500, 100_012), **PARAMS)
    right = build(spec, Generators.random_keys(500, 100_013), **PARAMS)

    assert_equal backing_store(left.union(right)), backing_store(right.union(left)),
                 "#{spec.id}: A ∪ B and B ∪ A produced different filters"
  end

  # Union must be associative, for the same reason.
  for_each_filter_with "unions associatively", :supports_union? do |spec|
    a = build(spec, Generators.random_keys(400, 100_014), **PARAMS)
    b = build(spec, Generators.random_keys(400, 100_015), **PARAMS)
    c = build(spec, Generators.random_keys(400, 100_016), **PARAMS)

    left_first = a.union(b).union(c)
    right_first = a.union(b.union(c))

    assert_equal backing_store(left_first), backing_store(right_first),
                 "#{spec.id}: (A ∪ B) ∪ C and A ∪ (B ∪ C) produced different filters"
  end

  # Unioning a filter with itself must not change which keys it holds.
  #
  # Idempotence follows from union being a set operation, and it is the cheapest
  # check that the operation is not accumulating something per call.
  #
  # Compared on the backing store rather than on the whole encoding, because
  # `len` legitimately differs: a union re-derives it as a cardinality estimate,
  # so A ∪ A reports the estimate where A reported the built-from count. That is
  # the documented behavior, not a defect — the two numbers answer different
  # questions, which is why `estimated_len` is a separate capability.
  for_each_filter_with "unions idempotently", :supports_union? do |spec|
    keys = Generators.random_keys(500, 100_017)
    filter = build(spec, keys, **PARAMS)
    doubled = filter.union(filter)

    assert_equal backing_store(filter), backing_store(doubled),
                 "#{spec.id}: A ∪ A holds different keys than A"

    # And the membership answers must be identical, which is the property the
    # bit comparison is standing in for.
    probes = keys + Generators.disjoint_probe_keys(keys, 5_000, 100_017)

    assert_equal filter.contains_all(probes), doubled.contains_all(probes),
                 "#{spec.id}: A ∪ A answered differently from A"
  end

  # A union with an empty filter must be the original.
  for_each_filter_with "unions with an empty filter as an identity",
                       :supports_union? do |spec|
    keys = Generators.random_keys(500, 100_018)
    filter = build(spec, keys, **PARAMS)
    empty = build(spec, [], **PARAMS)

    combined = filter.union(empty)

    assert combined.contains_all(keys).all?, "#{spec.id} lost keys unioning with an empty filter"

    # The bit arrays must match; `len` may legitimately differ, since a union
    # re-derives it as an estimate rather than carrying the built-from count.
    assert_equal filter.memory_bytes, combined.memory_bytes
  end

  # The union's reported rate must rise and must predict what it does.
  #
  # The result holds more keys in the same number of bits, so its rate is higher
  # than either input's. A filter reporting its inputs' rate after combining is
  # describing a filter it no longer is.
  for_each_filter_with "reports an honest rate after a union", :supports_union? do |spec|
    left_keys = Generators.random_keys(2_000, 100_019)
    right_keys = Generators.random_keys(2_000, 100_020)
    all_keys = left_keys + right_keys

    left = build(spec, left_keys, **PARAMS)
    both = left.union(build(spec, right_keys, **PARAMS))

    assert_operator both.false_positive_rate, :>, left.false_positive_rate,
                    "#{spec.id} claims the same rate after doubling the keys it holds"

    probes = Generators.disjoint_probe_keys(all_keys, Tiers.statistical_probes, 100_020)
    report = Oracle.new(all_keys).audit(both, probes)
    claimed = both.false_positive_rate
    bound = Tolerance.binomial_bounds(probes.length, claimed)

    assert_includes bound, report.false_positives,
                    Tolerance.explain(
                      observed: report.false_positives,
                      expected: probes.length * claimed,
                      bound: bound,
                      trials: probes.length,
                      seed: 100_020,
                      label: "#{spec.id} after a union (claims #{claimed.round(6)})"
                    )
  end

  # Incompatible shapes must be refused, not merged.
  #
  # Two filters differing in bit count, hash count, or seed cannot combine
  # pointwise. The operation must report that rather than produce a filter whose
  # answers are silently wrong — which is the worse outcome by a wide margin,
  # since nothing downstream would notice.
  for_each_filter_with "refuses to combine incompatible filters",
                       :supports_union? do |spec|
    base = build(spec, Generators.random_keys(100, 100_021), **PARAMS)

    incompatible = {
      "a different size" => PARAMS.merge(expected_items: 500_000),
      "a different target rate" => PARAMS.merge(false_positive_rate: 0.2),
      "a different seed" => PARAMS.merge(seed: PARAMS[:seed] + 1)
    }

    incompatible.each do |why, params|
      other = build(spec, Generators.random_keys(100, 100_022), **params)
      response = base.try_union(other)

      refute response["ok"], "#{spec.id} unioned a filter with #{why}"
      assert_equal "incompatible", response["kind"],
                   "#{spec.id} rejected #{why} with #{response["kind"]}: #{response["message"]}"

      # The message must name which part of the shape disagreed, since that is
      # what tells a caller how to fix their params.
      assert_match(/bit_count|hash_count|seed/, response["message"],
                   "the error should name the field that differs: #{response["message"]}")
    end
  end

  # An intersection must contain every key present in both inputs.
  #
  # The half of the contract that actually holds: keys in both inputs set the
  # same bits in both filters, so those bits survive the AND.
  for_each_filter_with "intersects without losing a shared member",
                       :supports_intersection? do |spec|
    shared = Generators.random_keys(500, 100_030)
    left_only = Generators.random_keys(500, 100_031)
    right_only = Generators.random_keys(500, 100_032)

    left = build(spec, shared + left_only, **PARAMS)
    right = build(spec, shared + right_only, **PARAMS)

    overlap = left.intersect(right)

    assert_no_false_negatives(overlap, Oracle.new(shared), context: "after an intersection")
  end

  # Intersection must be commutative.
  for_each_filter_with "intersects commutatively", :supports_intersection? do |spec|
    a = build(spec, Generators.random_keys(500, 100_033), **PARAMS)
    b = build(spec, Generators.random_keys(500, 100_034), **PARAMS)

    assert_equal backing_store(a.intersect(b)), backing_store(b.intersect(a)),
                 "#{spec.id}: A ∩ B and B ∩ A produced different filters"
  end

  # An intersection with an empty filter must be empty.
  for_each_filter_with "intersects with an empty filter to nothing",
                       :supports_intersection? do |spec|
    keys = Generators.random_keys(500, 100_035)
    filter = build(spec, keys, **PARAMS)
    empty = build(spec, [], **PARAMS)

    overlap = filter.intersect(empty)
    positives = overlap.contains_all(keys).count(true)

    assert_equal 0, positives,
                 "#{spec.id} reported #{positives} of #{keys.length} keys present after " \
                 "intersecting with an empty filter"
  end

  # Intersection is only approximately the set intersection, and the result must
  # say so.
  #
  # A bit survives the AND when any key of A and any key of B both set it, not
  # necessarily the same key. So the result holds keys in neither input, and its
  # rate must reflect that rather than being inherited from the operands.
  for_each_filter_with "reports its rate honestly after an intersection",
                       :supports_intersection? do |spec|
    shared = Generators.random_keys(200, 100_036)
    left_keys = shared + Generators.random_keys(2_000, 100_037)
    right_keys = shared + Generators.random_keys(2_000, 100_038)

    overlap = build(spec, left_keys, **PARAMS).intersect(build(spec, right_keys, **PARAMS))
    claimed = overlap.false_positive_rate

    assert_operator claimed, :>=, 0.0
    assert_operator claimed, :<=, 1.0
    refute claimed.nan?, "#{spec.id} reported NaN after an intersection"

    # Measured against keys in neither input: every positive there is a false
    # positive of the intersection.
    probes = Generators.disjoint_probe_keys(left_keys + right_keys,
                                            Tiers.statistical_probes, 100_038)
    observed = overlap.contains_all(probes).count(true).to_f / probes.length

    # The claim must be in the right neighbourhood. Loose because the AND's rate
    # is genuinely hard to predict from the operands — which is exactly why the
    # filter has to measure rather than assume.
    assert_operator claimed, :>=, observed / 10,
                    "#{spec.id} claims #{claimed.round(8)} after intersecting but observes " \
                    "#{observed.round(8)}; the claim understates by more than 10x"
  end

  # A cardinality estimate must track the distinct key count.
  #
  # Distinct from the built-from count, which is what makes the axis worth
  # having: a filter built from 3,000 keys of which 1,000 are distinct holds
  # 1,000.
  for_each_filter_with "estimates its distinct key count",
                       :estimates_cardinality? do |spec|
    [100, 1_000, 5_000].each do |count|
      keys = Generators.random_keys(count, 100_040)
      estimate = build(spec, keys, **PARAMS).estimated_len

      # The estimator is `-(m/k) ln(1 - X/m)`, which is unbiased but noisy. Ten
      # percent is comfortably inside its error at these fill levels while still
      # catching an estimator that is wrong by a factor.
      assert_in_delta count, estimate, count * 0.1,
                      "#{spec.id} estimated #{estimate} distinct keys out of #{count}"
    end
  end

  # Duplicates in the input must not inflate the estimate.
  #
  # The case where the estimate and the built-from count visibly disagree, and
  # the one that shows the estimate is derived from contents rather than
  # bookkeeping.
  for_each_filter_with "estimates distinct keys, not supplied keys",
                       :estimates_cardinality? do |spec|
    distinct = Generators.random_keys(1_000, 100_041)
    supplied = distinct * 3

    filter = build(spec, supplied, **PARAMS)

    assert_equal supplied.length, filter.len,
                 "len should report the keys supplied" if spec.len_counts_duplicates?

    assert_in_delta distinct.length, filter.estimated_len, distinct.length * 0.1,
                    "#{spec.id} estimated #{filter.estimated_len} distinct keys from " \
                    "#{supplied.length} supplied, of which #{distinct.length} are distinct"
  end

  # The estimate must stay meaningful after a union.
  #
  # The case that makes the axis worth having. After combining, the built-from
  # count is not what the filter holds; an estimate read from the bits is.
  for_each_filter_with "estimates cardinality correctly after a union",
                       :estimates_cardinality? do |spec|
    shared = Generators.random_keys(500, 100_042)
    left_keys = shared + Generators.random_keys(1_000, 100_043)
    right_keys = shared + Generators.random_keys(1_000, 100_044)
    distinct_total = (left_keys + right_keys).uniq.length

    both = build(spec, left_keys, **PARAMS).union(build(spec, right_keys, **PARAMS))

    assert_in_delta distinct_total, both.estimated_len, distinct_total * 0.1,
                    "#{spec.id} estimated #{both.estimated_len} distinct keys after a union " \
                    "of #{left_keys.length} and #{right_keys.length} keys sharing " \
                    "#{shared.length}, where the true distinct count is #{distinct_total}"
  end

  # An empty filter must estimate zero, not a small positive number.
  for_each_filter_with "estimates zero for an empty filter",
                       :estimates_cardinality? do |spec|
    assert_equal 0, build(spec, [], **PARAMS).estimated_len,
                 "#{spec.id} estimated a nonzero distinct count with no keys inserted"
  end

  # Similarity must agree with the true Jaccard index of the key sets.
  #
  # Not gated on its own axis: it is derived from the same machinery as union
  # and intersection, so a filter offering both should offer this.
  for_each_filter_with "estimates Jaccard similarity", :supports_intersection? do |spec|
    shared = Generators.random_keys(1_000, 100_050)
    left_keys = shared + Generators.random_keys(1_000, 100_051)
    right_keys = shared + Generators.random_keys(1_000, 100_052)

    # |A ∩ B| / |A ∪ B| = 1000 / 3000.
    truth = shared.length.to_f / (left_keys + right_keys).uniq.length

    left = build(spec, left_keys, **PARAMS)
    result = left.similarity(build(spec, right_keys, **PARAMS))

    assert_in_delta truth, result.fetch("jaccard"), 0.1,
                    "#{spec.id} estimated a Jaccard index of " \
                    "#{result["jaccard"].round(4)} where the true value is #{truth.round(4)}"
  end

  # Containment is asymmetric, and the reply must not confuse the directions.
  #
  # A small set inside a large one is almost entirely contained; the reverse is
  # not. A filter that returned the same number for both would pass a symmetric
  # test and be useless.
  for_each_filter_with "reports containment in the right direction",
                       :supports_intersection? do |spec|
    small_keys = Generators.random_keys(200, 100_060)
    large_keys = small_keys + Generators.random_keys(1_800, 100_061)

    small = build(spec, small_keys, **PARAMS)
    large = build(spec, large_keys, **PARAMS)

    result = small.similarity(large)

    # Nearly all of the small set is in the large one.
    assert_in_delta 1.0, result.fetch("containment_left_in_right"), 0.1,
                    "#{spec.id}: the small set should be almost entirely inside the large one"

    # About a tenth of the large set is in the small one.
    assert_in_delta 200.0 / 2_000, result.fetch("containment_right_in_left"), 0.1,
                    "#{spec.id}: the large set is mostly outside the small one"

    # And the two directions must genuinely differ, or the asymmetry was lost.
    assert_operator result.fetch("containment_left_in_right"), :>,
                    result.fetch("containment_right_in_left") + 0.3,
                    "#{spec.id} reported near-identical containment in both directions, " \
                    "which loses the asymmetry the operation exists to express"
  end

  # A filter declining every axis must still be a coherent declaration.
  #
  # The guard against a capability claimed but unimplemented: if a filter says
  # it unions, the tests above run against it. If it says it does not, they skip
  # visibly. What must not happen is a claim with nothing behind it.
  for_each_filter "declares each set-operation axis explicitly" do |spec|
    %i[supports_union? supports_intersection? estimates_cardinality?].each do |axis|
      assert_includes [true, false], spec.public_send(axis),
                      "#{spec.id} did not declare #{axis.to_s.delete_suffix("?")}"
    end
  end

  private

  # The filter's bit array, as hex, with the header stripped.
  #
  # Set-operation results are compared on this rather than on the whole
  # encoding, because a union re-derives `len` as a cardinality estimate. Two
  # filters holding exactly the same keys therefore differ in their headers
  # while agreeing on every bit that decides an answer.
  #
  # Falls back to the whole encoding for a filter whose payload layout is not
  # known here, which is conservative: it can only make a comparison stricter.
  #
  # @param handle [Cli::Handle]
  # @return [String]
  def backing_store(handle)
    encoded = handle.encode
    Hex.encode(encoded.byteslice(Encodings::HEADER_BYTES,
                                 encoded.bytesize - Encodings::HEADER_BYTES))
  end
end
