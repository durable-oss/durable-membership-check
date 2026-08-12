# frozen_string_literal: true

module DmcCheck
  # Statistical bounds for false positive rate assertions.
  #
  # Filters are probabilistic. A test asserting an exact rate flakes; a test
  # with a tolerance pulled out of the air either flakes or catches nothing.
  # Both failure modes are visible in the reference suites:
  # `external/binfuse/test/filter.cpp` asserts `fpr <= 0.005` against a nominal
  # 0.0039, a 28% margin with no stated derivation, which passes a filter that
  # is meaningfully worse than advertised.
  #
  # The bounds here are derived from the trial count, so they tighten as the
  # test does more work rather than staying fixed.
  #
  # # Seed shopping is fabrication
  #
  # Choosing a seed because the test passes under it fabricates a result. The
  # rule: pick the seed first — a constant, or the plan step number — then set
  # the tolerance from the math. If a fixed-seed statistical test fails, the
  # fix is to investigate the filter, not to try seed 43.
  #
  # If a seed is genuinely a known-bad outlier, that gets its own test
  # recording why, not a silent swap.
  module Tolerance
    # Standard deviations for a one-sided bound.
    #
    # Matches `PoissonUpperBound(expected, 3.0)` at
    # `external/BuRR/tests.cpp:165`. Three sigma one-sided is roughly a 1-in-740
    # flake rate per assertion, which would be too many across a few dozen
    # assertions — except that every statistical test here is seeded and
    # deterministic, so an assertion either always passes or always fails and
    # the flake question becomes a question about seed selection.
    DEFAULT_STDDEVS = 3.0

    module_function

    # A one-sided upper bound on a Poisson count.
    #
    # Ported verbatim from `external/BuRR/test_helpers.hpp`, itself lifted from
    # RocksDB's `util/ribbon_test.cpp`:
    #
    #     expected_count + stddevs * sqrt(expected_count) + 1.0
    #
    # The trailing `+ 1.0` matters at small expected counts, where the Poisson
    # tail is fat.
    #
    # @param expected_count [Float]
    # @param stddevs [Float]
    # @return [Integer]
    def poisson_upper_bound(expected_count, stddevs = DEFAULT_STDDEVS)
      (expected_count + (stddevs * Math.sqrt(expected_count)) + 1.0).ceil
    end

    # A one-sided lower bound on a Poisson count.
    #
    # The mirror of {poisson_upper_bound}, floored at zero. Every reference
    # suite checks only that a rate is not too high; a rate far *below* target
    # is also a defect — most likely the filter is sized far larger than
    # requested, wasting memory.
    #
    # @param expected_count [Float]
    # @param stddevs [Float]
    # @return [Integer]
    def poisson_lower_bound(expected_count, stddevs = DEFAULT_STDDEVS)
      bound = expected_count - (stddevs * Math.sqrt(expected_count)) - 1.0
      bound.negative? ? 0 : bound.floor
    end

    # Whether the normal approximation to a binomial is usable.
    #
    # The usual rule of thumb: at least ten expected successes and ten expected
    # failures. Below that the approximation is poor and {binomial_bounds}
    # falls back to a wider, safer interval.
    #
    # @param trials [Integer]
    # @param probability [Float]
    # @return [Boolean]
    def normal_approximation_valid?(trials, probability)
      trials * probability >= 10 && trials * (1 - probability) >= 10
    end

    # A two-sided bound on a binomial count.
    #
    # Needed where the Poisson approximation is poor — that is, where `p` is not
    # small, which is exactly the regime of a Bloom filter built at a 10% or 50%
    # target rate.
    #
    # Where the normal approximation does not apply, falls back to a Poisson
    # interval, which is wider in that regime and therefore safe.
    #
    # @param trials [Integer]
    # @param probability [Float]
    # @param stddevs [Float]
    # @return [Range] an inclusive integer range
    def binomial_bounds(trials, probability, stddevs = DEFAULT_STDDEVS)
      expected = trials * probability

      unless normal_approximation_valid?(trials, probability)
        return poisson_lower_bound(expected, stddevs)..poisson_upper_bound(expected, stddevs)
      end

      # Variance of a binomial, with a continuity correction of one count on
      # each side so that a bound at small counts is not artificially tight.
      spread = (stddevs * Math.sqrt(trials * probability * (1 - probability))) + 1.0

      low = (expected - spread).floor
      low = 0 if low.negative?

      high = (expected + spread).ceil
      high = trials if high > trials

      low..high
    end

    # Describes why an observed count did or did not fall in a bound.
    #
    # Every statistical assertion routes its failure message through here, so
    # all of them report the same facts: observed, expected, the bound, the
    # trial count, and the seed.
    #
    # @param observed [Integer]
    # @param expected [Float]
    # @param bound [Range]
    # @param trials [Integer]
    # @param seed [Integer, nil]
    # @param label [String]
    # @return [String]
    def explain(observed:, expected:, bound:, trials:, seed: nil, label: "count")
      observed_rate = trials.zero? ? 0.0 : observed.to_f / trials
      expected_rate = trials.zero? ? 0.0 : expected.to_f / trials

      lines = [
        "#{label} outside its #{DEFAULT_STDDEVS}-sigma bound",
        format("  observed: %d (rate %.6f)", observed, observed_rate),
        format("  expected: %.2f (rate %.6f)", expected, expected_rate),
        "  bound:    #{bound.first}..#{bound.last}",
        "  trials:   #{trials}"
      ]
      lines << "  seed:     #{seed}" unless seed.nil?

      lines.join("\n")
    end

    # The false positive rate a Bloom filter should achieve.
    #
    # `p = (1 - e^(-kn/m))^k`, matching `Bloom001::false_positive_rate`. Used by
    # the differential checks in area 110, which verify the implementation
    # against an independently written closed form rather than against itself.
    #
    # @param bits [Integer] m
    # @param keys [Integer] n
    # @param hashes [Integer] k
    # @return [Float]
    def bloom_false_positive_rate(bits:, keys:, hashes:)
      return 0.0 if keys.zero?

      (1.0 - Math.exp(-hashes.to_f * keys / bits))**hashes
    end

    # The optimal bit count for a Bloom filter, `m = -n ln(p) / (ln 2)^2`.
    #
    # An independent restatement of `optimal_sizing`, so a refactor of the Rust
    # sizing code is caught by comparison rather than by trusting it.
    #
    # @param keys [Integer]
    # @param rate [Float]
    # @return [Integer]
    def bloom_optimal_bits(keys, rate)
      return 64 if keys.zero?

      (-keys * Math.log(rate) / (Math.log(2)**2)).ceil
    end

    # The optimal hash count, `k = (m/n) ln 2`.
    #
    # @param bits [Integer]
    # @param keys [Integer]
    # @return [Integer]
    def bloom_optimal_hashes(bits, keys)
      return 1 if keys.zero?

      ((bits.to_f / keys) * Math.log(2)).round
    end
  end
end
