# frozen_string_literal: true

require "test_helper"
require "fileutils"
require "json"

# Area 070 — seed reproducibility and the frozen-implementation promise.
#
# `Params::seed` is documented as making construction deterministic, "which
# matters for reproducible builds and for tests." A filter that is deterministic
# by accident rather than by contract will stop being deterministic during some
# future refactor, and nothing will notice until a golden file breaks in an
# unrelated change.
#
# This area also enforces the promise in `lib/dmc-core/src/lib.rs`: "once
# published, which keys it accepts and rejects never changes."
class DeterminismTest < DmcCheck::ConformanceTest
  include DmcCheck

  # 070.010.010 — the same seed and keys produce an identical filter.
  #
  # Compared through the encoded bytes rather than through a type-specific
  # equality, since bytes are what is observable across the boundary and they
  # cover every field rather than the ones an equality happens to compare.
  for_each_filter "reproduces itself byte for byte from the same inputs" do |spec|
    keys = Generators.random_keys(1_000, 70_010_010)
    params = { expected_items: keys.length, false_positive_rate: 0.01, seed: 70_010_010 }

    first = build(spec, keys, **params).encode
    second = build(spec, keys, **params).encode

    assert_equal Hex.encode(first), Hex.encode(second),
                 "#{spec.id} built differently from identical inputs"
  end

  # Determinism must hold across processes too, not merely within one. A filter
  # that seeded itself from process state would pass the check above and fail
  # this one.
  for_each_filter "reproduces itself across separate processes" do |spec|
    keys = Generators.random_keys(500, 70_010_011)
    params = { expected_items: keys.length, false_positive_rate: 0.01, seed: 70_010_011 }

    encodings = 3.times.map do
      Cli::Session.open { |s| Hex.encode(s.build(spec.id, keys, **params).encode) }
    end

    assert_equal 1, encodings.uniq.length,
                 "#{spec.id} built differently in separate processes, which means something " \
                 "outside its inputs reached the construction"
  end

  # 070.010.020 — different seeds produce different filters.
  #
  # Probabilistic in principle: two seeds could coincidentally agree for a tiny
  # key set. At 1,000 keys the probability is negligible.
  for_each_filter "produces a different filter under a different seed" do |spec|
    keys = Generators.random_keys(1_000, 70_010_020)
    params = { expected_items: keys.length, false_positive_rate: 0.01 }

    encodings = (1..8).map { |seed| Hex.encode(build(spec, keys, **params, seed: seed).encode) }

    assert_equal encodings.length, encodings.uniq.length,
                 "#{spec.id} produced identical filters under different seeds; " \
                 "the seed does not reach the construction"
  end

  # 070.010.030 — key insertion order does not affect the result.
  #
  # For a filter that sets bits commutatively this must be byte-identical. For a
  # peeling filter it need not be, which is what the capability declares — and
  # there the weaker property is asserted instead.
  for_each_filter_with "is byte-identical under shuffled input",
                       :order_independent? do |spec|
    keys = Generators.random_keys(1_000, 70_010_030)
    params = { expected_items: keys.length, false_positive_rate: 0.01, seed: 70_010_030 }

    original = build(spec, keys, **params).encode

    3.times do |round|
      shuffled = keys.shuffle(random: Random.new(70_010_030 + round))
      rebuilt = build(spec, shuffled, **params).encode

      assert_equal Hex.encode(original), Hex.encode(rebuilt),
                   "#{spec.id} declares order-independent construction but shuffle #{round} " \
                   "produced different bytes"
    end
  end

  # The negative case: a filter that declares order dependence must still hold
  # every member and report the same length whatever the order.
  for_each_filter_without "stays equivalent under shuffled input",
                          :order_independent? do |spec|
    keys = Generators.random_keys(1_000, 70_010_031)
    params = { expected_items: keys.length, false_positive_rate: 0.01, seed: 70_010_031 }
    oracle = Oracle.new(keys)

    original = build(spec, keys, **params)
    shuffled = build(spec, keys.shuffle(random: Random.new(70_010_031)), **params)

    assert_equal original.len, shuffled.len, "#{spec.id} reported a different length"
    assert_no_false_negatives(shuffled, oracle, context: "built from shuffled input")
  end

  # 070.010.050 — the default seed is stable, and zero is a legitimate seed.
  #
  # `hash64` mixes the seed via `seed.wrapping_mul(FNV_PRIME)` and `probes`
  # derives `h2` from `h1 ^ seed.rotate_left(32)`, so a zero seed is not
  # degenerate. That is a claim worth checking rather than assuming: a zero seed
  # that collapsed the mixing would be invisible until someone set a nonzero one
  # and saw different behavior.
  for_each_filter "behaves the same at seed zero as at any other seed" do |spec|
    members = Generators.random_keys(2_000, 70_010_050)
    probes = Generators.disjoint_probe_keys(members, 50_000, 70_010_050)
    params = { expected_items: members.length, false_positive_rate: 0.01 }

    rates = [0, 1, 12_345, 2**63].map do |seed|
      handle = build(spec, members, **params, seed: seed)
      rate = handle.contains_all(probes).count(true).to_f / probes.length
      handle.release
      rate
    end

    zero_seed_rate = rates.first
    others = rates.drop(1)
    mean_of_others = others.sum / others.length

    bound = Tolerance.binomial_bounds(probes.length, mean_of_others)

    assert_includes bound, (zero_seed_rate * probes.length).round,
                    Tolerance.explain(
                      observed: (zero_seed_rate * probes.length).round,
                      expected: mean_of_others * probes.length,
                      bound: bound,
                      trials: probes.length,
                      seed: 0,
                      label: "#{spec.id} at seed 0 against the mean of seeds " \
                             "#{[1, 12_345, 2**63].inspect}"
                    )
  end

  # An unspecified seed must mean the documented default, not an arbitrary one.
  for_each_filter "defaults its seed rather than choosing one" do |spec|
    keys = Generators.random_keys(200, 70_010_051)

    without_seed = build(spec, keys, expected_items: keys.length,
                                     false_positive_rate: 0.01).encode
    with_zero = build(spec, keys, expected_items: keys.length,
                                  false_positive_rate: 0.01, seed: 0).encode

    assert_equal Hex.encode(with_zero), Hex.encode(without_seed),
                 "#{spec.id} built differently with no seed than with seed 0; " \
                 "Params::default documents the default as 0"
  end

  # 070.030.020 — a golden encoding pins the frozen-implementation promise.
  #
  # Without checked-in goldens, "once published, which keys it accepts and
  # rejects never changes" is unenforceable. These are generated on first run
  # and compared thereafter.
  #
  # A mismatch is a frozen-implementation violation. The fix is a new version
  # id, not an updated golden file — see the README in the golden directory.
  for_each_filter "matches its checked-in golden encoding" do |spec|
    fixture = Golden.for(spec)

    unless fixture.exist?
      fixture.write(spec, session)
      skip "wrote a new golden for #{spec.id} at #{fixture.relative_path}; " \
           "review it and commit it"
    end

    fixture.assert_matches(self, spec, session)
  end

  # 070.030.030 — the golden decodes and reproduces its recorded answers.
  #
  # Separate from the byte comparison and still valuable if the encoding
  # changes: encoding drift breaks the test above, a decoder regression breaks
  # this one.
  for_each_filter "decodes its golden and reproduces the recorded answers" do |spec|
    fixture = Golden.for(spec)
    skip "no golden recorded for #{spec.id} yet" unless fixture.exist?

    fixture.assert_decodes(self, session)
  end

  # 070.020.010 — hashing is stable, observed through the filter.
  #
  # `hash64` is shared by every implementation, so a change to it changes every
  # filter at once. That is precisely the kind of change that must be a
  # deliberate new implementation version. The golden encodings above pin it
  # transitively; this pins it for a key set chosen to exercise the chunk
  # boundaries specifically.
  for_each_filter "hashes chunk-boundary keys stably" do |spec|
    keys = (0..65).map { |n| ("\xAB".b * n) } + [
      "".b, "\x00".b, "\xFF".b * 8, "\x00".b * 9,
      "the quick brown fox jumps over the lazy dog".b
    ]

    params = { expected_items: keys.length, false_positive_rate: 0.001, seed: 70_020_010 }
    encodings = 2.times.map { Hex.encode(build(spec, keys, **params).encode) }

    assert_equal 1, encodings.uniq.length, "#{spec.id} hashed the same keys differently"

    oracle = Oracle.new(keys)
    assert_no_false_negatives(build(spec, keys, **params), oracle,
                              context: "chunk-boundary key set")
  end

  # 070.040.010 — the suite itself is reproducible.
  #
  # Every generator must be a pure function of its arguments. Both
  # `external/vqf` (via RAND_bytes) and `external/binfuse` (via random_device)
  # fail this, which is why their statistical failures cannot be replayed.
  def test_every_generator_is_reproducible
    Generators.standard_suite(100, seed: 70_040_010).each_key do |name|
      first = Generators.standard_suite(100, seed: 70_040_010).fetch(name)
      second = Generators.standard_suite(100, seed: 70_040_010).fetch(name)

      assert_equal first, second, "generator #{name} is not reproducible from its seed"
    end
  end

  # A different seed must actually change the keys, or the seed parameter is
  # decorative.
  def test_seeded_generators_respond_to_their_seed
    %i[random_keys small_keys variable_length_keys].each do |generator|
      first = Generators.public_send(generator, 100, 1)
      second = Generators.public_send(generator, 100, 2)

      refute_equal first, second, "#{generator} ignored its seed"
    end
  end

  # 070.040.010 — no test source reads a clock or an unseeded random device.
  #
  # A grep-level check, which is the only kind available for this. Every RNG in
  # the suite must be constructed with an explicit seed.
  def test_no_test_reads_a_clock_or_an_unseeded_rng
    root = File.expand_path("../..", __dir__)
    offenders = []

    # Patterns that make a run unreproducible. `Random.new(seed)` is fine;
    # `Random.new` with no argument seeds itself from the system.
    unseeded = [
      /Random\.new\s*(?:\(\s*\)|$)/,
      /SecureRandom/,
      /\brand\s*\(/,
      /\bsrand\b/,
      # Time is fine for measuring elapsed wall clock, never for seeding.
      /Time\.now.*seed/i
    ]

    Dir.glob("#{root}/correctness-testing/{lib,test}/**/*.rb").each do |path|
      next if File.basename(path) == File.basename(__FILE__)

      File.readlines(path).each_with_index do |line, index|
        # Comments describe these patterns; only code can violate the rule.
        # `\z` would not anchor here: the line still carries its newline, and
        # `.` does not cross one. Chomp first, then strip from the first `#`.
        code = line.chomp.sub(/#.*/, "")
        next if code.strip.empty?

        offenders << "#{path}:#{index + 1}: #{line.strip}" if unseeded.any? { |p| code.match?(p) }
      end
    end

    assert_empty offenders,
                 "test code must be reproducible from its own output:\n  #{offenders.join("\n  ")}"
  end

  # A golden encoding on disk, with the parameters that produced it.
  #
  # Kept small on purpose (plan step 070.030.040): a few hundred keys, so the
  # files stay in the low kilobytes. The point is behavioral pinning, not scale
  # coverage.
  class Golden
    # Explicitly namespaced rather than relying on `include`: the methods below
    # are class methods, which do not see an instance-side include.
    Generators = DmcCheck::Generators
    Hex = DmcCheck::Hex

    # Keys in a golden filter. Small enough to stay in the low kilobytes,
    # large enough that the encoding is not trivially reproducible by accident.
    KEY_COUNT = 256

    # Fixed across every golden, so the recorded parameters are the only thing
    # that varies between implementations.
    SEED = 70_030_010

    # Probe keys whose answers are recorded alongside the bytes.
    #
    # The false positives among these are the valuable part: they pin the exact
    # behavior rather than only the membership guarantee.
    PROBE_COUNT = 2_000

    # @return [Golden]
    def self.for(spec)
      new(spec.id)
    end

    def initialize(id)
      @id = id
      @dir = File.expand_path("golden", __dir__)
    end

    # @return [String]
    def bin_path = File.join(@dir, "#{@id}.bin")

    # @return [String]
    def json_path = File.join(@dir, "#{@id}.json")

    # @return [String] the path as written in a message
    def relative_path = "correctness-testing/test/golden/#{@id}.bin"

    # @return [Boolean]
    def exist? = File.exist?(bin_path) && File.exist?(json_path)

    # The key set and parameters a golden is built from.
    #
    # @return [Array(Array<String>, Hash)]
    def self.inputs
      [
        Generators.random_keys(KEY_COUNT, SEED),
        { expected_items: KEY_COUNT, false_positive_rate: 0.01, seed: SEED }
      ]
    end

    # Generates and writes the golden files.
    #
    # @return [void]
    def write(spec, session)
      require "json"
      FileUtils.mkdir_p(@dir)

      keys, params = self.class.inputs
      handle = session.build(spec.id, keys, **params)
      probes = Generators.disjoint_probe_keys(keys, PROBE_COUNT, SEED)
      answers = handle.contains_all(probes)

      File.binwrite(bin_path, handle.encode)
      File.write(json_path, "#{JSON.pretty_generate(
        id: spec.id,
        generated_by: "correctness-testing/test/determinism_test.rb",
        key_generator: "random_keys(#{KEY_COUNT}, #{SEED})",
        params: params,
        len: handle.len,
        memory_bytes: handle.memory_bytes,
        false_positive_rate: handle.false_positive_rate,
        probe_generator: "disjoint_probe_keys(members, #{PROBE_COUNT}, #{SEED})",
        probe_positives: answers.each_index.select { |i| answers[i] }
      )}\n")
    end

    # Asserts current code reproduces the golden bytes exactly.
    #
    # @return [void]
    def assert_matches(test, spec, session)
      require "json"
      keys, params = self.class.inputs
      recorded = JSON.parse(File.read(json_path))

      rebuilt = session.build(spec.id, keys, **params).encode
      expected = File.binread(bin_path)

      test.assert_equal Hex.encode(expected), Hex.encode(rebuilt),
                        "#{spec.id} no longer reproduces its golden encoding.\n" \
                        "  This is a frozen-implementation violation: " \
                        "`#{spec.id}` promises that which keys it accepts and rejects " \
                        "never changes.\n" \
                        "  The fix is to publish a new version id, not to regenerate " \
                        "#{relative_path}.\n" \
                        "  See correctness-testing/test/golden/README.md."

      handle = session.build(spec.id, keys, **params)
      test.assert_equal recorded.fetch("len"), handle.len
      test.assert_equal recorded.fetch("memory_bytes"), handle.memory_bytes
    end

    # Asserts the golden decodes and answers exactly as recorded.
    #
    # @return [void]
    def assert_decodes(test, session)
      require "json"
      recorded = JSON.parse(File.read(json_path))
      keys, = self.class.inputs

      handle = session.decode(File.binread(bin_path))
      probes = Generators.disjoint_probe_keys(keys, PROBE_COUNT, SEED)
      answers = handle.contains_all(probes)

      positives = answers.each_index.select { |i| answers[i] }

      test.assert_equal recorded.fetch("probe_positives"), positives,
                        "#{recorded["id"]} decoded its golden but answered differently. " \
                        "The recorded answers include this implementation's false positives, " \
                        "which pin its exact behavior rather than only its soundness."

      # Members must still be found, which is the guarantee that outranks all
      # the rest.
      test.assert_equal keys.map { true }, handle.contains_all(keys),
                        "#{recorded["id"]} lost a member from its golden encoding"
    end
  end
end
