# frozen_string_literal: true

require "test_helper"

# Area 090 — concurrent use.
#
# `dmc_core::Filter` requires `Send + Sync`, justified in the trait docs: "a
# built filter is immutable, so it can be shared across threads without further
# wrapping." Callers will rely on that, so it needs testing rather than
# assertion.
#
# What this suite can reach from outside the process is narrower than what the
# Rust tests can: `Send + Sync` is a compile-time property, checked there. What
# is checked here is the observable consequence — that concurrent use through
# separate sessions produces identical answers, and that the registry's lazily
# built index is safe under concurrent first touch.
#
# `external/BuRR/parbench.cpp` is the closest reference, running the full query
# check across a thread pool and aggregating per-thread results.
class ConcurrencyTest < DmcCheck::ConformanceTest
  include DmcCheck

  # More workers than cores, to force preemption rather than merely
  # interleaving.
  WORKERS = 12

  # 090.010.030 — concurrent queries return identical answers, not merely
  # correct ones.
  #
  # Identical is the sharper assertion: it catches a filter that is
  # correct-but-nondeterministic under concurrency, which a per-thread
  # correctness check would pass.
  #
  # Each worker gets its own session and its own permutation of the probe set,
  # so no two workers query in the same order.
  for_each_filter "answers identically from every concurrent worker" do |spec|
    keys = Generators.random_keys(2_000, 90_010_030)
    probes = keys.first(500) + Generators.disjoint_probe_keys(keys, 1_500, 90_010_030)
    params = { expected_items: keys.length, false_positive_rate: 0.01, seed: 90_010_030 }

    # The reference answers, taken single-threaded first.
    reference = build(spec, keys, **params).contains_all(probes)

    results = WORKERS.times.map do |worker|
      Thread.new do
        Cli::Session.open do |s|
          handle = s.build(spec.id, keys, **params)

          # A different permutation per worker, undone before comparison.
          order = (0...probes.length).to_a.shuffle(random: Random.new(90_010_030 + worker))
          answers = handle.contains_all(order.map { |i| probes[i] })

          restored = Array.new(probes.length)
          order.each_with_index { |original, shuffled| restored[original] = answers[shuffled] }
          restored
        end
      end
    end.map(&:value)

    results.each_with_index do |answers, worker|
      next if answers == reference

      differing = answers.each_index.count { |i| answers[i] != reference[i] }
      first = answers.each_index.find { |i| answers[i] != reference[i] }

      flunk "#{spec.id}: worker #{worker} disagreed with the single-threaded reference on " \
            "#{differing} of #{probes.length} probes; first at #{first} " \
            "(#{Hex.encode(probes[first])}): reference #{reference[first]}, " \
            "worker #{answers[first]}"
    end

    assert_equal [reference] * WORKERS, results
  end

  # 090.020.010 — independent filters build concurrently without interference.
  #
  # Each worker builds with a different seed and key set, then the result is
  # compared against what that build produces alone. Any difference means
  # construction picked up state from elsewhere.
  for_each_filter "builds concurrently without interference" do |spec|
    inputs = WORKERS.times.map do |worker|
      [
        Generators.random_keys(500, 90_020_010 + worker),
        { expected_items: 500, false_positive_rate: 0.01, seed: 90_020_010 + worker }
      ]
    end

    # Sequential first, as the reference.
    expected = inputs.map do |keys, params|
      Hex.encode(build(spec, keys, **params).encode)
    end

    actual = inputs.each_with_index.map do |(keys, params), _worker|
      Thread.new do
        Cli::Session.open { |s| Hex.encode(s.build(spec.id, keys, **params).encode) }
      end
    end.map(&:value)

    actual.each_with_index do |encoding, worker|
      assert_equal expected[worker], encoding,
                   "#{spec.id}: worker #{worker} built a different filter concurrently " \
                   "than it did alone"
    end
  end

  # 090.020.020 — concurrent first-touch of the registry is safe.
  #
  # The registry index is built once behind a `OnceLock`. Every one of these
  # processes builds its own index from scratch as its first action, so this is
  # first-touch every time rather than once. A race would show as a partially
  # populated index.
  def test_concurrent_first_touch_of_the_registry
    expected = FilterSpec.all.map { |f| [f.id, f.family, f.version] }.sort

    results = WORKERS.times.map do
      Thread.new do
        Cli::Session.open do |s|
          s.list.map { |f| [f.fetch("id"), f.fetch("family"), f.fetch("version")] }.sort
        end
      end
    end.map(&:value)

    results.each_with_index do |seen, worker|
      assert_equal expected, seen,
                   "worker #{worker} saw a different registry on first touch: #{seen.inspect}"
    end
  end

  # 090.020.030 — concurrent builds by name are safe.
  #
  # Exercises name lookup under contention, including the family-alias path.
  for_each_filter "resolves its name concurrently" do |spec|
    names = [spec.id, spec.family].uniq
    keys = Generators.random_keys(200, 90_020_030)
    params = { expected_items: keys.length, false_positive_rate: 0.01, seed: 90_020_030 }

    results = (WORKERS * 2).times.map do |worker|
      Thread.new do
        Cli::Session.open do |s|
          s.build(names[worker % names.length], keys, **params).id
        end
      end
    end.map(&:value)

    # Every build by exact id must give that id; every build by family must give
    # whatever the family resolves to.
    results.each_with_index do |id, worker|
      requested = names[worker % names.length]
      expected = requested == spec.family ? spec.family_resolves_to : spec.id

      assert_equal expected, id,
                   "worker #{worker} asked for #{requested} and got #{id}"
    end
  end

  # 090.010.050 — a filter survives being handed to another worker.
  #
  # Across a process boundary this is the encoded form: build in one session,
  # decode and query in another. Distinct from sharing, and it exercises the
  # path a real deployment uses when it caches a filter to disk or to a network
  # store.
  for_each_filter "survives being handed to another process" do |spec|
    keys = Generators.random_keys(1_000, 90_010_050)
    oracle = Oracle.new(keys)
    params = { expected_items: keys.length, false_positive_rate: 0.01, seed: 90_010_050 }

    encoded = build(spec, keys, **params).encode
    probes = keys + Generators.disjoint_probe_keys(keys, 2_000, 90_010_050)
    reference = build(spec, keys, **params).contains_all(probes)

    results = WORKERS.times.map do
      Thread.new do
        Cli::Session.open do |s|
          handle = s.decode(encoded)
          [handle.contains_all(probes), handle.contains_all(oracle.members).all?]
        end
      end
    end.map(&:value)

    results.each_with_index do |(answers, sound), worker|
      assert sound, "#{spec.id}: worker #{worker} lost a member after decoding"
      assert_equal reference, answers,
                   "#{spec.id}: worker #{worker} answered differently after decoding"
    end
  end
end
