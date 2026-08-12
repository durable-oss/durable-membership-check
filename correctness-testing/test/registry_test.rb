# frozen_string_literal: true

require "test_helper"

# Area 060 — the plugin registry and name resolution.
#
# The registry is what lets a binding or a CLI reach every filter by name
# without a match arm per type. Its failure modes are unusual: registration
# happens through link-time sections, so a filter reachable in a unit test is
# not proof it is reachable from a separately linked binary.
#
# This suite runs against a separately linked binary by construction, which is
# the strongest form of that check available. `dmc-cli` is its own crate; if
# `inventory` dropped its registrations, every test here would report
# `unknown_filter`.
class RegistryTest < DmcCheck::ConformanceTest
  include DmcCheck

  # 060.020.010 — registrations are visible from an external binary at all.
  #
  # The check that has to pass before any other test in this file means
  # anything.
  def test_at_least_one_filter_is_linked
    refute_empty FilterSpec.all,
                 "dmc-cli reported no filters. Either none are compiled in, or the linker " \
                 "discarded the inventory sections that carry the registrations."
  end

  # 060.010.010 — an exact id resolves to itself.
  for_each_filter "resolves its exact id to itself" do |spec|
    described = session.describe(spec.id)

    assert_equal spec.id, described.fetch("id"),
                 "asking for #{spec.id} produced #{described["id"]}"
  end

  # 060.010.020 — a family alias resolves to the highest version in the family.
  #
  # Computed from the registry rather than hardcoded, so a new version moves the
  # expectation automatically.
  def test_family_aliases_resolve_to_the_highest_version
    FilterSpec.all.group_by(&:family).each do |family, members|
      expected = members.max_by(&:version)
      described = session.describe(family)

      assert_equal expected.id, described.fetch("id"),
                   "family #{family} has versions #{members.map(&:version).sort.inspect}; " \
                   "the alias should resolve to #{expected.id} but resolved to #{described["id"]}"
    end
  end

  # 060.010.020 — the resolution each registration reports agrees with reality.
  for_each_filter "agrees about where its family alias points" do |spec|
    skip "#{spec.id} reports no family resolution" if spec.family_resolves_to.nil?

    assert_equal spec.family_resolves_to, session.describe(spec.family).fetch("id"),
                 "#{spec.id} claims family #{spec.family} resolves to " \
                 "#{spec.family_resolves_to}, but describing the family disagrees"
  end

  # 060.010.050 — unknown names error rather than defaulting.
  #
  # Silently falling back to some other filter would be far worse than failing:
  # a typo would produce answers that look right.
  def test_unknown_names_are_reported_not_defaulted
    ["no-such-filter", "", " ", "bloom ", " bloom", "bloom\x00", "bloom_", "_001"].each do |name|
      response = session.try_build(name, ["k".b], expected_items: 1, false_positive_rate: 0.01)

      refute response["ok"], "building #{name.inspect} succeeded; it should not resolve"
      assert_equal "unknown_filter", response["kind"],
                   "building #{name.inspect} gave #{response["kind"]}, expected unknown_filter"
      assert_includes response["message"], name.strip.empty? ? "" : name.strip,
                      "the error should name what was requested"
    end
  end

  # 060.010.060 — name resolution is case-sensitive.
  #
  # Ids are encoded into filter bytes, where case matters. A case-insensitive
  # convenience, if ever wanted, belongs at a CLI layer rather than here.
  for_each_filter "resolves case-sensitively" do |spec|
    variants = [spec.id.upcase, spec.id.capitalize, spec.family.upcase]
                 .reject { |name| name == spec.id || name == spec.family }

    variants.each do |name|
      response = session.try_build(name, ["k".b], expected_items: 1, false_positive_rate: 0.01)

      refute response["ok"], "#{name.inspect} resolved; ids must be case-sensitive"
    end
  end

  # 060.030.010 — no duplicate ids.
  #
  # Two registrations sharing an id would silently overwrite each other in the
  # registry's map. Unenforceable at compile time; a test is the only guard.
  def test_ids_are_unique
    ids = FilterSpec.all.map(&:id)

    assert_equal ids.length, ids.uniq.length,
                 "duplicate registration ids: #{ids.tally.select { |_, n| n > 1 }.keys.inspect}"
  end

  # 060.030.020 — ids match the family_NNN convention.
  #
  # `register_filter!` now derives the id from the family and version, so a
  # mismatch fails the build. This asserts the result from outside, which also
  # covers a registration built by hand rather than through the macro.
  for_each_filter "has an id matching family_NNN" do |spec|
    expected = format("%s_%03d", spec.family, spec.version)

    assert_equal expected, spec.id,
                 "#{spec.id} does not match its family #{spec.family} and version #{spec.version}"
  end

  # 060.030.030 — versions within a family are distinct.
  #
  # Two registrations with the same family and version make alias resolution
  # order-dependent.
  def test_versions_within_a_family_are_distinct
    FilterSpec.all.group_by(&:family).each do |family, members|
      versions = members.map(&:version)

      assert_equal versions.length, versions.uniq.length,
                   "family #{family} has repeated versions: " \
                   "#{versions.tally.select { |_, n| n > 1 }.keys.inspect}"
    end
  end

  # 060.030.040 — descriptions are present and not placeholders.
  #
  # These surface in a CLI listing and in a binding's catalog.
  for_each_filter "has a real description" do |spec|
    refute_empty spec.description.strip, "#{spec.id} has no description"

    assert_operator spec.description.length, :>=, 16,
                    "#{spec.id} has a description too short to be useful: " \
                    "#{spec.description.inspect}"

    placeholders = ["todo", "tbd", "fixme", "xxx", "description"]
    lowered = spec.description.downcase

    placeholders.each do |placeholder|
      refute_includes lowered, placeholder,
                      "#{spec.id}'s description looks like a placeholder: " \
                      "#{spec.description.inspect}"
    end
  end

  # 060.030.050 — the listing is sorted by id.
  #
  # Documented as "sorted by id" and delivered by the registry's map ordering. A
  # future switch to a hash map would break that contract silently.
  def test_listing_is_sorted_by_id
    ids = FilterSpec.all.map(&:id)

    assert_equal ids.sort, ids, "the registry listing is not sorted by id"
  end

  # 060.010.030 — a listing entry and a describe of the same name agree.
  for_each_filter "describes itself consistently with the listing" do |spec|
    described = FilterSpec.new(session.describe(spec.id))

    assert_equal spec.id, described.id
    assert_equal spec.family, described.family
    assert_equal spec.version, described.version
    assert_equal spec.description, described.description
    assert_equal spec.capabilities, described.capabilities,
                 "#{spec.id} declares different capabilities in `list` and `describe`"
  end

  # 060.040.020 — parameter validation happens for every filter, uniformly.
  #
  # An invalid rate must give InvalidParameter, not ConstructionFailed and not a
  # panic. `rejects_out_of_range_false_positive_rate` covers bloom in Rust; this
  # makes it universal.
  for_each_filter "rejects an out-of-range false positive rate" do |spec|
    [0.0, 1.0, -0.5, 1.5, Float::NAN, Float::INFINITY, -Float::INFINITY].each do |rate|
      response = session.try_build(spec.id, ["k".b], expected_items: 1,
                                                     false_positive_rate: rate)

      refute response["ok"], "#{spec.id} accepted a false positive rate of #{rate}"
      assert_equal "invalid_parameter", response["kind"],
                   "#{spec.id} rejected rate #{rate} with #{response["kind"]}, " \
                   "expected invalid_parameter"
    end
  end

  # 060.040.030 — building by family and by exact id agree.
  #
  # Where the alias resolves to this implementation, the two paths must produce
  # the same filter, byte for byte. `build_boxed` is a thin wrapper today, but
  # it is the kind of wrapper that acquires a difference during a refactor.
  for_each_filter "builds identically through its family alias and its id" do |spec|
    skip "#{spec.family} does not resolve to #{spec.id}" unless spec.family_resolves_to == spec.id

    keys = Generators.random_keys(200, 60_040_030)
    params = { expected_items: keys.length, false_positive_rate: 0.01, seed: 60_040_030 }

    by_id = session.build(spec.id, keys, **params)
    by_family = session.build(spec.family, keys, **params)

    assert_equal by_id.id, by_family.id
    assert_equal Hex.encode(by_id.encode), Hex.encode(by_family.encode),
                 "#{spec.id} built differently through its family alias"
  end

  # 060.040.040 — errors propagate with their variant intact.
  #
  # An implementation's error must reach the caller as itself, not flattened
  # into a generic failure.
  def test_error_variants_survive_the_registry
    expectations = {
      "unknown_filter" => -> { session.try_build("not-a-filter", []) },
      "invalid_parameter" => -> { session.try_build(FilterSpec.all.first.id, ["k".b],
                                                    false_positive_rate: 2.0) },
      "corrupt" => -> { session.try_decode("short".b) },
      "unknown_encoding" => -> { session.try_decode(Encodings.unlinked_family) }
    }

    expectations.each do |expected_kind, attempt|
      response = attempt.call

      refute response["ok"], "expected #{expected_kind}, but the call succeeded"
      assert_equal expected_kind, response["kind"],
                   "got #{response["kind"]} (#{response["message"]}), expected #{expected_kind}"
    end
  end

  # 060.020.060 — the registry index is stable across repeated reads.
  #
  # Built once behind a OnceLock. Repeated listings must be identical in content
  # and order; a partially populated index would show as a shrinking list.
  def test_the_registry_listing_is_stable
    first = session.list

    5.times do
      assert_equal first, session.list, "the registry listing changed between reads"
    end
  end

  # 060.020.060 — concurrent first-touch of the registry is safe.
  #
  # Separate processes rather than threads, since each `dmc-cli` invocation
  # builds its own index from scratch. That is the stronger check: it exercises
  # first-touch every time rather than once per process.
  def test_concurrent_first_touch_sees_the_complete_registry
    expected = FilterSpec.all.map(&:id).sort

    results = 8.times.map do
      Thread.new do
        Cli::Session.open { |s| s.list.map { |f| f.fetch("id") }.sort }
      end
    end.map(&:value)

    results.each_with_index do |ids, i|
      assert_equal expected, ids,
                   "process #{i} saw a different registry: #{ids.inspect}"
    end
  end

  # 060.040.010 — every registered filter builds from the standard key sets.
  #
  # The entry point to the conformance suite: the test discovers filters rather
  # than listing them, so a new implementation is covered the moment it
  # registers.
  for_each_filter "builds from every standard generator" do |spec|
    Generators.standard_suite(200, seed: 60_040_010).each do |generator, keys|
      response = session.try_build(spec.id, keys, expected_items: keys.length,
                                                  false_positive_rate: 0.01)

      assert response["ok"],
             "#{spec.id} failed to build from #{generator} keys: #{response["message"]}"
    end
  end
end
