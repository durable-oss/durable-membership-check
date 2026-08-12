# frozen_string_literal: true

module DmcCheck
  # One filter implementation as the suite sees it.
  #
  # Built from the CLI's `describe` output, so everything here — the id, the
  # family, the capabilities — comes from the implementation's own registration
  # rather than from a table maintained alongside the tests. Adding a filter
  # means registering it in Rust; the suite discovers it and knows which checks
  # apply.
  class FilterSpec
    # @return [String] versioned implementation id, such as "bloom_001"
    attr_reader :id

    # @return [String] family name, such as "bloom"
    attr_reader :family

    # @return [Integer] version within the family
    attr_reader :version

    # @return [String] one-line description
    attr_reader :description

    # @return [String, nil] the id the family alias resolves to
    attr_reader :family_resolves_to

    # @return [Hash] the raw capability hash, string-keyed
    attr_reader :capabilities

    # Builds one from a `describe` or `list` entry.
    #
    # @param info [Hash]
    def initialize(info)
      @id = info.fetch("id")
      @family = info.fetch("family")
      @version = info.fetch("version")
      @description = info.fetch("description")
      @family_resolves_to = info["family_resolves_to"]
      @capabilities = info.fetch("capabilities")
    end

    # Every linked implementation.
    #
    # One process spawn, cached for the life of the suite: the registry cannot
    # change while the tests run, and re-asking per test file would spawn a
    # process per file for no new information.
    #
    # @return [Array<FilterSpec>]
    def self.all
      @all ||= Cli::Session.open { |session| session.list }.map { |info| new(info) }
    end

    # Whether repeats in the input build successfully.
    # @return [Boolean]
    def tolerates_duplicate_keys? = @capabilities.fetch("tolerates_duplicate_keys")

    # Whether shuffling the input yields a byte-identical filter.
    # @return [Boolean]
    def order_independent? = @capabilities.fetch("order_independent_construction")

    # Whether `len` counts repeats.
    # @return [Boolean]
    def len_counts_duplicates? = @capabilities.fetch("len_counts_duplicates")

    # Whether the filter sizes itself from the requested rate.
    # @return [Boolean]
    def honors_target_fpr? = @capabilities.fetch("honors_target_fpr")

    # Whether keys can be removed after construction.
    # @return [Boolean]
    def supports_deletion? = @capabilities.fetch("supports_deletion")

    # Whether querying mutates the filter.
    # @return [Boolean]
    def adaptive? = @capabilities.fetch("is_adaptive")

    # Whether two compatible filters combine into one holding both key sets.
    # @return [Boolean]
    def supports_union? = @capabilities.fetch("supports_union")

    # Whether two compatible filters combine into one holding their overlap.
    # @return [Boolean]
    def supports_intersection? = @capabilities.fetch("supports_intersection")

    # Whether the filter estimates how many distinct keys it holds.
    # @return [Boolean]
    def estimates_cardinality? = @capabilities.fetch("estimates_cardinality")

    # Largest key count the implementation is designed for.
    # @return [Integer, nil]
    def max_practical_keys = @capabilities["max_practical_keys"]

    # Whether a key count is within the implementation's design range.
    #
    # @param count [Integer]
    # @return [Boolean]
    def supports_size?(count)
      max = max_practical_keys
      max.nil? || count <= max
    end

    # The published space overhead for this family, as a fraction.
    #
    # A property of the algorithm rather than of the implementation, so it lives
    # in a table here rather than in a capability. Sources are the papers under
    # `RESEARCH/`.
    #
    # Returns nil for a family with no recorded bound, which is not a failure —
    # the space check skips and says so.
    #
    # @return [Float, nil]
    def published_overhead
      {
        # 1/ln(2)^2 ≈ 1.44, so ~44% above the information-theoretic bound.
        "bloom" => 0.44,
        # graf-lemire-2020-xor-filters.pdf
        "xor" => 0.23,
        # graf-lemire-2022-binary-fuse-filters.pdf
        "fuse" => 0.13,
        # limasset-2026-zor-filters.pdf reports overhead near 1% at its
        # largest tested key counts; this implementation runs the fuse
        # auxiliary at a fixed 8-bit fingerprint rather than the paper's
        # width-tuned one (see zor_001's module docs) and sizes its main
        # table to keep construction fast at moderate key counts, so its
        # measured overhead sits well above the paper's own figure — around
        # 35-45% at 10,000 keys, this test's fixed sample size. Set above
        # that observed figure rather than the paper's, since this bound
        # exists to catch a regression in what this implementation actually
        # does, not to assert the paper's own result.
        "zor" => 0.5,
        # dillinger-walzer-2022-ribbon-filter-fast-succinct-retrieval.pdf
        "ribbon" => 0.01
      }[@family]
    end

    # @return [String]
    def to_s = @id
  end
end
