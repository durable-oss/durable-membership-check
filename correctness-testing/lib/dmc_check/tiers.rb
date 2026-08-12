# frozen_string_literal: true

module DmcCheck
  # Size tiers, and the gate that decides which of them run.
  #
  # `external/BuRR/tests.cpp` uses 512 / 12800 / 131072 for the same reason:
  # enough scale to exercise the structure, small enough for a debug build.
  #
  # The slow tiers are gated on an environment variable rather than a build
  # flag. A flag would leak into the dependency graph and change what gets
  # compiled; reading the environment at runtime keeps the fast path fast
  # without a second build configuration.
  module Tiers
    # Sizes small enough to enumerate by hand.
    TINY = (0..8).to_a.freeze

    # The default tier. Runs on every invocation.
    SMALL = 1_000

    # Runs when DMC_SLOW_TESTS is set.
    MEDIUM = 100_000

    # Runs when DMC_SLOW_TESTS is set and there is disk headroom.
    LARGE = 10_000_000

    # Probe count for a statistical assertion.
    #
    # Below about 100,000 probes a three-sigma bound is so wide the test asserts
    # nothing. `external/binfuse/test/helpers.hpp` uses 1,000,000 and
    # `external/fastfilter_cpp/tests/unit.cc` uses 50,000,000.
    STATISTICAL_PROBES = 100_000

    # Probe count when the slow tier is enabled.
    STATISTICAL_PROBES_SLOW = 1_000_000

    module_function

    # Whether the slow tiers are enabled.
    #
    # @return [Boolean]
    def slow?
      value = ENV.fetch("DMC_SLOW_TESTS", "")
      !value.empty? && value != "0"
    end

    # The key counts to run a table-driven test over.
    #
    # @return [Array<Integer>]
    def sizes
      slow? ? [SMALL, MEDIUM] : [SMALL]
    end

    # How many probes a statistical assertion should use.
    #
    # @return [Integer]
    def statistical_probes
      slow? ? STATISTICAL_PROBES_SLOW : STATISTICAL_PROBES
    end

    # Free space on the volume holding the repository, in bytes.
    #
    # `/mnt/storage` was at 100% while this suite was being written. A large
    # tier that builds filters in the tens of megabytes fails confusingly on a
    # full volume, so the gate checks headroom and skips with a clear message
    # rather than failing mid-write.
    #
    # @return [Integer, nil] nil if it cannot be determined
    def free_bytes
      output = `df -B1 --output=avail #{File.expand_path("../../..", __dir__)} 2>/dev/null`
      line = output.lines[1]
      line&.strip&.to_i
    rescue StandardError
      nil
    end

    # Whether there is room for the large tier.
    #
    # @param needed [Integer]
    # @return [Boolean]
    def room_for?(needed)
      available = free_bytes
      available.nil? || available > needed
    end
  end
end
