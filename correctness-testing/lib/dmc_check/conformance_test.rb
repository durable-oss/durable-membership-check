# frozen_string_literal: true

require "minitest/autorun"

module DmcCheck
  # Base class for a test that runs against every registered filter.
  #
  # Subclasses call {.for_each_filter} instead of defining `test_` methods
  # directly. That generates one minitest method per implementation, so a
  # failure names the filter it came from and one broken implementation does
  # not mask another.
  #
  # Checks that only apply to some filters go through {.for_each_filter_with},
  # which reads the declared capability and skips with a stated reason where it
  # does not hold. A skip is visible in the minitest output, which is the point:
  # a filter passing forty of sixty checks because it opted out of twenty should
  # be obvious at a glance rather than looking identical to one that passed all
  # sixty.
  class ConformanceTest < Minitest::Test
    # Defines one test method per registered filter.
    #
    # @param name [String] a description, used to build the method name
    # @yieldparam spec [FilterSpec] the implementation under test
    # @return [void]
    def self.for_each_filter(name, &block)
      FilterSpec.all.each do |spec|
        define_method(:"test_#{spec.id}_#{name.gsub(/\W+/, "_")}") do
          instance_exec(spec, &block)
        end
      end
    end

    # Defines one test method per filter, gated on a declared capability.
    #
    # Where the capability does not hold the test skips with a message naming
    # the capability, so the reason is in the output rather than in someone's
    # memory.
    #
    # @param name [String]
    # @param capability [Symbol] a predicate on {FilterSpec}, e.g. :honors_target_fpr?
    # @yieldparam spec [FilterSpec]
    # @return [void]
    def self.for_each_filter_with(name, capability, &block)
      FilterSpec.all.each do |spec|
        define_method(:"test_#{spec.id}_#{name.gsub(/\W+/, "_")}") do
          unless spec.public_send(capability)
            skip "#{spec.id} declares #{capability.to_s.delete_suffix("?")} = false"
          end

          instance_exec(spec, &block)
        end
      end
    end

    # Defines one test method per filter, gated on a capability being absent.
    #
    # The negative case is a check too, not a skip: a filter declaring that it
    # rejects duplicates must be shown to actually reject them, not merely
    # excused from the duplicate test.
    #
    # @param name [String]
    # @param capability [Symbol]
    # @yieldparam spec [FilterSpec]
    # @return [void]
    def self.for_each_filter_without(name, capability, &block)
      FilterSpec.all.each do |spec|
        define_method(:"test_#{spec.id}_#{name.gsub(/\W+/, "_")}") do
          if spec.public_send(capability)
            skip "#{spec.id} declares #{capability.to_s.delete_suffix("?")} = true"
          end

          instance_exec(spec, &block)
        end
      end
    end

    # A session shared by every test in the process.
    #
    # One `dmc-cli serve` process rather than one per test. Filters are
    # per-handle so tests do not interfere, and the saving is large: the
    # statistical tests would otherwise spend most of their time in `fork`.
    #
    # @return [Cli::Session]
    def self.session
      @session ||= begin
        session = Cli::Session.new
        # Reaped at process exit rather than after each test, since it is
        # shared. A leaked process would be visible as a hung test run.
        at_exit { session.close }
        session
      end
    end

    # @return [Cli::Session]
    def session = self.class.session

    # Builds a filter, failing the test if the build itself failed.
    #
    # @param spec [FilterSpec]
    # @param keys [Array<String>]
    # @param params [Hash]
    # @return [Cli::Handle]
    def build(spec, keys, **params)
      session.build(spec.id, keys, **params)
    end

    # Asserts a filter has no false negatives over its own member set.
    #
    # The one absolute guarantee, and the check every other membership
    # assertion is built on. The failure message names the offending key and
    # its index, following `external/vqf/src/main.cc`, which prints the value
    # and index on its first failure — because "some key of ten million failed"
    # is not a debuggable message.
    #
    # @param handle [Cli::Handle]
    # @param oracle [Oracle]
    # @param context [String] what was being tested, for the failure message
    # @return [AuditReport]
    def assert_no_false_negatives(handle, oracle, context: "")
      report = oracle.audit(handle, oracle.members)

      assert(
        report.sound?,
        "#{handle.id} lost a member#{context.empty? ? "" : " (#{context})"}\n" \
        "  #{report.false_negative_message}"
      )

      report
    end
  end
end
