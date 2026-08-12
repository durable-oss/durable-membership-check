# frozen_string_literal: true

require "set"

module DmcCheck
  # Ground truth for membership.
  #
  # Built from the same key slice handed to the filter, it answers `contains?`
  # exactly. Every membership assertion compares filter output against this,
  # never against a hand-maintained list.
  class Oracle
    # @return [Array<String>] the member keys, in insertion order
    attr_reader :members

    # @param members [Array<String>] byte strings
    def initialize(members)
      @members = members.map(&:b)
      @set = @members.to_set
    end

    # @param key [String]
    # @return [Boolean] whether the key was inserted
    def contains?(key)
      @set.include?(key.b)
    end

    # @return [Integer] the number of distinct members
    def distinct_count = @set.size

    # Classifies one filter answer against the truth.
    #
    # @param key [String]
    # @param answer [Boolean] what the filter said
    # @return [Symbol] :true_positive, :false_positive, :true_negative, or :false_negative
    def classify(key, answer)
      truth = contains?(key)

      if truth
        answer ? :true_positive : :false_negative
      else
        answer ? :false_positive : :true_negative
      end
    end

    # Runs a probe set through a filter and tallies the outcomes.
    #
    # Records the first offending key for each error class.
    # `external/vqf/src/main.cc` prints the offending value and index on its
    # first failure; this carries that forward, because "some key of ten
    # million failed" is not a debuggable message.
    #
    # @param handle [Cli::Handle]
    # @param probes [Array<String>]
    # @param batch [Integer] keys per round trip
    # @return [AuditReport]
    def audit(handle, probes, batch: 50_000)
      report = AuditReport.new(probes.length)

      probes.each_slice(batch) do |slice|
        answers = handle.contains_all(slice)

        slice.each_with_index do |key, offset|
          report.record(key, classify(key, answers[offset]), report.total_seen + offset)
        end

        report.advance(slice.length)
      end

      report
    end
  end

  # The tally from {Oracle#audit}.
  class AuditReport
    # @return [Integer]
    attr_reader :true_positives, :false_positives, :true_negatives, :false_negatives

    # @return [Integer] how many probes have been classified so far
    attr_reader :total_seen

    # @return [Hash{Symbol => Array(String, Integer)}] first offender per error class
    attr_reader :first_offenders

    # @param expected_total [Integer]
    def initialize(expected_total)
      @expected_total = expected_total
      @true_positives = 0
      @false_positives = 0
      @true_negatives = 0
      @false_negatives = 0
      @total_seen = 0
      @first_offenders = {}
    end

    # Records one classified probe.
    #
    # @param key [String]
    # @param classification [Symbol]
    # @param index [Integer]
    # @return [void]
    def record(key, classification, index)
      case classification
      when :true_positive then @true_positives += 1
      when :false_positive then @false_positives += 1
      when :true_negative then @true_negatives += 1
      when :false_negative then @false_negatives += 1
      end

      # Keep the first of each error class only. A filter that is broken for
      # every key would otherwise fill memory with offenders.
      if %i[false_positive false_negative].include?(classification)
        @first_offenders[classification] ||= [key, index]
      end
    end

    # Advances the running index after a batch.
    #
    # @param count [Integer]
    # @return [void]
    def advance(count)
      @total_seen += count
    end

    # @return [Integer] probes that were genuine members
    def actual_members = @true_positives + @false_negatives

    # @return [Integer] probes that were not members
    def actual_non_members = @false_positives + @true_negatives

    # The observed false positive rate.
    #
    # Measured against non-members only. Returns 0.0 when the probe set
    # contained no non-members, since a rate over zero trials is undefined and
    # raising here would break the found-probability sweep at 100%.
    #
    # @return [Float]
    def false_positive_rate
      return 0.0 if actual_non_members.zero?

      @false_positives.to_f / actual_non_members
    end

    # The fraction of all probes the filter answered `true` for.
    #
    # The quantity the found-probability sweep predicts as `f + (1-f) * p`.
    #
    # @return [Float]
    def positive_rate
      return 0.0 if @total_seen.zero?

      (@true_positives + @false_positives).to_f / @total_seen
    end

    # Whether the no-false-negative contract held.
    #
    # @return [Boolean]
    def sound? = @false_negatives.zero?

    # A failure message naming the first false negative.
    #
    # @return [String]
    def false_negative_message
      key, index = @first_offenders[:false_negative]
      return "no false negatives" if key.nil?

      "#{@false_negatives} false negative(s) out of #{actual_members} members; " \
        "first at index #{index}: #{Hex.encode(key)} (#{key.inspect})"
    end

    # @return [String]
    def to_s
      format(
        "probes=%d tp=%d fp=%d tn=%d fn=%d fpr=%.6f",
        @total_seen, @true_positives, @false_positives, @true_negatives,
        @false_negatives, false_positive_rate
      )
    end
  end
end
