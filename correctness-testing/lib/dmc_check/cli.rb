# frozen_string_literal: true

require "json"
require "open3"

module DmcCheck
  # Drives the `dmc-cli` binary.
  #
  # Two transports, matching the CLI's two modes. {Session} keeps a process
  # alive and speaks newline-delimited JSON over its pipes; {.one_shot} spawns a
  # process per command. The statistical checks need the former — a million
  # probes through a million process spawns is not a test, it is a weekend.
  #
  # Keys cross the boundary as hex, because keys are arbitrary bytes and JSON
  # strings are not. Callers pass and receive Ruby byte strings; this class
  # handles the encoding.
  module Cli
    # Raised when the binary cannot be found, dies, or answers something that
    # is not JSON. Distinct from a filter reporting an error, which is a normal
    # response with `ok: false`.
    class TransportError < StandardError; end

    # Where the compiled binary lives.
    #
    # Overridable with DMC_CLI so a release build or a cross-compiled binary can
    # be exercised without editing anything.
    #
    # @return [String]
    def self.binary_path
      ENV["DMC_CLI"] || File.expand_path("../../../target/debug/dmc-cli", __dir__)
    end

    # Verifies the binary exists and reports how to build it if not.
    #
    # Called once at suite startup. A missing binary is the single most likely
    # first-run failure, and "No such file or directory" does not tell anyone
    # what to do about it.
    #
    # @raise [TransportError] if the binary is absent or not executable
    # @return [void]
    def self.assert_available!
      path = binary_path
      return if File.executable?(path)

      raise TransportError, <<~MESSAGE
        dmc-cli not found at #{path}

        Build it first:
            cargo build -p dmc-cli

        Or point DMC_CLI at an existing binary:
            DMC_CLI=/path/to/dmc-cli rake test
      MESSAGE
    end

    # Runs a single command in a fresh process.
    #
    # Convenient for one-off metadata queries. Do not use it in a loop; that is
    # what {Session} is for.
    #
    # @param request [Hash] a command, keys as symbols or strings
    # @return [Hash] the parsed reply, with string keys
    def self.one_shot(request)
      assert_available!

      out, err, status = Open3.capture3(binary_path, "serve", stdin_data: "#{JSON.generate(request)}\n")

      line = out.lines.first
      raise TransportError, "dmc-cli produced no output (exit #{status.exitstatus}): #{err}" if line.nil?

      parse(line)
    end

    # Parses one reply line.
    #
    # @param line [String]
    # @return [Hash]
    def self.parse(line)
      JSON.parse(line)
    rescue JSON::ParserError => e
      raise TransportError, "dmc-cli replied with something that is not JSON: #{line.inspect} (#{e.message})"
    end

    # A long-lived `dmc-cli serve` process.
    #
    # Filters persist across commands under integer handles, so a test builds
    # once and probes as many times as it likes. The process is reaped by
    # {#close}; {Session.open} does that for you.
    class Session
      # Starts a session.
      #
      # @yieldparam session [Session]
      # @return [Object] whatever the block returns
      def self.open
        session = new
        begin
          yield session
        ensure
          session.close
        end
      end

      def initialize
        Cli.assert_available!

        @stdin, @stdout, @stderr, @thread = Open3.popen3(Cli.binary_path, "serve")
        @closed = false
      end

      # Sends a command and reads the reply.
      #
      # @param request [Hash]
      # @return [Hash] the parsed reply
      # @raise [TransportError] if the process died
      def call(request)
        raise TransportError, "session is closed" if @closed

        @stdin.puts(JSON.generate(request))
        @stdin.flush

        line = @stdout.gets
        if line.nil?
          # The process exited without replying. Its stderr is the only clue.
          leftover = begin
            @stderr.read
          rescue IOError
            ""
          end
          raise TransportError, "dmc-cli exited mid-session: #{leftover}"
        end

        Cli.parse(line)
      end

      # Sends a command and raises unless it succeeded.
      #
      # For the majority of calls, where a failure means the test is broken
      # rather than that the filter misbehaved.
      #
      # @param request [Hash]
      # @return [Hash]
      def call!(request)
        response = call(request)
        return response if response["ok"]

        raise TransportError,
              "dmc-cli reported #{response["kind"]}: #{response["message"]} (request: #{request.inspect})"
      end

      # Lists every linked implementation with its capabilities.
      #
      # @return [Array<Hash>]
      def list
        call!(cmd: "list").fetch("filters")
      end

      # Describes one implementation by exact id or family alias.
      #
      # @param name [String]
      # @return [Hash]
      def describe(name)
        call!(cmd: "describe", name: name).fetch("filter")
      end

      # Builds a filter and returns a handle onto it.
      #
      # @param name [String] exact id or family alias
      # @param keys [Array<String>] member keys as byte strings
      # @param params [Hash] any of :expected_items, :false_positive_rate, :seed
      # @return [Handle]
      def build(name, keys, **params)
        response = call!(
          cmd: "build",
          name: name,
          keys_hex: Hex.encode_all(keys),
          params: Session.encode_params(params)
        )

        Handle.new(self, response.fetch("handle"), response.fetch("info"))
      end

      # Attempts a build, returning the raw reply whether or not it succeeded.
      #
      # Used by the tests that drive error paths on purpose.
      #
      # @return [Hash]
      def try_build(name, keys, **params)
        call(
          cmd: "build",
          name: name,
          keys_hex: Hex.encode_all(keys),
          params: Session.encode_params(params)
        )
      end

      # Rewrites non-finite rates as the keywords the CLI accepts.
      #
      # JSON has no way to write NaN or an infinity as a number, and
      # `Params::validate` rejects all three by name. Sending them as keywords
      # is what makes that validation reachable from a test at all.
      #
      # @param params [Hash]
      # @return [Hash]
      def self.encode_params(params)
        rate = params[:false_positive_rate]
        return params unless rate.is_a?(Float)

        keyword =
          if rate.nan? then "nan"
          elsif rate == Float::INFINITY then "inf"
          elsif rate == -Float::INFINITY then "-inf"
          end

        keyword ? params.merge(false_positive_rate: keyword) : params
      end

      # Decodes bytes into a filter, returning the raw reply.
      #
      # @param bytes [String] a byte string
      # @return [Hash]
      def try_decode(bytes)
        call(cmd: "decode", bytes_hex: Hex.encode(bytes))
      end

      # Decodes bytes into a filter, raising on failure.
      #
      # @param bytes [String]
      # @return [Handle]
      def decode(bytes)
        handle_from(call!(cmd: "decode", bytes_hex: Hex.encode(bytes)))
      end

      # Wraps a reply that produced a new filter.
      #
      # @param response [Hash] a successful reply carrying "handle" and "info"
      # @return [Handle]
      def handle_from(response)
        Handle.new(self, response.fetch("handle"), response.fetch("info"))
      end

      # Ends the session and reaps the process.
      #
      # @return [void]
      def close
        return if @closed

        @closed = true

        begin
          @stdin.puts(JSON.generate(cmd: "quit"))
          @stdin.flush
        rescue Errno::EPIPE, IOError
          # Already gone; nothing to ask it.
        end

        [@stdin, @stdout, @stderr].each do |io|
          io.close
        rescue IOError
          nil
        end

        @thread&.join
      end
    end

    # A filter living inside a {Session}.
    #
    # Wraps the handle so callers work with an object rather than an integer,
    # and carries the accounting reported at build time.
    class Handle
      # @return [Integer] the id the filter was built under
      attr_reader :id

      # @return [Integer] how many keys it was built from
      attr_reader :len

      # @return [Integer] bytes in the backing store
      attr_reader :memory_bytes

      # @return [Float] estimated false positive rate as built
      attr_reader :false_positive_rate

      # @return [Boolean] whether it holds no keys
      attr_reader :empty

      def initialize(session, handle, info)
        @session = session
        @handle = handle
        @id = info.fetch("id")
        @len = info.fetch("len")
        @memory_bytes = info.fetch("memory_bytes")
        @false_positive_rate = info.fetch("false_positive_rate")
        @empty = info.fetch("is_empty")
      end

      # @return [Boolean]
      def empty? = @empty

      # Tests membership for one key.
      #
      # Prefer {#contains_all} in a loop-shaped test: one round trip for many
      # keys is dramatically faster than many round trips for one.
      #
      # @param key [String] a byte string
      # @return [Boolean]
      def contains?(key)
        contains_all([key]).first
      end

      # Tests membership for many keys in one round trip.
      #
      # @param keys [Array<String>] byte strings
      # @return [Array<Boolean>] one answer per key, in order
      def contains_all(keys)
        return [] if keys.empty?

        @session.call!(
          cmd: "contains",
          handle: @handle,
          keys_hex: Hex.encode_all(keys)
        ).fetch("answers")
      end

      # Re-reads the accounting fields from the filter itself.
      #
      # Distinct from the attributes, which are a snapshot from build time. The
      # round-trip tests compare the two.
      #
      # @return [Hash]
      def info
        @session.call!(cmd: "info", handle: @handle).fetch("info")
      end

      # Encodes the filter to bytes.
      #
      # @return [String] a byte string
      def encode
        Hex.decode(@session.call!(cmd: "encode", handle: @handle).fetch("bytes_hex"))
      end

      # Combines this filter with another into one holding both key sets.
      #
      # @param other [Handle]
      # @return [Handle]
      def union(other)
        @session.handle_from(@session.call!(cmd: "union", left: @handle, right: other.raw))
      end

      # Combines this filter with another into one holding their overlap.
      #
      # @param other [Handle]
      # @return [Handle]
      def intersect(other)
        @session.handle_from(@session.call!(cmd: "intersect", left: @handle, right: other.raw))
      end

      # Attempts a union, returning the raw reply whether or not it succeeded.
      #
      # For the tests that combine deliberately incompatible filters.
      #
      # @param other [Handle]
      # @return [Hash]
      def try_union(other)
        @session.call(cmd: "union", left: @handle, right: other.raw)
      end

      # Attempts an intersection, returning the raw reply.
      #
      # @param other [Handle]
      # @return [Hash]
      def try_intersect(other)
        @session.call(cmd: "intersect", left: @handle, right: other.raw)
      end

      # Estimates how many distinct keys the filter holds.
      #
      # Distinct from {#len}, which counts the keys it was *built* from. The two
      # disagree after a union, and whenever the input contained duplicates.
      #
      # @return [Integer]
      def estimated_len
        @session.call!(cmd: "estimated_len", handle: @handle).fetch("estimated_len")
      end

      # Estimates how alike this filter's key set is to another's.
      #
      # @param other [Handle]
      # @return [Hash] with "jaccard", "containment_left_in_right",
      #   and "containment_right_in_left"
      def similarity(other)
        @session.call!(cmd: "similarity", left: @handle, right: other.raw)
      end

      # The underlying integer handle.
      #
      # Needed by the two-operand commands, which name their operands by number.
      #
      # @return [Integer]
      def raw = @handle

      # Releases the filter.
      #
      # @return [void]
      def release
        @session.call(cmd: "drop", handle: @handle)
        nil
      end
    end
  end
end
