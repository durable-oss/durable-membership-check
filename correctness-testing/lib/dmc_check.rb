# frozen_string_literal: true

# Correctness tests for the durable-membership-check filter implementations.
#
# The Rust crates carry their own unit tests. This suite is separate on purpose:
# it drives the filters through the `dmc-cli` binary, from outside the language
# they are written in, using an oracle and key generators written independently
# of the code under test. A bug in the Rust hash cannot hide itself from a test
# whose keys were generated in Ruby.
#
# # How the suite finds filters
#
# Nothing here lists implementations by name. `dmc-cli list` reports every
# filter linked into the binary along with the capabilities it declares, and the
# tests iterate that. Adding an implementation in Rust — registering it with
# `register_filter!` and declaring what it guarantees — extends this suite with
# no edits here.
#
# # Layout
#
#   lib/dmc_check/generators.rb  key generators, all seeded and deterministic
#   lib/dmc_check/oracle.rb      ground truth and the audit report
#   lib/dmc_check/tolerance.rb   statistical bounds
#   lib/dmc_check/cli.rb         the transport to dmc-cli
#   lib/dmc_check/filter_spec.rb one implementation as the suite sees it
#   test/                        the checks themselves, one file per plan area
#
# See PLANS/correctness-tests/ for what each area covers and where the ideas
# came from.
module DmcCheck
end

require_relative "dmc_check/hex"
require_relative "dmc_check/crc32c"
require_relative "dmc_check/encodings"
require_relative "dmc_check/generators"
require_relative "dmc_check/oracle"
require_relative "dmc_check/tolerance"
require_relative "dmc_check/tiers"
require_relative "dmc_check/cli"
require_relative "dmc_check/filter_spec"
require_relative "dmc_check/conformance_test"
