# Correctness testing

A Ruby suite that drives every registered filter through the `dmc-cli` binary.

The Rust crates carry their own unit tests. This is separate on purpose: it
tests the filters from outside the language they are written in, with key
generators and a membership oracle written independently of the code under
test. A bug in the Rust hash cannot hide itself from keys generated in Ruby.

Implements [`PLANS/correctness-tests/`](../PLANS/correctness-tests/), which
records what each area covers and where each idea came from.

## Running

```sh
cd correctness-testing
rake              # builds dmc-cli, then runs the suite
rake slow         # includes the larger size tiers and probe counts
rake filters      # lists what the suite will run against, with capabilities
```

Or directly, against a binary you have already built:

```sh
cargo build -p dmc-cli
cd correctness-testing
ruby -Ilib -Itest test/invariants_test.rb
```

`DMC_CLI` overrides the binary path, so a release build or a cross-compiled
binary can be exercised without editing anything:

```sh
cargo build --release -p dmc-cli
DMC_CLI=../target/release/dmc-cli rake test
```

## The suite discovers filters; it does not list them

Nothing here names an implementation. `dmc-cli list` reports every filter linked
into the binary along with the capabilities it declares, and the tests iterate
that.

Adding a filter in Rust — implementing `Filter`, registering it with
`register_filter!`, declaring what it guarantees — extends this suite with no
edits here. The new implementation immediately faces every universal check, plus
whichever capability-gated checks its declaration turns on.

That is what the capability metadata is for. A test written as

```ruby
for_each_filter_with "achieves the rate it was asked for", :honors_target_fpr? do |spec|
```

runs against a Bloom filter, and skips with a stated reason against an xor
filter, whose rate follows from its fingerprint width rather than from the
request. Neither outcome needs a table of special cases in the test.

### Declaring a new filter's capabilities

In the Rust registration. Start from the strictest setting and opt out of each
axis that genuinely diverges, saying why:

```rust
dmc_core::register_filter! {
    family: "xor",
    version: 1,
    description: "Xor filter built by hypergraph peeling.",
    capabilities: dmc_core::Capabilities::strict()
        // Peeling fails on a repeated key rather than absorbing it.
        .without_duplicate_tolerance()
        // Construction visits keys in input order.
        .without_order_independence()
        // The rate follows from the fingerprint width, not from the request.
        .without_target_fpr(),
    build: XorFilter::build_boxed,
    decode: XorFilter::decode_boxed,
}
```

Opting out is deliberate, and the direction matters. A filter that declares
nothing gets the most demanding suite, so a forgotten declaration fails loudly
rather than quietly testing less. An axis silently defaulting to "not tested"
would be the worst of both.

An opt-out is not always a skip. Where the negative case has content, the suite
asserts it instead: a filter declaring `tolerates_duplicate_keys: false` is
tested to reject duplicates with `ConstructionFailed`, because silently building
a filter with false negatives is the worst possible outcome.

## Layout

| Path | Contents |
|---|---|
| `lib/dmc_check/cli.rb` | Transport to `dmc-cli`, both one-shot and session modes |
| `lib/dmc_check/crc32c.rb` | CRC-32C, written independently of the Rust one it checks |
| `lib/dmc_check/encodings.rb` | The header layout, for tests that hand-build hostile input |
| `lib/dmc_check/generators.rb` | Key generators, all seeded and deterministic |
| `lib/dmc_check/oracle.rb` | Ground truth and the audit report |
| `lib/dmc_check/tolerance.rb` | Statistical bounds |
| `lib/dmc_check/tiers.rb` | Size tiers and the slow-test gate |
| `lib/dmc_check/filter_spec.rb` | One implementation as the suite sees it |
| `lib/dmc_check/conformance_test.rb` | The capability-aware minitest base class |
| `test/golden/` | Byte-exact encodings that pin the frozen-implementation promise |

Test files map to plan areas: `invariants_test.rb` is area 020,
`statistical_test.rb` is 030, `adversarial_keys_test.rb` is 040,
`serialization_test.rb` is 050, `registry_test.rb` is 060,
`determinism_test.rb` is 070, `concurrency_test.rb` is 090.

`harness_test.rb` tests the harness itself, which is not vanity — see below.

## How it talks to the filters

`dmc-cli serve` reads one JSON command per line and writes one reply per line.
Filters persist across commands under integer handles, so a test builds once and
probes a hundred thousand times in one process. Spawning a process per probe
would make the statistical tests unusable.

Keys cross as hex, because keys are arbitrary bytes and JSON strings are not. A
key containing a NUL, a lone `0xFF`, or an invalid UTF-8 sequence arrives
unchanged — and those are exactly the keys worth testing.

Errors are replies, not exceptions. Sending an out-of-range parameter and
reading back `{"ok":false,"kind":"invalid_parameter"}` is how the error paths
get tested at all.

## Determinism

Every generator is a pure function of its arguments. No system clock, no
`SecureRandom`, no unseeded `Random.new`. A statistical failure that cannot be
replayed from the test output is a failure nobody can fix — and
`determinism_test.rb` greps the suite's own source to enforce it.

Both reference implementations this suite draws from fail that rule.
`external/vqf` seeds from `RAND_bytes` and `external/binfuse` seeds `mt19937_64`
from `random_device`, so neither can reproduce its own rate failures.

### Seed shopping is fabrication

Choosing a seed because the test passes under it fabricates a result. The rule:
pick the seed first — a constant, or the plan step number — then derive the
tolerance from the math. If a fixed-seed statistical test fails, the fix is to
investigate the filter, not to try seed 43.

If a seed is genuinely a known-bad outlier, that gets its own test recording
why, not a silent swap.

## Bounds, not thresholds

A test asserting an exact false positive rate flakes. A test with a tolerance
pulled out of the air either flakes or catches nothing. Both failure modes are
visible in the references: `external/binfuse/test/filter.cpp` asserts
`fpr <= 0.005` against a nominal 0.0039 — a 28% margin with no derivation, which
passes a filter meaningfully worse than advertised and would not catch a slow
regression.

Every rate assertion here derives its bound from the trial count, so the bound
tightens as the test does more work. At 100,000 probes and a 1% target the
three-sigma bound allows 1.9% above expectation; at a million probes, 0.9%.

## Testing the harness

`harness_test.rb` exists because harness bugs produce filter failures that are
not filter failures — and, worse, filter successes that are not successes. Two
happened while this suite was being written:

- The probe mixer clamped a requested 25% member fraction to 5%, and the
  found-probability sweep reported the resulting mismatch as a Bloom defect.
- A grep meant to catch unseeded RNGs matched its own documentation.

Plan step 010.030.050 makes the general point: a harness that silently produces
a 0.6 mix when asked for 0.5 will report rates that are wrong in a direction
nobody notices.

## Slow tiers

The default run uses 1,000-key filters and 100,000 probes. `DMC_SLOW_TESTS=1`
raises those to 100,000 keys and 1,000,000 probes.

Gated on an environment variable rather than a build flag: a flag would leak
into the dependency graph and change what gets compiled, while reading the
environment keeps the fast path fast without a second build configuration. A
skipped tier prints a notice, so a run that covered half the suite does not look
like one that covered all of it.

## What this suite has found

Recorded because a suite that has never caught anything is a suite nobody should
trust:

- **A decoder accepting `len = u64::MAX`.** `usize::try_from` only rejects
  counts overflowing a 32-bit target; on 64-bit it passed `u64::MAX` through,
  decoding into a filter claiming eighteen quintillion keys in an eight-byte
  array. Fixed by bounding `len` against the bit count, with a Rust regression
  test alongside.

- **Seed corruption was undetectable. Fixed.** Flipping any bit of the
  eight-byte seed field left a structurally perfect encoding — every length,
  version, and bound validated — that decoded into a filter answering
  differently, including `false` for keys that were inserted. All eight seed
  bytes plus one capacity byte, confirmed, and unchanged across the header
  format rewrite.

  Closed by a CRC-32C over the whole encoding (plan step 050.030.010). The test
  that documented the gap now asserts the opposite: every single-bit flip
  anywhere in the encoding is rejected. Castagnoli's polynomial gives Hamming
  distance 6 at these lengths, so 1-, 2-, and 3-bit errors are caught with
  certainty rather than probability.

  What it does not fix, and the tests say so: clearing a bit in the bit array
  still yields a valid encoding of a smaller key set. The bytes *are* the data.
  The gain is that such an encoding refuses to load rather than silently losing
  members.

- **The header format rewrite, immediately.** When the encoding changed from a
  NUL-terminated id string to a fixed 73-byte binary header, the golden test
  failed with the exact bytes that differed and the exact reason it matters.
  That is the frozen-implementation guard doing its job: it cannot tell a
  deliberate format change from an accidental one, so it reports both and leaves
  the judgment to a person.
