# Golden encodings

One pair of files per registered implementation:

- `<id>.bin` — the encoded filter, byte for byte
- `<id>.json` — the inputs that produced it, plus the answers it gives

These exist to enforce one sentence from `lib/dmc-core/src/lib.rs`:

> once published, which keys it accepts and rejects never changes

Without checked-in bytes that promise is unenforceable. With them, any change to
hashing, sizing, probe derivation, or the payload layout fails
`determinism_test.rb` immediately and loudly.

## What is recorded

`probe_positives` is the valuable part. It lists the indices, within a fixed
probe set of 2,000 non-member keys, that the filter reports as present — that
is, its **false positives**. Those pin the exact behavior rather than only the
membership guarantee. Two filters can both find every member while disagreeing
on every false positive; only the recorded positives catch that.

The key set and probe set are not stored. Both are regenerated from the seed
recorded in the JSON, which is why every generator in `lib/dmc_check/` is a pure
function of its arguments.

## When regenerating is legitimate

Adding a **new implementation id**. That is the only case.

A new id has no golden yet, so the test writes one and skips with a notice.
Review the generated files and commit them.

## When regenerating is not legitimate

**Because a test failed.** A golden mismatch means the implementation changed
what it accepts and rejects. That is a frozen-implementation violation, and the
fix is to publish the change as a new version id — `bloom_002`, not an updated
`bloom_001.bin`.

Regenerating to make the suite pass converts a caught violation into a silent
one. It is the bug, not the fix.

Two exceptions, both requiring the change to be deliberate and reviewed:

- The implementation was never published, so nothing depends on its behavior yet.
- A behavior-preserving change to the *encoding format* under a bumped
  `PAYLOAD_VERSION`, where the old version stays decodable. In that case the
  decode test (`070.030.030`) must keep passing against the old bytes.

## Regenerating

Delete the pair and run the suite:

    rm correctness-testing/test/golden/bloom_001.*
    cd correctness-testing && rake test

The test writes fresh files and skips with a notice naming what it wrote.
Deleting by hand is deliberate on purpose: there is no `--regenerate` flag to
reach for reflexively when a test goes red.

## Size

A few hundred keys per filter, so the files stay in the low kilobytes. The point
is behavioral pinning, not scale coverage — the size tiers in
`lib/dmc_check/tiers.rb` handle scale. A golden corpus that grew to hundreds of
megabytes would be a self-inflicted problem, particularly on a volume that has
already hit 100% during this project.
