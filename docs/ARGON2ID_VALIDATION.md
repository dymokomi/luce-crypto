# Native Argon2id validation

September 15, 2026 UTC. This checkpoint implements the plan's selected password
KDF, not a frozen vault format, calibrated production costs or completed M0/M1b.
Prior SHA-2/keyed source, CI and VPS evidence remains historical in
[SHA-2 validation](VALIDATION.md) and [keyed validation](KEYED_VALIDATION.md).

## New test scope

- BLAKE2b: RFC 7693's `abc` example, 770 independent hashlib cases covering all
  1–64 digest sizes, empty/full/final block and 127/128/129 byte boundaries,
  inputs through 65,536 bytes; multiple incremental chunkings, empty updates,
  overwriting borrowed input, short-output retry, canaries and closed/wiped state.
- H': 102 independent hashlib-composed cases, input lengths 0/1/72/124/128/1024,
  output boundaries through 65,536, and input/output overlap. Synthetic BLAKE2b
  128-bit counter carry/overflow is checked without allocating impossible inputs.
- RFC 9106 section 5.3: prehash, eight published memory words after each of three
  passes and final tag, using 1/2/3/4/8 workers. Secret K and associated data included.
- 138 deterministic pinned-reference fixtures: one RFC, 135 quick, two extended.
  Quick runner performs 493 derivations with 1/2/4/8 workers (single-lane cases
  need only one worker). Lanes 1/2/3/4/7/8/17/64, passes 1/2/3, minimum/rounded
  memory, segment address boundaries 127/128/129/256/257, output sizes 4–65,536,
  empty/binary/block-boundary/65,536-byte inputs and optional K/associated data.
  Every generated expected tag must match both serial and parallel reference runs.
- Nine native allocator/worker paths: successful rounded allocation, refusal,
  cancellation before allocation/from a worker/after a pass, and start failures
  at attempts 1/2/10/36. The allocator observes exact size, zeroed bytes and all
  worker completions before release. Rejected output and surrounding canaries
  stay untouched. No global-heap interception occurs concurrently with workers.
- 26 admission failures, a real rejected-before-allocation call, requested versus
  rounded work budget, maximum-width arithmetic without huge allocation, all four
  input/output overlap forms, and eight independent callers with inner workers.
- Owning facade adds eight one-shot/persistent allocation failures across all four
  allocations (result bytes, matrix, result object, ownership shell); the combined
  keyed harness now has 32 failure paths, 22 observed zeroed 73-byte releases and
  five zeroed matrix releases. Invalid/closed inputs/configuration tests included.
- Real Luce consumer checks reference/RFC keys, optional K/associated data,
  parallel workers, result survival after closing inputs/configuration and explicit
  revealed-copy survival. Six new harness tests guard counts/encodings/fixtures,
  a mutated fixture, saved failure batches and read-only failure diagnostics.

All earlier 2,272 SHA-2 cases, 753 keyed cases, file streams, native lifecycle,
ownership and worker tests remain in the six-mode and sanitizer runners. There
are 17 harness tests in total. ASan/UBSan instruments generated Base C/runtime and
Base callers of owning APIs, not the actual Luce-generated consumer's C.

The extended native-opt-3 runner additionally tests 64 MiB × 3 passes and
256 MiB × 1 pass, four lanes, with 1/2/4/8 workers (eight derivations). These are
correctness/resource cases, not calibrated defaults or evidence of linear scaling.

## Reproduction and fingerprints

```sh
python3 -m venv build/oracle-env
build/oracle-env/bin/python -m pip install --only-binary=:all: -r tests/oracle-requirements.txt
build/oracle-env/bin/python tests/argon_oracle.py
python3 tests/run.py
python3 tests/sanitize.py
python3 tests/check_argon.py build/native3/argon-driver --full
python3 tools/codegen_probe.py
```

Only `argon_oracle.py --write` regenerates the fixture. CI verifies committed
bytes against the independent pinned engine. Ordinary/prebuilt tests need only
the fixture and Python's standard library; no foreign Argon2 engine is deployed
to the VPS. Bundles include all new native binaries, checkers and public fixtures.

- Argon2id JSON SHA-256:
  `3799f3e8b6dd518d8f5e7a694ff961ec2709dfe343c3a934eabbfbd258f5ca21`.
- BLAKE2b/H' corpus: 873 records/14 batches,
  `72dfa4708d20ad600bd5e4ab7a405804eb202680a3fa0cf27802bcbb9752712e`.
- Argon2id quick corpus: 493 derivations/31 batches,
  `d5eb7622bf99ada4a4dec07f46aa56fe8fb4b729e5502b696c24728bb08e156d`.
- Argon2id extended corpus: eight derivations/eight batches,
  `3d952987d98b4cbcfa4274580eca15940b14833080232f64aa53ed90209980cb`.

## Evidence status and exclusions

Final macOS arm64 replay passes all six modes, all 17 harness tests, every old/new
quick suite, generated-C ASan/UBSan, the eight larger-memory Argon2id derivations,
18 extended SHA-2 file cases and the pinned independent reference fixture check.
Logs: ignored `build/final-argon-correctness.log`, `final-argon-sanitize.log`,
`final-argon-extended.log` and `argon-hash-extended.log`. Python 3.14.6; both compiler
source pins are unchanged. This document does not claim hosted CI or VPS success
for this new source yet.

Generated Base C, native-opt-3 and C-O2 Argon2 call-site assemblies are retained
with hashes under ignored `build/codegen`. Local arm64 inspection shows matrix
wiping before allocator release, joins on both success and partial-spawn-error
paths, and seed/final-block cleanup on error returns. This is a scoped observation,
not whole-library/helper dataflow or side-channel review. The existing noinline
defect still reproduces; neither language repository was modified.

Not yet covered: TSan, independent security review, statistical timing analysis,
production KDF calibration/aggregate admission, persistent worker pool, vault/PHC
formats, real-secret custody, locked/guarded memory, comprehensive spill/copy
erasure, physical power loss or cleanup after trapping join/process failure.
The rest of AEAD/signatures/authentication/TLS/registry/CLI acceptance remains open.
