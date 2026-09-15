# Native keyed foundation validation

September 15, 2026 UTC. This checkpoint adds native HMAC-SHA-256/384/512, HKDF,
owned secret buffers, consuming hash finalization and an owning Luce API.
It does not complete M0/M1b or authorize real credentials. The older SHA-2
checkpoint's CI/VPS evidence is separate in [validation history](VALIDATION.md).

## Test scope

The six-mode runner (native 0–3, C-debug and C-release) and generated-Base-C
ASan/UBSan retain all 2,272 SHA-2 oracle cases and 15 quick file-stream cases.
New gates are:

- 21 RFC 4231 HMAC cases: seven input pairs for each supported SHA-2 variant.
  Case 5 checks the official 128-bit prefix and the independent Python full tag;
  it does not establish a truncated-verification API.
- 504 generated HMAC cases covering empty/short/block-boundary/oversized keys
  through 1,024 bytes and input/padding boundaries through 4,097 bytes. Each checks
  whole-buffer results, several chunkings, empty updates, key/input overwrite
  after borrowing, short-output retry, canaries and consuming verification with
  correct, changed-first/middle/last-byte and truncated tags.
- Three RFC 5869 SHA-256 vectors, plus 225 independent HKDF cases across all
  algorithms. Checks both combined derivation and separate extract/expand, exact
  PRK/OKM, empty parameters, output/block boundaries and 255-block maximum.
- Native secret/state lifecycle, canaries, invalid algorithms and KDF lengths,
  short PRK/output, overlapping input/salt/info/output and unchanged rejected
  output; consuming hash finish; equality mismatches at every position of a
  256-byte input; whole-byte selector masks; eight independent 512 KiB-stack
  workers using HMAC/HKDF and OS entropy.
- Allocator-observed secret zeroing before release for lengths 1, 73 and 65,536,
  empty buffers, explicit-close idempotence, allocation refusal, copied-input
  independence and injected entropy failure after writing 37 of 73 bytes.
  Real OS entropy tests establish call success/ownership, not randomness quality.
- 24 systematic heap-failure paths: native HMAC allocation, all three owning
  Secret creation/HKDF allocations, and two HMAC result allocations, with both
  one-shot and persistent refusal. Exact pointer/size/live-block ledger; 15 owned
  73-byte secret releases inspected for zeroing; retry after failed HMAC finish;
  invalid algorithms, negative/excessive high-level lengths and closed references.
  No global-heap interception runs concurrently with worker tests.
- Real Luce consumer retains previous hash tests and adds Secret ownership,
  explicit revealed-copy survival, HMAC/RFC tags after closing the original key,
  consuming verification, RFC HKDF bytes and random-secret ownership.
- Seven keyed harness tests: RFC agreement, case counts, exact corpus fingerprint,
  record encoding, corrupted RFC rejection, HKDF bounds, failure-batch retention
  and read-only failure diagnostics. Four original SHA-2 harness tests remain.

Keyed corpus: 753 records, 12 batches; SHA-256
`f803e4371704a49259ed7499364a4460ac88474b435a1f52f2f6eff41401a500`.
Only public test inputs are retained in failed batches. Harness temporary files
are scoped and removed. Native runtime libraries do not depend on Python or its
crypto backend.

## Generated code and exclusions

`tools/codegen_probe.py` retains the wipe/equality/selector/dead-buffer bodies in
four native and C -O0/-O2/-O3 variants, with compiler pin and assembly hashes. The
automatic gate asserts generated C volatile qualifiers and body retention only.
Local arm64 native-opt-3 inspection shows zero byte stores, bytewise XOR/OR
comparison and a retained dead-buffer wipe call. Local compiled C retains the
wipe/dead-buffer call too; its comparison includes a runtime conversion helper.
All four native noinline reproducers contain the +17 computation in `main`.

This is not whole-library/call-site/helper timing analysis, a constant-time
guarantee or proof that all copies, registers/spills and temporary scalar values
are erased. No mlock/guard-page/swap/core-dump guarantees, TSan, statistical
side-channel testing, exhaustive fuzzing, formal verification, certification or
independent security review. ASan/UBSan instruments Base-emitted C/runtime and
native use of owning facades, not the actual Luce-generated consumer's C.
See [API/security boundaries](KEYED.md) before interpreting any passing test.

## Evidence status

Final local macOS arm64 replay passed all six modes, all eleven harness tests,
the complete SHA-2/keyed/native/owning/failure/worker suites and ASan/UBSan. Logs:
ignored `build/final-keyed-correctness.log` and `build/final-keyed-sanitize.log`.
The separate extended native-opt-3 SHA-2 file suite passed all 18 cases through
32 MiB + 3 bytes (`build/keyed-extended.log`). Python 3.14.6; compiler pins remain
unchanged. Generated-code probe passed; observations are under `build/codegen/`
and `build/codegen.log`. Neither language repository was modified.
Hosted Linux/macOS and isolated VPS results for this keyed checkpoint are pending;
older SHA-2 results must not be attributed to this source.
