# SHA-2 foundation validation

First source checkpoint, September 15, 2026 UTC. No milestone-completion or
security-review claim.

Passed locally on macOS arm64 in all six modes (native optimizations 0–3,
C-debug, C-release):

- 643 unmodified NIST byte-oriented short/long-message vectors.
- 1,629 independent `hashlib` cases: every length 0–257, larger block/padding
  boundaries, binary patterns, deterministic random bytes, `abc`, one million `a`
  bytes and a 1 MiB binary message, for SHA-256/384/512.
- Each case checks the whole digest, several input chunkings, empty updates,
  unaligned borrowed buffers with canaries, overwriting input after return,
  an independently expected prefix snapshot, copy/branch and continuation.
- Native API tests: short-output rejection/canaries, repeated snapshots,
  copy/reset/close, unsupported names, synthetic 64/128-bit length boundaries,
  eight independent 512 KiB-stack workers and the owning Base facade.
- Real Luce consumer: known SHA-256 values, incremental API, all algorithms,
  reset/disposal, retained byte/string results.

Corpus SHA-256 `74f7de7389126b01e5d0fe2769b5adb316203930bc17761007e0e599c2c7bcd2`;
Python 3.14.6. This identifies concrete batch bytes, not a guarantee of cross-version
random generation. Failures preserve exact batches when storage permits.

The final public native-facade layout passed all six local modes, generated-C
ASan/UBSan and 15 quick file-stream cases, plus the complete prebuilt runner.
The 18-case extended native-opt-3
file profile passed through 32 MiB + 3 bytes with a fixed 32 KiB input buffer.
Fresh pinned compiler bootstrap passed without modifying either language source.
Four fixture/parser/provenance unit tests pass; original NIST bytes are preserved,
including their CRLF and whitespace, rather than reformatted.

Local logs: `build/final-correctness.log`, `build/final-sanitize.log` and
`build/extended.log` (ignored). Tests used the pinned external compiler binaries;
the separate fresh local bootstrap also passed. CI bootstraps fresh pinned sources.

Pending: Linux/macOS hosted CI and verified read-only isolated VPS bundle.
Tests must pass at the source revision being published;
a pending row is not evidence.

Limits: no bit-oriented inputs, CAVP Monte Carlo suite, >4 GiB real stream test,
ThreadSanitizer, exhaustive fuzzing, formal verification, side-channel or generated
code audit, secret-wipe guarantee, hardware acceleration, FIPS certification or
independent security review. Synthetic maximal counters test arithmetic/encoding,
not actual exabyte-length messages. Native fixed storage is not a process RSS bound.
M1b and prerequisite M0 remain incomplete; this is a hashing dependency checkpoint,
not auth, TLS, signatures, a working registry or the final `luc` journey.
