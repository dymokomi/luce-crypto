# SHA-2 foundation validation

This is the historical unkeyed checkpoint. See [keyed validation](KEYED_VALIDATION.md)
for the subsequent HMAC/HKDF/owned-secret work and its separately scoped evidence.

Verified source `e779ff103c70af345fb639a2940b6564e761444a`, September 15, 2026 UTC.
No milestone-completion or security-review claim.

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

## Hosted and isolated second-host results

[CI 34934494281](https://github.com/dymokomi/luce-crypto/actions/runs/34934494281)
passed on both Linux x86_64 (Ubuntu 24.04, 2m41s) and macOS arm64 (macos-15,
2m4s). Both hosts freshly bootstrapped the pinned compilers, passed all six modes,
four harness tests, ASan/UBSan and all 18 extended file-stream cases. Downloaded
logs show the same 2,272-case corpus digest in every mode and sanitizer run on
Python 3.14.7; this was inspected rather than inferred from a green job summary.

The CI Linux archive SHA-256 is
`425cdf1fd09f9d4705d082dbd224e05c2cac41037ba2f4c2b96cea7d07a713be`.
Verified locally and after upload: 20 unique allowlisted regular members (four
binaries, three scripts, seven fixture/hash files, four license/provenance files,
revision and hash manifest); 19 per-file hashes and exact source revision. No
symlink/hardlink/path-traversal entries, compiler installation or live data.

The existing Ubuntu 24.04 x86_64 VPS passed the four harness tests and complete
prebuilt quick suite on Python 3.12.3: native/Luce API and eight independent workers,
643 NIST + 1,629 generated cases (same corpus digest), and 15 file-stream cases.
The 32 MiB extended profile ran locally/in CI, not on the VPS.

VPS result: success, exit 0, 12.397 seconds elapsed / 3.106 seconds CPU, under
unchanged 180-second, 25%-CPU, 512-MiB/no-swap and 64-task caps. Dynamic unprivileged
user, private network/tmp, read-only inputs/host, protected home/live applications,
no capabilities and idle I/O. These are whole-suite observations, not throughput,
latency or capacity guarantees. No public listener or credentials were created.

The exact temporary stage was removed after validating its revision and inactive,
collected unit. All 32 running services, Caddy PID/activation/configuration hash and
the existing site's HTTPS 200/ETag/content length matched the pre-test baseline.
Removed inputs can be reproduced from the retained public test bundle. Ignored
evidence lives under `build/ci-34934494281/`; no live access material is published.

## Remaining gates

Limits: no bit-oriented inputs, CAVP Monte Carlo suite, >4 GiB real stream test,
ThreadSanitizer, exhaustive fuzzing, formal verification, side-channel or generated
code audit, secret-wipe guarantee, hardware acceleration, FIPS certification or
independent security review. Synthetic maximal counters test arithmetic/encoding,
not actual exabyte-length messages. Native fixed storage is not a process RSS bound.
M1b and prerequisite M0 remain incomplete; this is a hashing dependency checkpoint,
not auth, TLS, signatures, a working registry or the final `luc` journey.
