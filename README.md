# luce-crypto

Native Luce Base cryptography with an owning Luce API. MIT OR Apache-2.0.
Provides byte-oriented incremental SHA-256/384/512, HMAC, HKDF, parallel Argon2id
and experimental owned secret buffers. No foreign cryptographic engine or subprocess is a runtime
dependency. Keyed APIs are not yet approved for real credential custody.

```luce
from crypto import Hasher, digest

let state = Hasher("sha256")
state.update(b"package ")
state.update(b"source")
let result = state.digest()
print(result.hexdigest())
state.close()
```

Manifest package identity is `luce_crypto`; exports are `crypto` and
`crypto_native`. Add a relative `[dependencies] luce_crypto = "../luce-crypto"`
entry to the current `luce.toml`. A registry installer is not implemented here.

The native `crypto_native.make_hash()` returns pointer-free value state.
`update(bytes)` borrows input only until return. `digest(output)` snapshots the
state, writes exactly 32/48/64 bytes and leaves any tail unchanged. Repeated
digests and further updates are allowed. Copying native state creates an independent
branch; no cloning allocator is needed. `reset()` retains the algorithm; `close()`
is idempotent and subsequent operations fail. Zero-initialized state is closed.
The high-level facade returns owning `Digest` objects with `bytes()` and
`hexdigest()`; Luce obtains retained byte/string values across subsequent disposal.
Base callers must release owning `interop.Reference` results explicitly.

Each state is single-owner/single-thread at a time. Independent instances can run
on separate workers; do not share a mutable state or a Luce ownership carrier
between threads. Updates are synchronous and proportional to input length; callers
control scheduling by feeding bounded chunks. This is not automatic parallelism
inside one SHA-2 message, a deadline, or an asynchronous cancellation API.

Native hashing has fixed storage and no heap allocation. Byte counts reject
messages outside the algorithm's bit-length range before mutation. Outputs must
not alias the native state; native input must not alias that mutable state either.
The one-shot native digest may overlap input/output because reading finishes first.
Only byte-aligned inputs are supported. Unsupported algorithm names fail closed.

## Security status

Experimental, not security-reviewed or certified. These unkeyed hashes do not
authenticate a publisher without a separately trusted expected digest/signature.
Do not invent a MAC by prefixing a key, or use SHA-2 as a password KDF.
Native `close()` now uses volatile stores on the exact owned buffer/hash storage.
That does **not** erase other copies, compiler spills/registers, swap or core dumps.
The pinned native compiler ignores `noinline`; the package does not treat it as a
security barrier. Functional tests and retained assembly are not independent
security/side-channel review. Experimental ChaCha20-Poly1305 / XChaCha20-Poly1305, FIPS 202 SHAKE128/256,
FIPS 204 ML-DSA-65, SHA-1 (Git object IDs only), and ECDSA P-256
(verify, sign, keygen) are implemented. Argon2id
cost calibration, hardened custody, side-channel review and TLS remain required
infrastructure work. No production keys or credentials are created.
See [keyed APIs and memory limits](docs/KEYED.md).
See [Argon2id APIs, admission budgets and cancellation](docs/ARGON2ID.md).

## Tests

Sibling compiler sources are pinned in `bootstrap/BASE` and `bootstrap/LUCE`.
They are read-only inputs; generated builds stay under this repository's ignored
`build/` directory. Supported test hosts: macOS arm64 and Linux x86_64.

```sh
python3 tools/bootstrap.py
python3 tests/run.py
python3 tests/sanitize.py
python3 tests/check_hashes.py build/native3/driver build/native3/file-driver --full
python3 tests/check_argon.py build/native3/argon-driver --full
python3 tools/codegen_probe.py
```

Or supply `--base /path/to/luce-base --luce /path/to/luce` to `tests/run.py`.
The runner builds and executes dedicated X25519 and P-256 vector programs in
all six modes; these programs are also included in sanitizer and prebuilt-bundle
checks. They cover RFC 7748 scalar multiplication/Diffie–Hellman, RFC 6979
verification/public-key derivation, and P-256 signing/tampering. They are not a
side-channel audit. Compiler caches default to `build/cache` (`LUCE_CACHE` can
override this).
See [validation](docs/VALIDATION.md) for measured scope and exclusions, and
[provenance](NOTICE.md) for standards and unchanged NIST fixtures.
The committed Argon2id fixture can additionally be regenerated/verified against
the pinned test-only reference as described in [Argon2id validation](docs/ARGON2ID_VALIDATION.md).
