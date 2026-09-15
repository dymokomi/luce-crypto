# luce-crypto

Native Luce Base cryptography with an owning Luce API. MIT OR Apache-2.0.
This first implementation provides byte-oriented, incremental SHA-256, SHA-384
and SHA-512. No foreign cryptographic engine or subprocess is a runtime dependency.

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
`close()` is logical disposal, **not** a proven non-elidable secret wipe. State
snapshots, runtime copies and timing/generated-code behavior have not been audited
for secrets. HMAC/HKDF, Argon2id, AEAD, signatures, secure ownership and TLS are
still required infrastructure work. No production keys or credentials are created.

## Tests

Sibling compiler sources are pinned in `bootstrap/BASE` and `bootstrap/LUCE`.
They are read-only inputs; generated builds stay under this repository's ignored
`build/` directory. Supported test hosts: macOS arm64 and Linux x86_64.

```sh
python3 tools/bootstrap.py
python3 tests/run.py
python3 tests/sanitize.py
python3 tests/check_hashes.py build/native3/driver build/native3/file-driver --full
```

Or supply `--base /path/to/luce-base --luce /path/to/luce` to `tests/run.py`.
See [validation](docs/VALIDATION.md) for measured scope and exclusions, and
[provenance](NOTICE.md) for standards and unchanged NIST fixtures.
