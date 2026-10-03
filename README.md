# luce-crypto

Native Luce Base cryptography with an owning Luce API. MIT OR Apache-2.0.
Provides byte-oriented incremental SHA-224/256/384/512, HMAC, HKDF, parallel
Argon2id, AES-GCM, ChaCha20-Poly1305, X25519, P-256 ECDH/ECDSA, P-384 and RSA
signature verification, ML-DSA-65 and experimental owned secret buffers. No foreign cryptographic engine or subprocess is a runtime
dependency. Keyed APIs are not yet approved for real credential custody.

```luce
from luce_crypto.crypto import Hasher, digest

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
security/side-channel review.

### What is constant-time

"Constant-time" below means: in the Luce source, no branch and no memory
index depends on secret data. Nobody has audited the machine code the six
compiler modes produce, so this is a source-level property only.

| Primitive | Secret data | Status | Reference |
| --- | --- | --- | --- |
| AES-128/192/256, GCM, GHASH | key, plaintext | constant-time (bitsliced S-box, carry-less multiply with holes) | BearSSL `aes_ct64`, `ghash_ctmul64` |
| ChaCha20, Poly1305 | key, plaintext | constant-time (add/rotate/xor; masked final reduction) | RFC 8439, BearSSL `chacha20_ct`, `poly1305_ctmul` |
| X25519 | private scalar | constant-time ladder with masked swap, fixed inversion chain | BearSSL `ec_c25519_m31` |
| P-256 ECDH, keygen, ECDSA signing | private key, nonce | constant-time: masked 2-bit window, constant-time table scan for the fixed-base 4-bit window, branch-free field and scalar arithmetic, fixed-exponent inversion | BearSSL `ec_p256_m31` |
| ECDSA P-256 nonces | private key | deterministic RFC 6979 (no dependence on RNG quality) | BearSSL `ecdsa_i31_sign_raw` |
| SHA-1/2, HMAC, HKDF | key | constant-time (no data-dependent branches) | FIPS 180-4, RFC 2104/5869 |
| ECDSA P-256/P-384 verification | none | variable-time (public data) | |
| RSA PKCS#1 v1.5 / PSS verification | none | variable-time Montgomery exponentiation (public data) | BearSSL `rsa_i31_*_vrfy`, OpenSSL `rsa_pss.c` |
| P-384 | none | verification only; variable-time | |

RSA is verification only (`rsa_verify_pkcs1`, `rsa_verify_pss`; SHA-1/224/256/384/512;
separate MGF1 hash; fixed or recovered salt length; moduli from a caller-chosen
minimum, 2048 bits by default, to 8192). There is no RSA signing, decryption,
P-384 ECDH or P-384 signing. SHA-1 is kept for legacy RSA/ECDSA verification
vectors and Git object IDs; TLS 1.3 does not use it.

### Validation

Every in-scope primitive is checked against independent references; each
test program prints its counts and asserts them, so a vector cannot be
skipped silently. Converters regenerate all committed vector files.

| Primitive | Sources (cases) |
| --- | --- |
| SHA-1/224/256/384/512, HMAC, HKDF | NIST CAVP SHA ShortMsg/LongMsg; BearSSL test_crypto.c KATs incl. million-a, byte-by-byte and split-and-copy (42); Wycheproof hmac_sha256/384/512, hkdf_sha256/384 complete (691); OpenSSL evpmd_sha/evpmac/evpkdf_hkdf (48); RFC 4231/5869 via Python oracle |
| AES, AES-GCM | BearSSL AES block (387), Monte Carlo (3), CTR (9), GHASH (16 + 1025 lengths against a bit-serial GHASH), GCM with tamper and truncation (18); Wycheproof aes_gcm complete (316); NIST CAVP gcmEncryptExtIV/gcmDecrypt, 3 of 15 cases per parameter set committed (9641; all 47,250 run locally with `tools/cavp_vectors.py --full`); OpenSSL GCM (173) |
| ChaCha20, Poly1305, ChaCha20-Poly1305 | BearSSL KATs at every prefix length (3 + 1); RFC 8439 Appendix A (23); Wycheproof chacha20_poly1305 complete (325); OpenSSL evpciph_chacha (27) |
| X25519 | BearSSL KATs + 1000-iteration chain; RFC 7748 §5.2 and §6.1 (the 1,000,000-iteration chain with `x25519-kat <dir> full`, 336 s, run locally); Wycheproof x25519 complete (518); OpenSSL evppkey_ecx (15) |
| P-256/P-384 points, P-256 ECDH | BearSSL EC KATs, carry cases, 20 multiply-add identity rounds, keygen checks; Wycheproof ecdh_secp256r1 and _ecpoint complete (967); OpenSSL evppkey_ecdh P-256 (16) |
| ECDSA P-256/P-384 | BearSSL RFC 6979 KATs incl. deterministic P-256 signing (20); Wycheproof ecdsa_secp256r1_sha256/sha512 and ecdsa_secp384r1_sha256/sha384/sha512, DER and P1363, complete (3748); NIST CAVP SigVer P-256/P-384 (150); OpenSSL evppkey_ecdsa and _rfc6979 (64) |
| RSA verification | BearSSL public-op, PKCS#1 and PSS KATs (64) and 491 modpow inputs; Wycheproof rsa_signature 2048/3072/4096/8192 x SHA-256/384/512 and 17 RSASSA-PSS files complete (5432); OpenSSL evppkey_rsa/_rsa_common verification (86) |

Out of scope, by source (each is counted by its test program):

- BearSSL: MD5 hashing and HMAC/HKDF over MD5 or SHA-1 (no SHA-1 HMAC); AES
  decryption and AES-CBC (TLS 1.3 needs neither); P-521 (curve not
  implemented); RFC 6979 signing with SHA-1 (needs HMAC-SHA-1); the
  incremental HMAC "out then continue" and HKDF streaming APIs (this API is
  one-shot); GCM tags of 1-3, 5-7 or 9-11 bytes (refused: SP 800-38D); the
  cross-implementation Poly1305/GHASH checks are replaced by round trips and a
  bit-serial GHASH; RSA private-key operations (verification only).
- Wycheproof: x25519 ASN.1/JWK/PEM key-format files, ecdh webcrypto/PEM files
  and SHA-3/SHAKE/SHA-512-truncated hash variants (not implemented); RSA
  sig_gen, OAEP and PKCS#1 encryption files (verification only). "Acceptable"
  cases are run: X25519 must produce the listed value; ECDH refuses compressed
  and unusual encodings; PKCS#1 refuses DigestInfo without NULL parameters.
- NIST CAVP SigVer: curves other than P-256/P-384 (975 cases).
- OpenSSL: see `tests/vectors/openssl/SUMMARY.txt` (other hashes, MACs,
  ciphers and curves, signing and decryption, FIPS-provider policy checks,
  RSASSA-PSS keys with embedded parameters, keys generated at run time).
- IETF: the RFC 7748 million-iteration chain is not in CI (runtime).

Argon2id
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
The runner builds and executes every vector program in all six modes and under
the sanitizers (see Validation above). Vector files live under `tests/vectors/`
and are regenerated from local reference checkouts (kept out of the
repository) by `tools/bearssl_vectors.py`, `tools/wycheproof.py`,
`tools/openssl_vectors.py`, `tools/rfc_vectors.py` and `tools/cavp_vectors.py`;
each directory records the SHA-256 of its sources. The tests are not a
side-channel audit. Compiler caches default to `build/cache` (`LUCE_CACHE` can
override this).
See [validation](docs/VALIDATION.md) for measured scope and exclusions, and
[provenance](NOTICE.md) for standards and unchanged NIST fixtures.
The committed Argon2id fixture can additionally be regenerated/verified against
the pinned test-only reference as described in [Argon2id validation](docs/ARGON2ID_VALIDATION.md).
