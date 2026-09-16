# SHAKE and ML-DSA-65

Experimental FIPS 202 SHAKE128/SHAKE256 and FIPS 204 ML-DSA-65. Not
security-reviewed, certified or approved for real credentials.

SHAKE matches Python hashlib empty/`abc`/fox vectors and incremental absorb.
ML-DSA-65 `KeyGen_internal` for the all-zero 32-byte seed matches OpenSSL 3.6
`hexseed` public keys (SHA-256
`085ba380ff386dd52e42349c6eb88489d6058ea541a4e3fb0dce9a3fd1f7a911`).
Deterministic sign/verify round-trips; OpenSSL `pkeyutl` signatures over
`hello` verify in the native implementation. Pure ML-DSA with empty context.

All six local compiler modes and ASan/UBSan pass alongside prior SHA-2, keyed,
Argon2id and AEAD suites. OpenSSL is a test-only oracle, not a runtime engine.

Remaining: HashML-DSA, hedged-vs-deterministic policy tests, malformed
encodings, generated-code/constant-time review, official ACVP corpora and
independent cryptographic review. No production keys.
