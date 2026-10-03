# Provenance

Original Luce Base SHA-2/HMAC/HKDF/BLAKE2b/Argon2id and memory implementation, Copyright 2026 Dy Mokomi,
MIT OR Apache-2.0. No C/C++/Rust cryptographic engine is included or linked.

Algorithm definitions and numeric constants: NIST FIPS 180-4 (August 2015),
sections 4–6, https://doi.org/10.6028/NIST.FIPS.180-4.

Build/test/bootstrap/bundle scaffolding follows the MIT OR Apache-2.0
`dymokomi/luce-compress` and `dymokomi/luce-pkg-server` patterns by the same author.
HMAC is implemented from RFC 2104; HKDF from RFC 5869. Numeric input/output facts
in `tests/rfc_keyed.py` come from RFC 4231 section 4 (SHA-256/384/512 cases 1–7)
and RFC 5869 appendix A.1–A.3 (SHA-256). These fixtures are separately attributed;
no RFC prose, implementation code or foreign engine is included. RFC 4231 case 5
provides a truncated prefix, checked against the full independent oracle tag.

Standards: https://www.rfc-editor.org/rfc/rfc2104.html,
https://www.rfc-editor.org/rfc/rfc4231.html,
https://www.rfc-editor.org/rfc/rfc5869.html.

Python `hashlib`/`hmac` are independent development-test oracles only. The Base/Luce
toolchains and their existing runtime/OS bindings remain separate dependencies.

Sequential unkeyed BLAKE2b follows RFC 7693; Argon2id version 0x13, its variable
length H' and numeric known-answer/intermediate-state facts follow RFC 9106.
Standards: https://www.rfc-editor.org/rfc/rfc7693.html and
https://www.rfc-editor.org/rfc/rfc9106.html (section 5.3).
The upstream Argon2 reference's indexing and compression were inspected as a
cross-check: https://github.com/P-H-C/phc-winner-argon2/tree/20190702/src.
No upstream implementation source or RFC prose is copied into this package.

SHAKE128/SHAKE256 follow FIPS 202; ML-DSA-65 follows FIPS 204. Independent
known-answer checks use Python hashlib for SHAKE and OpenSSL 3.6 ML-DSA-65
(`hexseed` key generation and `pkeyutl` signatures) as test-only oracles.
No OpenSSL, liboqs or pqcrystals object is linked into production builds.
NTT zeta constants match the public Dilithium reference table for q=8380417;
they are field elements specified by FIPS 204, not copied engine source.

AES (FIPS 197) and AES-GCM (NIST SP 800-38D) are original Luce code whose
bitsliced structure follows Thomas Pornin's BearSSL (MIT license,
https://www.bearssl.org/): `aes_ct64.c`/`aes_ct64_enc.c` (orthogonalization,
round functions and key schedule) and `ghash_ctmul64.c` (carry-less multiply
with holes). The S-box is the Boyar–Peralta circuit,
https://eprint.iacr.org/2009/191. No BearSSL source is included.
BearSSL copyright notice: Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>,
permission granted under the MIT license.

RSA verification follows RFC 8017 (§8.1.2, §8.2.2, §9.1.2, §9.2, §B.2.1); the
Montgomery multiplication is the CIOS method (Koç, Acar, Kaliski 1996).

X25519 (RFC 7748) is original Luce code whose field representation and ladder
follow BearSSL `ec_c25519_m31.c` (MIT, Copyright (c) 2016 Thomas Pornin); it
replaces an earlier port of the public-domain TweetNaCl routine.

P-256 is original Luce code whose point layer (Jacobian formulas, 2-bit
variable-base window with masked selection, 4-bit fixed-base window with a
constant-time table scan) follows BearSSL `ec_p256_m31.c` (MIT, Copyright (c)
2016 Thomas Pornin); `src/luce_crypto/p256_table.lucb` is recomputed from the
curve constants by `tools/p256_table.py`. ECDSA nonces follow RFC 6979 §3.2,
as BearSSL's `ecdsa_i31_sign_raw` does. Verification uses a joint two-bit
window (Straus); P-384 multiplication uses CIOS Montgomery products.

RSA verification checks follow BearSSL `rsa_i31_pkcs1_vrfy.c`/`rsa_i31_pss_vrfy.c`
and OpenSSL `crypto/rsa/rsa_pss.c` (`RSA_verify_PKCS1_PSS_mgf1`); the
exponentiation reuses a per-key Montgomery context and computes R^2 mod n
from R mod n by doublings and Montgomery squarings.

## Test data

The test vectors (NIST CAVP SHA-2, GCM and ECDSA files, Project Wycheproof,
BearSSL `test_crypto.c` known answers, OpenSSL EVP test data, RFC 8439/7748
vectors and the Argon2id fixture) are not part of this package. They live in
https://github.com/dymokomi/luce-crypto-vectors at the revision pinned in
`bootstrap/PACKAGES`; its NOTICE.md gives each source's license, revision,
retrieval date and checksums. The converters in `tools/` and the test oracles
in `tests/` are part of this package.
