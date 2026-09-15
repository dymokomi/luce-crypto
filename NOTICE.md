# Provenance

Original Luce Base SHA-2/HMAC/HKDF and memory implementation, Copyright 2026 Dy Mokomi,
MIT OR Apache-2.0. No C/C++/Rust cryptographic engine is included or linked.

Algorithm definitions and numeric constants: NIST FIPS 180-4 (August 2015),
sections 4–6, https://doi.org/10.6028/NIST.FIPS.180-4.

`tests/vectors/*.rsp` are unmodified NIST CAVP public byte-oriented SHA-256,
SHA-384 and SHA-512 ShortMsg/LongMsg response files, downloaded September 15,
2026 UTC from:
https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip

Original ZIP SHA-256:
`929ef80b7b3418aca026643f6f248815913b60e01741a44bba9e118067f4c9b8`.
Individual original-byte hashes are retained in `tests/vectors/SHA256SUMS`.
The NIST files are US government test data, separately attributed rather than
claimed as original project source. They are test-only data, not an engine.
Informal use of these vectors is **not** NIST/CAVP/FIPS certification.

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
