# Keyed APIs and secret-memory boundary

Experimental, not independently reviewed. All algorithms are native Luce Base.
Python/C reference crypto is test-only; OS entropy and allocation are existing
Base standard-library facilities. HKDF is not a password-hardening algorithm.

```luce
from crypto import secret_from_bytes, Hmac, hkdf

let key = secret_from_bytes(b"public test key, not a real credential")
let mac = Hmac(key, "sha256")
mac.update(b"package metadata")
let tag = mac.finish()
let derived = hkdf(key, b"salt", b"protocol-specific context", 32)
derived.close()
key.close()
```

## Contracts

- Algorithms are exactly `sha256`, `sha384`, `sha512`. Unsupported names fail.
- `Hmac(key: Secret, algorithm)` absorbs the key during construction. Closing the
  original key afterward does not invalidate the HMAC. `update` borrows its input
  until return. `finish()` returns an owning public `Digest` and consumes the HMAC.
  `verify(expected)` consumes it too, including on mismatch/wrong tag length.
  Verification requires the complete 32/48/64-byte tag; no prefix acceptance.
- Native `make_hmac(bytes, algorithm)` returns a handle with `size`, `update`,
  `finish(output)`, `verify(tag)`, `close`. A short output leaves state/output
  unchanged. Successful finish/verify closes/frees the context. Copies of this
  handle borrow; they are not independent owners and must not be closed twice.
  Do not replace the native heap allocator during a handle's lifetime.
- One-shot `authenticate(key, input, algorithm)` returns a high-level `Digest`;
  native `authenticate(key_bytes, input, output, algorithm)` returns bytes written.
  HMAC output may overlap key/input because both are consumed before output.
- `hkdf(Secret, salt, info, length, algorithm)` returns a **Secret**, not a public
  digest/hex string. Native `hkdf(input, salt, info, output, algorithm)` fills a
  caller-owned span. `hkdf_extract` and `hkdf_expand` are also native exports.
  Length is 0–255×HashLen inclusive; expand requires PRK length at least HashLen.
  Empty salt follows RFC 5869. All native input/output overlap is rejected before
  mutation, including overlap with unused output tail. After validation, an
  unexpected expand error wipes its output span. Work is synchronous and bounded
  by caller inputs, not an asynchronous scheduling/latency guarantee.
- `secret_from_bytes` copies the caller's bytes into a native owned allocation.
  The caller's original bytes remain its responsibility. `random_secret(length)`
  uses OS entropy; partial entropy failure wipes/releases the allocation and
  returns an error, without fallback randomness. Length is 0–65,536 inclusive.
- A Luce `Secret` exposes `length`, full-byte `matches`, explicit `reveal`, `close`.
  `reveal` crosses into ordinary managed bytes: that copy can outlive close and
  is **not erased by closing the Secret**. There is no implicit bytes/hex accessor.
  Avoid `reveal` for real keys. Native secret handles expose borrowed `bytes` and
  `writable`; their custom allocator is retained and must outlive the handle.
- Native `Hash.finish(output)` is consuming; `digest(output)` remains a snapshot.
  Short output fails before mutation. Hash copies remain independent value state;
  HMAC deliberately uses consuming finalization, not secret-derived snapshots.
- Each owner is single-threaded; independent instances work on separate workers.
  Do not transfer a Luce ownership carrier between threads. Native handle copies
  and returned spans do not prolong allocation lifetime. Base callers release
  owning `interop.Reference` results explicitly.

## What erasure and comparison do—and do not—mean

`secure.wipe` writes each byte through a volatile pointer. `Hash.close` wipes its
exact state representation and then sets a non-secret closed marker. Hash message
schedules, HMAC padded key/intermediate buffers, HKDF PRK/previous blocks and owned
secret byte allocations are explicitly wiped on their normal/error cleanup paths.
HMAC contexts are closed before free. Allocation tests inspect secret bytes before
the underlying allocator receives them, including constructor/unwind failures.

This does not establish erasure of all temporary scalar values, compiler-generated
copies/registers/spills, allocator/runtime bookkeeping, GC-managed copies, OS swap,
crash dumps or device memory. No page locking/guard-page facility is claimed.
`close` cannot protect secrets already exposed by callers or by memory disclosure.

The equality primitive reads all bytes at equal public lengths and accumulates
XOR differences; unequal public lengths return false immediately. This source
structure alone is not a cross-target constant-time guarantee. The byte selector
is a bitwise blend (0/255 select entire bytes), package-local and not a protocol.

The pinned native backend's `noinline` violation is reproducible in
`tests/noinline_repro.lucb`. Native levels 0–3 inline the +17 callee into `main`;
the C backend preserves the attribute. Do not rely on this attribute as an erasure
or timing barrier. Detailed language audit is kept separately in the parent
workspace, with no edits to the language repositories.

`tools/codegen_probe.py` retains bodies using test-only function pointers and
emits four native and C -O0/-O2/-O3 assembly variants. Its automated assertions
check body retention and generated C volatile qualifiers, **not** instruction
dataflow or constant time. Address-taking is a probe aid, not a production fix.
Manual review, full-library/helper/call-site analysis, side-channel evaluation and
independent security review remain gates before real authentication/key custody.
