# Argon2id and password-derived keys

Experimental native Luce Base RFC 9106 Argon2id version 0x13. The BLAKE2b hash,
H' expansion, memory matrix, indexing, compression and scheduling are implemented
in Base. Existing Base memory/thread/OS bindings provide platform services; no
foreign cryptographic engine or subprocess implements the algorithm at runtime.
This is a primitive, not a credential vault, PHC password database, account proof
or encryption format. Do not use it for real credentials before independent review.

## Luce API

This example uses intentionally tiny **test-only** costs and public test data:

```luce
from crypto import Argon2id, secret_from_bytes

let password = secret_from_bytes(b"password")
let configuration = Argon2id(32, 2, 4, 32, 4)
let result = configuration.derive(password, b"somesalt")
password.close()
configuration.close()
assert(result.length() == 32)
result.close()
```

Constructor arguments: `memory_kib`, `passes`, `lanes`, optional `length=32`,
optional `workers=1`. Costs must be explicitly supplied. Lanes are part of the
cryptographic input; worker count only changes scheduling. A result does not
retain its password/configuration owner. It is an owning `Secret`, with no
implicit hexadecimal rendering. `reveal()` explicitly produces a managed copy;
closing the Secret does not erase that copy. Base users release returned
`interop.Reference` values explicitly; the Luce bridge manages these carriers.

`derive(password, salt, associated=b"")` supports associated data. The advanced
`derive_keyed(password, key, salt, associated=b"")` also accepts Argon2's optional
secret K, as a separate `Secret`. Empty passwords/keys/associated data are valid.
Salt must contain at least eight bytes: this is the API/reference-library minimum,
not an additional RFC 9106 requirement. Actual vault designs should generate a
distinct random 16-byte salt, authenticate all cost/version metadata with the
ciphertext, and calibrate costs for their environment. None of those vault choices
is silently made by this primitive.

Negative/overflowing costs, invalid salt/length, and closed owners fail before
allocating the result/matrix. A configuration retains no password/key. `close()`
is idempotent and subsequent derivation fails. Do not mutate/close a configuration
or input owner during a call; do not share Luce ownership carriers across workers.

## Native API and admission

`crypto_native.argon2id(password, salt, output, parameters, key=b"",
associated=b"", workers=1, limits=Argon2Limits(), cancellation=none)` derives into
caller-owned bytes. `Argon2Parameters(memory_kib=..., passes=..., lanes=...)` has
invalid zero costs, not password-hardening defaults. `Argon2Limits` defaults are
admission ceilings, **not recommended Argon2 parameters**:

| Resource | Default ceiling |
| --- | --- |
| Requested memory | 262,144 KiB (256 MiB) |
| Passes / lanes | 32 / 64 |
| Requested memory × passes | 2,097,152 KiB-passes |
| Each input | 1,048,576 bytes |
| Output | 65,536 bytes |

Native callers can explicitly supply different ceilings. RFC width constraints,
`memory_kib >= 8 * lanes`, output length >=4 and platform allocation arithmetic
are still checked. Supported tested hosts are 64-bit macOS arm64/Linux x86_64.
Maximum-width arithmetic tests do not constitute multi-terabyte allocation tests.
High-level Luce currently uses the default ceilings. There is no PHC parser or
implicit fallback to weaker costs, another algorithm or a foreign implementation.

Workers must be 1–8; the actual number of concurrent execution groups is
`min(workers, lanes)`, including the calling thread. Requested m is hashed and
budgeted; allocated m' is rounded down to a multiple of `4 * lanes`. Different
requests that round to the same allocation still produce different tags.
No result bytes are written until computation succeeds. Inputs may overlap output
because they have all been read before final output; none is retained after return.
The caller must keep all input/output/cancellation storage alive and not mutate
inputs during the call. Mutable state/control objects must not alias those buffers.

Admission is per call, not aggregate server capacity. The eventual server/CLI
must budget concurrent calls and queue expensive work. An isolated successful KDF
does not establish a safe public request rate or deadline.

## Parallelism, cancellation and cleanup

Each pass has four synchronized slices. Independent lanes in a slice are assigned
to bounded worker groups; each group fills its lanes serially. All spawned threads
join before the next slice and before any matrix release, including partial
worker-start failure. Worker stacks are 512 KiB. The current implementation starts
workers per slice; it does not claim a persistent pool or measured speedup for
small matrices. Independent calls do not share mutable algorithm state.

Native `Cancellation.request()` is atomic and may be called from another thread.
Cancellation is observed before allocation, between initial lanes, between slices
and before finalization. The call returns `cancelled` only after joining workers;
output stays unchanged. This is cooperative cancellation, not per-block preemption
or a wall-clock deadline. A request racing the final check may complete normally.

Matrix, seed, serialized final block, BLAKE2b state/message schedules and explicit
compression temporaries are volatile-wiped on normal/error return. The matrix is
wiped before its retained allocator releases it. Allocation/start errors propagate;
no failed derivation is treated as a valid key. Unexpected thread join failure
traps rather than unwinding into a use-after-free while a worker may still run.
Trap/process termination does not promise cleanup or erasure.

Internal allocator/start/after-pass test hooks are not public facade exports.
The process-global `memory.heap` must not change during threaded calls; the tests
intercept the matrix allocator separately and test global allocation failures only
with one worker. Custom allocators/cancellation storage must outlive the call.

The existing `noinline` compiler audit remains open. We do not rely on it as an
erasure barrier. Argon2id includes data-dependent accesses by design. Finite KATs,
sanitizers and retained assembly do not prove constant-time behavior, complete
copy/register/spill erasure, locked memory, swap/core protection or security review.
See [test scope and evidence](ARGON2ID_VALIDATION.md).
