#!/usr/bin/env python3
"""Test-only hashlib BLAKE2b and RFC 9106 H' differential oracle."""
from collections import Counter
import hashlib
from pathlib import Path
import random
import struct
import sys
import tempfile
from check_hashes import checked, ROOT

MAGIC = b"LCBLK01\0"


def expand(data, length):
    if not 1 <= length <= 0xffffffff:
        raise ValueError("H' output size")
    encoded = struct.pack("<I", length) + data
    if length <= 64:
        return hashlib.blake2b(encoded, digest_size=length).digest()
    rounds = (length + 31) // 32 - 2
    value = hashlib.blake2b(encoded).digest()
    chunks = [value[:32]]
    for _ in range(1, rounds):
        value = hashlib.blake2b(value).digest()
        chunks.append(value[:32])
    chunks.append(hashlib.blake2b(value, digest_size=length - 32 * rounds).digest())
    return b"".join(chunks)


def cases():
    # RFC 7693 Appendix A's unkeyed BLAKE2b-512 example.
    official = bytes.fromhex(
        "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
        "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923")
    assert hashlib.blake2b(b"abc").digest() == official
    yield 1, b"abc", official, "rfc7693"
    rng = random.Random(76939106)
    for size in range(1, 65):
        for length in (0, 1, 3, 63, 64, 127, 128, 129, 255, 256, 257, 1024):
            data = rng.randbytes(length)
            yield 1, data, hashlib.blake2b(data, digest_size=size).digest(), "blake2b"
    for length in (4097, 65536):
        data = rng.randbytes(length)
        yield 1, data, hashlib.blake2b(data).digest(), "blake2b"
    for length in (0, 1, 72, 124, 128, 1024):
        data = rng.randbytes(length)
        for size in (1, 4, 31, 32, 33, 63, 64, 65, 66, 95, 96, 97, 127, 128, 129, 1024, 65536):
            yield 2, data, expand(data, size), "hprime"


def check_blake(driver):
    counts, corpus, batches = Counter(), hashlib.sha256(), 0
    with tempfile.TemporaryDirectory(prefix="luce-crypto-blake-") as temporary:
        source = Path(temporary) / "batch.bin"
        records = []
        def run_batch():
            nonlocal batches
            payload = MAGIC + struct.pack("<I", len(records)) + b"".join(records)
            source.write_bytes(payload)
            try:
                result = checked([Path(driver).resolve(), source])
                assert result.stdout.endswith(f"PASS blake batch {len(records)}\n".encode())
            except BaseException:
                fingerprint = hashlib.sha256(payload).hexdigest()
                print(f"FAIL blake batch={batches} sha256={fingerprint}", flush=True)
                try:
                    saved = ROOT / "build/failures"
                    saved.mkdir(parents=True, exist_ok=True)
                    (saved / f"blake-{fingerprint}.bin").write_bytes(payload)
                except OSError as error:
                    print(f"REPRO_UNAVAILABLE {error}", flush=True)
                raise
            corpus.update(payload)
            batches += 1
            records.clear()
        for identity, (kind, data, expected, group) in enumerate(cases()):
            records.append(struct.pack("<III", identity, kind, len(data)) + data + struct.pack("<I", len(expected)) + expected)
            counts[group] += 1
            if len(records) == 64:
                run_batch()
        if records:
            run_batch()
    assert counts == {"rfc7693": 1, "blake2b": 770, "hprime": 102} and batches == 14
    print(f"PASS independent blake: {dict(counts)} batches={batches} corpus_sha256={corpus.hexdigest()} python={sys.version.split()[0]}", flush=True)


if __name__ == "__main__":
    check_blake(sys.argv[1])
