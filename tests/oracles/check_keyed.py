#!/usr/bin/env python3
"""RFC KATs and independent Python HMAC/HKDF differential oracle, test-only."""
from collections import Counter
import hashlib
import hmac
from pathlib import Path
import random
import struct
import sys
import tempfile
from check_hashes import checked, ROOT, ALGORITHMS
from rfc_keyed import HMAC_INPUTS, HMAC_TAGS, HKDF

MAGIC = b"LCKEY01\0"


def derive(algorithm, source, salt, info, length):
    size = hashlib.new(algorithm).digest_size
    if not 0 <= length <= 255 * size: raise ValueError("HKDF length")
    key = hmac.digest(salt or bytes(size), source, algorithm)
    blocks, previous = [], b""
    for number in range(1, (length + size - 1) // size + 1):
        previous = hmac.digest(key, previous + info + bytes([number]), algorithm)
        blocks.append(previous)
    return key, b"".join(blocks)[:length]


def cases():
    for algorithm in ALGORITHMS:
        assert len(HMAC_TAGS[algorithm]) == len(HMAC_INPUTS) == 7
        for (key, data), hexadecimal in zip(HMAC_INPUTS, HMAC_TAGS[algorithm]):
            expected = bytes.fromhex(hexadecimal)
            full = hmac.digest(key, data, algorithm)
            assert full[:len(expected)] == expected, "Python disagrees with RFC 4231"
            yield 1, algorithm, key, data, b"", full, b"", "rfc_hmac"
        rng = random.Random(19520002)
        for key_length in (0, 1, 20, 63, 64, 65, 127, 128, 129, 131, 255, 1024):
            key = rng.randbytes(key_length)
            for length in (0, 1, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 256, 4097):
                data = rng.randbytes(length)
                yield 1, algorithm, key, data, b"", hmac.digest(key, data, algorithm), b"", "generated_hmac"
        count = hashlib.new(algorithm).digest_size
        for key_length in (0, 1, 22, 64, 129):
            key = rng.randbytes(key_length)
            for length in (0, 1, 31, 32, 33, 47, 48, 49, 63, 64, 65, 127, 128, 129, 255 * count):
                salt = rng.randbytes(key_length)
                info = rng.randbytes(length % 133)
                prk, okm = derive(algorithm, key, salt, info, length)
                yield 2, algorithm, key, salt, info, prk, okm, "generated_hkdf"
    for source, salt, info, length, prk, okm in HKDF:
        expected = bytes.fromhex(prk), bytes.fromhex(okm)
        assert derive("sha256", source, salt, info, length) == expected, "Python disagrees with RFC 5869"
        yield 2, "sha256", source, salt, info, *expected, "rfc_hkdf"


def encode(identity, case):
    kind, algorithm, *fields, group = case
    del group
    return struct.pack("<III", identity, kind, int(algorithm[3:])) + b"".join(
        struct.pack("<I", len(field)) + field for field in fields)


def check_keyed(driver):
    counts, corpus, batches = Counter(), hashlib.sha256(), 0
    with tempfile.TemporaryDirectory(prefix="luce-crypto-keyed-") as temporary:
        source = Path(temporary) / "batch.bin"
        records = []
        def run_batch():
            nonlocal batches
            payload = MAGIC + struct.pack("<I", len(records)) + b"".join(records)
            assert len(payload) <= 16777216
            source.write_bytes(payload)
            try:
                result = checked([Path(driver).resolve(), source])
                assert result.stdout.endswith(f"PASS keyed batch {len(records)}\n".encode())
            except BaseException:
                fingerprint = hashlib.sha256(payload).hexdigest()
                print(f"FAIL keyed batch={batches} sha256={fingerprint}", flush=True)
                try:
                    saved = ROOT / "build/failures"
                    saved.mkdir(parents=True, exist_ok=True)
                    (saved / f"keyed-{fingerprint}.bin").write_bytes(payload)
                except OSError as error:
                    print(f"REPRO_UNAVAILABLE {error}", flush=True)
                raise
            corpus.update(payload)
            batches += 1
            records.clear()
        for identity, case in enumerate(cases()):
            records.append(encode(identity, case))
            counts[case[-1]] += 1
            if len(records) == 64: run_batch()
        if records: run_batch()
    print(f"PASS independent keyed: {dict(counts)} batches={batches} corpus_sha256={corpus.hexdigest()} python={sys.version.split()[0]}", flush=True)


if __name__ == "__main__": check_keyed(sys.argv[1])
