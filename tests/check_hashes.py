#!/usr/bin/env python3
"""NIST byte KATs + deterministic hashlib oracle. Test tooling, never runtime."""
import hashlib
from pathlib import Path
import random
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ALGORITHMS = ("sha256", "sha384", "sha512")
MAGIC = b"LCSHA01\0"


def vectors(path):
    fields = {}
    for line in path.read_text(encoding="ascii").splitlines():
        if not line or line.startswith(("#", "[")):
            continue
        key, value = line.split(" = ")
        assert key in ("Len", "Msg", "MD") and key not in fields
        fields[key] = value
        if key == "MD":
            assert set(fields) == {"Len", "Msg", "MD"}
            bits = int(fields["Len"])
            assert bits >= 0 and bits % 8 == 0
            message = bytes.fromhex(fields["Msg"])
            if bits == 0:
                assert message == b"\0"
                message = b""
            assert len(message) == bits // 8
            yield message, bytes.fromhex(fields["MD"])
            fields = {}
    assert not fields


def cases():
    for algorithm in ALGORITHMS:
        for group in ("ShortMsg", "LongMsg"):
            for message, expected in vectors(ROOT / f"tests/vectors/{algorithm.upper()}{group}.rsp"):
                assert hashlib.new(algorithm, message).digest() == expected, "oracle disagrees with NIST"
                yield algorithm, message, expected, "nist"
        rng = random.Random(19520001)
        for length in [*range(258), 511, 512, 513, 1023, 1024, 1025, 4095, 4096, 4097, 65535, 65536, 65537]:
            for message in (bytes([0xff]) * length, rng.randbytes(length)):
                yield algorithm, message, hashlib.new(algorithm, message).digest(), "generated"
        for message in (b"abc", b"a" * 1000000, bytes(range(256)) * 4096):
            yield algorithm, message, hashlib.new(algorithm, message).digest(), "generated"


def checked(command, timeout=90):
    result = subprocess.run([str(arg) for arg in command], capture_output=True, timeout=timeout)
    assert result.returncode == 0, (result.returncode, result.stdout[-2048:], result.stderr[-4096:])
    for marker in (b"AddressSanitizer", b"UndefinedBehaviorSanitizer", b"runtime error:"):
        assert marker not in result.stderr, result.stderr[-4096:]
    return result


def check(driver):
    counts = {"nist": 0, "generated": 0}
    corpus = hashlib.sha256()
    batches = 0
    with tempfile.TemporaryDirectory(prefix="luce-crypto-vectors-") as temporary:
        source = Path(temporary) / "batch.bin"
        records = []

        def run_batch():
            nonlocal batches
            payload = MAGIC + struct.pack("<I", len(records)) + b"".join(records)
            assert len(payload) <= 16777216
            source.write_bytes(payload)
            try:
                result = checked([Path(driver).resolve(), source])
                assert result.stdout.endswith(f"PASS batch {len(records)}\n".encode())
            except BaseException:
                fingerprint = hashlib.sha256(payload).hexdigest()
                print(f"FAIL batch={batches} sha256={fingerprint}", flush=True)
                try:
                    saved = ROOT / "build/failures"
                    saved.mkdir(parents=True, exist_ok=True)
                    (saved / f"{fingerprint}.bin").write_bytes(payload)
                except OSError as error:
                    print(f"REPRO_UNAVAILABLE {error}", flush=True)
                raise
            corpus.update(payload)
            batches += 1
            records.clear()

        for identity, (algorithm, message, expected, group) in enumerate(cases()):
            prefix = hashlib.new(algorithm, message[:len(message) // 2]).digest()
            record = struct.pack("<III", identity, int(algorithm[3:]), len(message)) + message + expected + prefix
            if records and (len(records) == 128 or sum(map(len, records)) + len(record) > 8 * 1024 * 1024):
                run_batch()
            records.append(record)
            counts[group] += 1
        if records: run_batch()
    print(f"PASS independent SHA-2: {counts} batches={batches} corpus_sha256={corpus.hexdigest()} python={sys.version.split()[0]}", flush=True)


def check_files(driver, full=False):
    lengths = [0, 32767, 32768, 32769, 1048577]
    if full: lengths += [32 * 1024 * 1024 + 3]
    with tempfile.TemporaryDirectory(prefix="luce-crypto-files-") as temporary:
        path = Path(temporary) / "source.bin"
        chunk = bytes(range(256)) * 128
        for length in lengths:
            oracles = [hashlib.new(name) for name in ALGORITHMS]
            left = length
            with path.open("wb") as stream:
                while left:
                    data = chunk[:min(left, len(chunk))]
                    stream.write(data)
                    for oracle in oracles: oracle.update(data)
                    left -= len(data)
            for algorithm, oracle in zip(ALGORITHMS, oracles):
                result = checked([Path(driver).resolve(), algorithm, path])
                assert result.stdout == f"OK {length} {oracle.hexdigest()}\n".encode(), result.stdout
    print(f"PASS {len(lengths) * 3} independent bounded file-stream hashes", flush=True)


if __name__ == "__main__":
    check(sys.argv[1])
    if len(sys.argv) > 2: check_files(sys.argv[2], full="--full" in sys.argv)
