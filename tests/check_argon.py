#!/usr/bin/env python3
"""Compare native binaries with committed pinned-reference fixtures; no C dependency."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import tempfile
from check_hashes import checked, ROOT

FIXTURE = Path(__file__).resolve().parent / "vectors/argon2id.json"
MAGIC = b"LCARG01\0"
FIXTURE_SHA256 = "3799f3e8b6dd518d8f5e7a694ff961ec2709dfe343c3a934eabbfbd258f5ca21"


def load_fixture():
    encoded = FIXTURE.read_bytes()
    assert hashlib.sha256(encoded).hexdigest() == FIXTURE_SHA256, "Argon2id fixture digest"
    fixture = json.loads(encoded)
    assert fixture["format"] == "luce-crypto-argon2id-v1" and fixture["version"] == 19
    assert len(fixture["cases"]) == 138
    assert [case["id"] for case in fixture["cases"]] == list(range(138))
    return fixture


def check_argon(driver, full=False):
    fixture = load_fixture()
    counts, corpus, batches = Counter(), hashlib.sha256(), 0
    with tempfile.TemporaryDirectory(prefix="luce-crypto-argon-") as temporary:
        source = Path(temporary) / "batch.bin"
        records = []
        def run_batch():
            nonlocal batches
            payload = MAGIC + struct.pack("<I", len(records)) + b"".join(records)
            source.write_bytes(payload)
            try:
                result = checked([Path(driver).resolve(), source])
                assert result.stdout.endswith(f"PASS argon batch {len(records)}\n".encode())
            except BaseException:
                fingerprint = hashlib.sha256(payload).hexdigest()
                print(f"FAIL argon batch={batches} sha256={fingerprint}", flush=True)
                try:
                    saved = ROOT / "build/failures"
                    saved.mkdir(parents=True, exist_ok=True)
                    (saved / f"argon-{fingerprint}.bin").write_bytes(payload)
                except OSError as error:
                    print(f"REPRO_UNAVAILABLE {error}", flush=True)
                raise
            corpus.update(payload)
            batches += 1
            records.clear()
        for case in fixture["cases"]:
            if (case["group"] == "extended") != full:
                continue
            for workers in (1, 2, 4, 8):
                # Serial and actually parallel workers for every multi-lane case.
                if case["lanes"] == 1 and workers != 1:
                    continue
                fields = [bytes.fromhex(case[name]) for name in ("password", "salt", "key", "associated", "expected")]
                assert len(fields[-1]) == case["length"]
                records.append(struct.pack("<IIIII", case["id"], case["memory_kib"], case["passes"], case["lanes"], workers)
                               + b"".join(struct.pack("<I", len(field)) + field for field in fields))
                counts[case["group"]] += 1
                if len(records) == (1 if full else 16):
                    run_batch()
        if records:
            run_batch()
    assert counts == ({"extended": 8} if full else {"rfc9106": 4, "quick": 489})
    assert batches == (8 if full else 31)
    print(f"PASS independent argon2id: {dict(counts)} batches={batches} corpus_sha256={corpus.hexdigest()}", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("driver")
    parser.add_argument("--full", action="store_true")
    args = parser.parse_args()
    check_argon(args.driver, args.full)
