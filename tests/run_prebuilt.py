#!/usr/bin/env python3
"""Run identical quick correctness gates from a read-only binary bundle."""
from pathlib import Path
import sys
from check_hashes import check, check_files, checked
from check_keyed import check_keyed
from check_blake import check_blake
from check_argon import check_argon


## Vector programs: each takes the tests/vectors directory as its argument.
VECTOR_PROGRAMS = ("hash-kat", "gcm-tests", "chacha-kat", "x25519-kat", "rsa-tests", "ecdsa-kat", "ec-kat")


def check_vectors(binaries, timeout=900):
    vectors = Path(__file__).resolve().parents[1] / "tests/vectors"
    for name in VECTOR_PROGRAMS:
        result = checked([Path(binaries) / name, vectors], timeout=timeout)
        assert result.stdout.startswith(b"PASS "), result.stdout
        print(result.stdout.decode(), end="", flush=True)


def check_all(binaries):
    binaries = Path(binaries).resolve()
    for name in ("x25519", "p256", "p384", "native", "facade", "keyed-native", "keyed-failures", "memory-probe", "argon-driver", "argon-failures", "aead-tests", "shake-tests", "mldsa-tests"):
        result = checked([binaries / name])
        assert result.stdout.startswith(b"PASS "), result.stdout
        print(result.stdout.decode(), end="", flush=True)
    check_vectors(binaries)
    check(binaries / "driver")
    check_files(binaries / "file-driver")
    check_keyed(binaries / "keyed-driver")
    check_blake(binaries / "blake-driver")
    check_argon(binaries / "argon-driver")


if __name__ == "__main__": check_all(sys.argv[1])
