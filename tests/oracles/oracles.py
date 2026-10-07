#!/usr/bin/env python3
"""The independent oracles: Python's hashlib/hmac, the pinned Argon2id fixture and OpenSSL
check the drivers built from drivers/ (usage: oracles.py BINARIES). The harnesses' own unit
tests run first, so a broken oracle cannot pass a broken driver."""
from pathlib import Path
import subprocess
import sys
import unittest

from check_hashes import check, check_files, checked
from check_keyed import check_keyed
from check_blake import check_blake
from check_argon import check_argon


def main():
    binaries = Path(sys.argv[1]).resolve()
    suite = unittest.defaultTestLoader.loadTestsFromNames(["test_vectors", "test_keyed", "test_argon"])
    if not unittest.TextTestRunner(verbosity=0).run(suite).wasSuccessful():
        sys.exit(1)
    # the Argon2id driver alone checks RFC 9106 and its worker counts
    result = checked([binaries / "argon2"])
    assert result.stdout.startswith(b"PASS "), result.stdout
    print(result.stdout.decode(), end="", flush=True)
    check(binaries / "hash")
    check_files(binaries / "file")
    check_keyed(binaries / "keyed")
    check_blake(binaries / "blake2b")
    check_argon(binaries / "argon2")
    subprocess.run([sys.executable, "check_mldsa.py", binaries / "mldsa_interop"], check=True, timeout=180)


if __name__ == "__main__":
    main()
