#!/usr/bin/env python3
"""Run identical quick correctness gates from a read-only binary bundle."""
from pathlib import Path
import sys
from check_hashes import check, check_files, checked
from check_keyed import check_keyed


def check_all(binaries):
    binaries = Path(binaries).resolve()
    for name in ("native", "facade", "keyed-native", "keyed-failures", "memory-probe"):
        result = checked([binaries / name])
        assert result.stdout.startswith(b"PASS "), result.stdout
        print(result.stdout.decode(), end="", flush=True)
    check(binaries / "driver")
    check_files(binaries / "file-driver")
    check_keyed(binaries / "keyed-driver")


if __name__ == "__main__": check_all(sys.argv[1])
