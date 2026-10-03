#!/usr/bin/env python3
"""Build and test Base internals and the Luce consumer in every pinned mode."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
from run_prebuilt import check_all

ROOT = Path(__file__).resolve().parents[1]
MODES = {f"native{i}": ["--native", "--opt", str(i)] for i in range(4)}
MODES.update({"c": ["--backend=c"], "c-release": ["--backend=c", "--release"]})
SOURCES = [("src/x25519_tests.lucb", "x25519"), ("src/p256_tests.lucb", "p256"), ("src/p384_tests.lucb", "p384"), ("src/native_tests.lucb", "native"), ("tests/driver.lucb", "driver"), ("tests/file_driver.lucb", "file-driver")]
SOURCES += [("src/keyed_tests.lucb", "keyed-native"),
            ("src/keyed_failure_tests.lucb", "keyed-failures"),
            ("tests/keyed_driver.lucb", "keyed-driver"),
            ("src/memory_probe.lucb", "memory-probe")]
SOURCES += [("src/blake2b_tests.lucb", "blake-driver"),
            ("src/argon2_tests.lucb", "argon-driver"),
            ("src/argon2_failure_tests.lucb", "argon-failures"),
            ("src/aead_tests.lucb", "aead-tests"),
            ("src/hash_kat_tests.lucb", "hash-kat"),
            ("src/gcm_tests.lucb", "gcm-tests"),
            ("src/chacha_kat_tests.lucb", "chacha-kat"),
            ("src/x25519_kat_tests.lucb", "x25519-kat"),
            ("src/rsa_kat_tests.lucb", "rsa-kat"),
            ("src/ecdsa_kat_tests.lucb", "ecdsa-kat"),
            ("src/ec_kat_tests.lucb", "ec-kat"),
            ("src/shake_tests.lucb", "shake-tests"),
            ("src/mldsa_tests.lucb", "mldsa-tests"),
            ("src/mldsa_interop.lucb", "mldsa-interop")]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=[*MODES, "all"], default="all")
    parser.add_argument("--base", type=Path, default=ROOT / "build/toolchain/luce-base")
    parser.add_argument("--luce", type=Path, default=ROOT / "build/toolchain/luce")
    args = parser.parse_args()
    environment = dict(os.environ, LUCE_BASE=str(args.base.resolve()))
    environment.setdefault("LUCE_STD", str(ROOT.parent / "luce-base/src/std"))
    environment.setdefault("LUCE_CACHE", str(ROOT / "build/cache"))
    def run(command):
        print("RUN", " ".join(str(arg) for arg in command), flush=True)
        timeout = 600 if len(command) > 1 and command[1] == "build" else 180
        subprocess.run([str(arg) for arg in command], cwd=ROOT, env=environment, check=True, timeout=timeout)
    run([sys.executable, "tests/test_vectors.py"])
    run([sys.executable, "tests/test_keyed.py"])
    run([sys.executable, "tests/test_argon.py"])
    for mode, flags in MODES.items():
        if args.mode not in (mode, "all"): continue
        output = ROOT / "build" / mode
        output.mkdir(parents=True, exist_ok=True)
        print(f"MODE {mode}", flush=True)
        for source, name in SOURCES:
            run([args.base.resolve(), "build", ROOT / source, *flags, "-o", output / name])
        run([args.luce.resolve(), "build", ROOT / "tests/facade.luc", *flags, "-o", output / "facade"])
        check_all(output)
        subprocess.run([sys.executable, "tests/check_mldsa.py", output / "mldsa-interop"],
                       cwd=ROOT, env=environment, check=True, timeout=180)
        print(f"PASS mode {mode}", flush=True)


if __name__ == "__main__": main()
