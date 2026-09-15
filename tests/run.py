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
SOURCES = [("src/luce_crypto/native_tests.lucb", "native"), ("tests/driver.lucb", "driver"), ("tests/file_driver.lucb", "file-driver")]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=[*MODES, "all"], default="all")
    parser.add_argument("--base", type=Path, default=ROOT / "build/toolchain/luce-base")
    parser.add_argument("--luce", type=Path, default=ROOT / "build/toolchain/luce")
    args = parser.parse_args()
    environment = dict(os.environ, LUCE_BASE=str(args.base.resolve()))
    def run(command):
        subprocess.run([str(arg) for arg in command], cwd=ROOT, env=environment, check=True, timeout=180)
    run([sys.executable, "tests/test_vectors.py"])
    for mode, flags in MODES.items():
        if args.mode not in (mode, "all"): continue
        output = ROOT / "build" / mode
        output.mkdir(parents=True, exist_ok=True)
        print(f"MODE {mode}", flush=True)
        for source, name in SOURCES:
            run([args.base.resolve(), "build", ROOT / source, *flags, "-o", output / name])
        run([args.luce.resolve(), "build", ROOT / "tests/facade.luc", *flags, "-o", output / "facade"])
        check_all(output)
        print(f"PASS mode {mode}", flush=True)


if __name__ == "__main__": main()
