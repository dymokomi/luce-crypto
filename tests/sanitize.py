#!/usr/bin/env python3
"""Instrument generated Base C and runtime; does not replace native-mode tests."""
import argparse
import os
from pathlib import Path
import subprocess
from run import SOURCES, ROOT
from check_hashes import check, check_files, checked
from check_keyed import check_keyed
from check_blake import check_blake
from check_argon import check_argon


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, default=ROOT / "build/toolchain/luce-base")
    args = parser.parse_args()
    runtime = ROOT.parent / "luce-base/runtime"
    output = ROOT / "build/sanitize"
    output.mkdir(parents=True, exist_ok=True)
    os.environ["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1"
    os.environ["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    def run(command):
        subprocess.run([str(arg) for arg in command], cwd=ROOT, check=True, timeout=180)
    for source, name in SOURCES:
        generated = output / f"{name}.c"
        run([args.base.resolve(), "build", ROOT / source, "--emit=c", "-o", generated])
        run([os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-g", "-w", "-fno-strict-aliasing",
             "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-I", runtime,
             generated, runtime / "lucb_rt.c", "-pthread", "-lm", "-o", output / name])
    for name in ("native", "keyed-native", "keyed-failures", "memory-probe", "argon-driver", "argon-failures"):
        print(checked([output / name]).stdout.decode(), end="", flush=True)
    check(output / "driver")
    check_files(output / "file-driver")
    check_keyed(output / "keyed-driver")
    check_blake(output / "blake-driver")
    check_argon(output / "argon-driver")
    print("PASS AddressSanitizer + UndefinedBehaviorSanitizer", flush=True)


if __name__ == "__main__": main()
