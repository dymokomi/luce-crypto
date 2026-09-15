#!/usr/bin/env python3
"""Retain inspectable memory primitive bodies; not a constant-time proof/checker."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SYMBOLS = ("lb_luce_crypto_secure_wipe", "lb_luce_crypto_secure_equal",
           "lb_luce_crypto_secure_select_byte", "probe_dead")


def body(text, symbol):
    match = re.search(rf"(?m)^_?{re.escape(symbol)}:.*$", text)
    if not match: raise AssertionError(f"missing inspectable body {symbol}")
    tail = text[match.start():]
    # Native local labels are L<number>_<number>; C locals start L or .L.
    end = re.search(r"(?m)^(?:_?lb_|_?probe_|_?main:)[\w.]*:?.*$", tail[tail.index("\n") + 1:])
    if end: tail = tail[:tail.index("\n") + 1 + end.start()]
    return tail


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, default=ROOT / "build/toolchain/luce-base")
    args = parser.parse_args()
    output = ROOT / "build/codegen"
    output.mkdir(parents=True, exist_ok=True)
    def run(command):
        subprocess.run([str(arg) for arg in command], cwd=ROOT, check=True, timeout=180)
    def emit(source, flags, target):
        run([args.base.resolve(), "build", source, *flags, "-o", target])
    source = ROOT / "src/luce_crypto/memory_probe.lucb"
    generated = output / "memory.c"
    emit(source, ["--emit=c"], generated)
    text = generated.read_text()
    assert "volatile uint8_t* lb_destination" in text
    assert "const volatile uint8_t* lb_a" in text and "const volatile uint8_t* lb_b" in text
    report = {"machine": platform.machine(), "system": platform.system(),
              "base_pin": (ROOT / "bootstrap/BASE").read_text().strip(),
              "scope": "body retention and C volatile qualifiers only; instruction dataflow requires human review",
              "assemblies": {}, "native_noinline_callee_retained": {}}
    for mode in ("native0", "native1", "native2", "native3", "c", "c-release", "c-O3"):
        assembly = output / f"memory-{mode}.s"
        if mode.startswith("native"):
            emit(source, ["--native", "--opt", mode[-1], "--emit=asm"], assembly)
            repro = output / f"noinline-{mode}.s"
            emit(ROOT / "tests/noinline_repro.lucb", ["--native", "--opt", mode[-1], "--emit=asm"], repro)
            report["native_noinline_callee_retained"][mode] = "must_remain_a_call" in repro.read_text()
        else:
            run([os.environ.get("CC", "cc"), "-std=gnu11", "-w", "-fno-strict-aliasing",
                 "-O3" if mode == "c-O3" else ("-O2" if mode == "c-release" else "-O0"), "-I", ROOT.parent / "luce-base/runtime",
                 "-S", generated, "-o", assembly])
        assembly_text = assembly.read_text()
        excerpts = "\n".join(body(assembly_text, symbol) for symbol in SYMBOLS)
        (output / f"bodies-{mode}.s").write_text(excerpts)
        report["assemblies"][mode] = hashlib.sha256(assembly.read_bytes()).hexdigest()
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2), flush=True)
    print("PASS memory probe body retention and volatile C qualifiers (not a side-channel proof)", flush=True)


if __name__ == "__main__": main()
