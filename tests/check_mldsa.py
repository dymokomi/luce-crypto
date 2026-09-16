#!/usr/bin/env python3
"""Independent OpenSSL ML-DSA-65 interop for the native verifier."""
import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    binary = Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / "build/native3/mldsa-interop")
    seed = bytes(32)
    pem = subprocess.check_output(
        ["openssl", "genpkey", "-algorithm", "ML-DSA-65", "-pkeyopt", f"hexseed:{seed.hex()}"]
    )
    pub = subprocess.check_output(["openssl", "pkey", "-pubout", "-outform", "DER"], input=pem)
    pk = pub[-1952:]
    assert hashlib.sha256(pk).hexdigest() == "085ba380ff386dd52e42349c6eb88489d6058ea541a4e3fb0dce9a3fd1f7a911"
    with tempfile.TemporaryDirectory(prefix="mldsa-") as tmp:
        tmp = Path(tmp)
        (tmp / "pk.bin").write_bytes(pk)
        (tmp / "msg").write_bytes(b"hello")
        (tmp / "key.pem").write_bytes(pem)
        subprocess.check_call(
            ["openssl", "pkeyutl", "-sign", "-inkey", tmp / "key.pem", "-in", tmp / "msg", "-out", tmp / "sig.bin"]
        )
        sig = (tmp / "sig.bin").read_bytes()
        assert len(sig) == 3309
        subprocess.check_call([binary, tmp / "pk.bin", tmp / "sig.bin", "hello"], cwd=ROOT)
    print("PASS OpenSSL ML-DSA-65 sign/verify interop", flush=True)


if __name__ == "__main__":
    main()
