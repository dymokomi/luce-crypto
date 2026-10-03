#!/usr/bin/env python3
"""Bundle only public test binaries/scripts for isolated second-host validation.

The bundle carries the luce-crypto-vectors checkout under luce-crypto-vectors/;
run it with LUCE_CRYPTO_VECTORS=luce-crypto-vectors python3 tests/run_prebuilt.py bin.
"""
import argparse
import hashlib
import io
from pathlib import Path
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from vector_root import vector_root  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binaries", type=Path, default=ROOT / "build/native3")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    programs = ["x25519", "p256", "native", "facade", "driver", "file-driver", "keyed-native", "keyed-failures", "keyed-driver", "memory-probe"]
    programs += ["blake-driver", "argon-driver", "argon-failures", "aead-tests", "hash-kat", "gcm-tests", "chacha-kat", "x25519-kat", "rsa-kat", "ecdsa-kat", "ec-kat", "shake-tests", "mldsa-tests", "mldsa-interop"]
    scripts = ["run_prebuilt.py", "vector_root.py", "check_hashes.py", "test_vectors.py", "check_keyed.py", "rfc_keyed.py", "test_keyed.py"]
    scripts += ["check_blake.py", "check_argon.py", "test_argon.py", "check_mldsa.py"]
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    manifest = []
    with tarfile.open(args.output, "w:gz") as bundle:
        def add(name, data, mode=0o644):
            item = tarfile.TarInfo(name)
            item.size, item.mode = len(data), mode
            bundle.addfile(item, io.BytesIO(data))
            manifest.append(f"{hashlib.sha256(data).hexdigest()}  {name}\n")
        for name in programs: add(f"bin/{name}", (args.binaries / name).read_bytes(), 0o755)
        for name in scripts: add(f"tests/{name}", (ROOT / "tests" / name).read_bytes())
        vectors = vector_root()
        for path in sorted(vectors.rglob("*")):
            if path.is_file() and ".git" not in path.relative_to(vectors).parts:
                add(f"luce-crypto-vectors/{path.relative_to(vectors)}", path.read_bytes())
        for name in ["LICENSE", "LICENSE-MIT", "LICENSE-APACHE", "NOTICE.md"]:
            add(name, (ROOT / name).read_bytes())
        add("REVISION", (revision + "\n").encode())
        add("SHA256SUMS", "".join(manifest).encode())
    print(f"{hashlib.sha256(args.output.read_bytes()).hexdigest()}  {args.output.name}", flush=True)


if __name__ == "__main__": main()
