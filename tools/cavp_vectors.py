#!/usr/bin/env python3
"""Convert NIST CAVP response files into line files under tests/vectors/cavp/.

Usage: tools/cavp_vectors.py GCM_DIR ECDSA_DIR

GCM_DIR holds gcmEncryptExtIV{128,192,256}.rsp and gcmDecrypt{128,192,256}.rsp
from gcmtestvectors.zip; ECDSA_DIR holds SigVer.rsp from
186-4ecdsatestvectors.zip (both from csrc.nist.gov, CAVP; US government work).

All ECDSA SigVer cases are kept. The GCM files repeat each of their 525
parameter sets (key, IV, plaintext, AAD and tag lengths) 15 times with random
values, 47,250 cases and 17 MB in all; to keep the package small the committed
files hold the first three cases of every parameter set, plus the first
failing case of each decrypt set when none of those three fails. Pass --full
to write every case instead (to a scratch directory with --out) for a local
run. Files are split below 900 KB. Formats (hex, "-" for empty):

  gcm_*      RESULT KEY IV AAD PT CT TAG     (RESULT valid, or invalid for FAIL)
  ecdsa_*    CURVE HASH QX QY R S MSG RESULT  (RESULT P or F, then the reason)
"""
import hashlib
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "tests/vectors/cavp"
LIMIT = 900_000


def records(path):
    """Yield (section headers, fields) for each Count block."""
    header, fields = {}, None
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if line.startswith("["):
            if fields:
                yield dict(header), fields
                fields = None
            for part in line.strip("[]").split(","):
                if "=" in part:
                    key, value = part.split("=", 1)
                    header[key.strip()] = value.strip()
                else:
                    header["group"] = line.strip("[]")
        elif line.startswith("Count") or line.startswith("Msg"):
            if line.startswith("Count") or fields is None or "Msg" in fields:
                if fields:
                    yield dict(header), fields
                fields = {}
            if line.startswith("Msg"):
                fields["Msg"] = line.split("=", 1)[1].strip()
        elif fields is not None and "=" in line:
            key, value = line.split("=", 1)
            fields[key.strip()] = value.strip()
        elif fields is not None and line == "FAIL":
            fields["FAIL"] = True
    if fields:
        yield dict(header), fields


def write_split(stem, lines, sums):
    chunk, size, part = [], 0, 0
    def flush():
        nonlocal chunk, size, part
        if chunk:
            name = f"{stem}_{part}.txt"
            (OUT / name).write_text("\n".join(chunk) + "\n")
            print(f"{name}: {len(chunk)} cases")
            part += 1
            chunk, size = [], 0
    for line in lines:
        if size + len(line) + 1 > LIMIT:
            flush()
        chunk.append(line)
        size += len(line) + 1
    flush()


def field(value):
    return value if value else "-"


def gcm(folder, sums, full):
    for kind in ("EncryptExtIV", "Decrypt"):
        lines = []
        for bits in (128, 192, 256):
            path = folder / f"gcm{kind}{bits}.rsp"
            sums.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  gcm{kind}{bits}.rsp")
            kept, failing = {}, set()
            for header, f in records(path):
                key = tuple(sorted(header.items()))
                count = kept.get(key, 0)
                result = "invalid" if f.get("FAIL") else "valid"
                first_failure = result == "invalid" and key not in failing
                if not full and count >= 3 and not first_failure:
                    continue
                kept[key] = count + 1
                if result == "invalid":
                    failing.add(key)
                lines.append(" ".join([result] + [field(f.get(k, "")) for k in ("Key", "IV", "AAD", "PT", "CT", "Tag")]))
        write_split(f"gcm_{kind.lower()}", lines, sums)


def ecdsa(folder, sums):
    path = folder / "SigVer.rsp"
    sums.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  SigVer.rsp")
    lines = []
    for header, f in records(path):
        curve, hash_name = header["group"].split(",")
        result = f["Result"].split()[0]
        reason = re.sub(r"[^A-Za-z0-9]+", "_", f["Result"][1:].strip(" ()")) or "-"
        lines.append(f"{curve} {hash_name.lower().replace('-', '')} {f['Qx']} {f['Qy']} {f['R']} {f['S']} {f['Msg']} {result} {reason}")
    write_split("ecdsa_sigver", lines, sums)


def main():
    global OUT
    arguments = [a for a in sys.argv[1:] if a != "--full"]
    if "--out" in arguments:
        at = arguments.index("--out")
        OUT = Path(arguments[at + 1])
        del arguments[at:at + 2]
    if len(arguments) != 2:
        raise SystemExit(__doc__)
    OUT.mkdir(parents=True, exist_ok=True)
    for old in OUT.glob("*.txt"):
        old.unlink()
    sums = []
    gcm(Path(arguments[0]), sums, "--full" in sys.argv)
    ecdsa(Path(arguments[1]), sums)
    (OUT / "SOURCE-SHA256SUMS").write_text("\n".join(sums) + "\n")


if __name__ == "__main__":
    main()
