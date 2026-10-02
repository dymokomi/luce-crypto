#!/usr/bin/env python3
"""Convert Wycheproof JSON vectors into the line files under tests/vectors/.

The JSON comes from https://github.com/C2SP/wycheproof (Apache-2.0) at the
revision in REVISION; pass the directory holding its testvectors_v1 files.
Each output line is space-separated hex fields, "-" for an empty field:

  wycheproof_aes_gcm.txt   RESULT KEY IV AAD MSG CT TAG          (96-bit IVs only)
  wycheproof_rsa_*.txt     key MODULUS EXPONENT, then RESULT MSG SIG
  wycheproof_ecdsa_*.txt   key X Y, then RESULT MSG DER_SIG

RESULT is "valid" or "invalid"; Wycheproof's "acceptable" cases are dropped.
"""
import json
from pathlib import Path
import sys

REVISION = "3fa63dd0344abb611f1fb1d77e119938603ea230"
ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "tests/vectors"
FILES = {
    "aes_gcm_test.json": "wycheproof_aes_gcm.txt",
    "rsa_signature_2048_sha256_test.json": "wycheproof_rsa_pkcs1_2048_sha256.txt",
    "rsa_signature_3072_sha384_test.json": "wycheproof_rsa_pkcs1_3072_sha384.txt",
    "rsa_signature_4096_sha512_test.json": "wycheproof_rsa_pkcs1_4096_sha512.txt",
    "rsa_pss_2048_sha256_mgf1_32_test.json": "wycheproof_rsa_pss_2048_sha256.txt",
    "rsa_pss_3072_sha256_mgf1_32_test.json": "wycheproof_rsa_pss_3072_sha256.txt",
    "rsa_pss_4096_sha512_mgf1_64_test.json": "wycheproof_rsa_pss_4096_sha512.txt",
    "ecdsa_secp384r1_sha256_test.json": "wycheproof_ecdsa_p384_sha256.txt",
    "ecdsa_secp384r1_sha384_test.json": "wycheproof_ecdsa_p384_sha384.txt",
}


def field(value):
    return value if value else "-"


def strip(number):
    """A JSON big-endian integer without its leading sign octet."""
    while len(number) > 2 and number.startswith("00"):
        number = number[2:]
    return number


def convert(source, name):
    data = json.loads(source.read_text())
    lines = []
    for group in data["testGroups"]:
        kind = group["type"]
        if kind == "AeadTest":
            if group["ivSize"] != 96 or group["tagSize"] != 128:
                continue
        elif kind in ("RsassaPkcs1Verify", "RsassaPssVerify"):
            key = group["publicKey"]
            lines.append(f"key {strip(key['modulus'])} {strip(key['publicExponent'])}")
        elif kind == "EcdsaVerify":
            point = group["publicKey"]["uncompressed"]
            width = (len(point) - 2) // 2
            lines.append(f"key {point[2:2 + width]} {point[2 + width:]}")
        else:
            raise SystemExit(f"{source.name}: unexpected group type {kind}")
        for test in group["tests"]:
            if test["result"] == "acceptable":
                continue
            if kind == "AeadTest":
                parts = [test["key"], test["iv"], test["aad"], test["msg"], test["ct"], test["tag"]]
            else:
                parts = [test["msg"], test["sig"]]
            lines.append(" ".join([test["result"]] + [field(p) for p in parts]))
    (OUT / name).write_text("\n".join(lines) + "\n")
    print(f"{name}: {sum(1 for l in lines if not l.startswith('key'))} cases")


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    folder = Path(sys.argv[1])
    for source, name in FILES.items():
        convert(folder / source, name)


if __name__ == "__main__":
    main()
