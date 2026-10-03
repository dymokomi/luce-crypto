#!/usr/bin/env python3
"""Convert Project Wycheproof JSON into the line files under tests/vectors/.

Usage: tools/wycheproof.py WYCHEPROOF_TESTVECTORS_V1_DIR

The JSON comes from https://github.com/C2SP/wycheproof (Apache-2.0) at the
revision in REVISION. Every test of every listed file is written, including
"acceptable" ones and parameter sets this package does not support; the Luce
tests decide and count each case, so nothing is dropped silently. Fields are
space-separated hex, "-" for empty; the last field lists the test's flags.

  AEAD     RESULT KEY IV AAD MSG CT TAG FLAGS
  MAC      RESULT KEY MSG TAG FLAGS              (group line: group TAGBITS)
  HKDF     RESULT IKM SALT INFO SIZE OKM FLAGS
  XDH      RESULT PUBLIC PRIVATE SHARED FLAGS
  ECDH     RESULT PUBLIC PRIVATE SHARED FLAGS    (PUBLIC is a point or SPKI)
  ECDSA    key X Y, then RESULT MSG SIG FLAGS
  PKCS#1   key N E, then RESULT MSG SIG FLAGS
  PSS      key N E HASH MGFHASH SALTLEN, then RESULT MSG SIG FLAGS

RESULT is valid, invalid or acceptable.
"""
import hashlib
import json
from pathlib import Path
import sys

REVISION = "3fa63dd0344abb611f1fb1d77e119938603ea230"
ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "tests/vectors/wycheproof"
FILES = [
    "aes_gcm_test", "chacha20_poly1305_test",
    "hmac_sha256_test", "hmac_sha384_test", "hmac_sha512_test",
    "hkdf_sha256_test", "hkdf_sha384_test",
    "x25519_test", "ecdh_secp256r1_test", "ecdh_secp256r1_ecpoint_test",
    "ecdsa_secp256r1_sha256_test", "ecdsa_secp256r1_sha256_p1363_test",
    "ecdsa_secp256r1_sha512_test", "ecdsa_secp256r1_sha512_p1363_test",
    "ecdsa_secp384r1_sha256_test", "ecdsa_secp384r1_sha384_test", "ecdsa_secp384r1_sha384_p1363_test",
    "ecdsa_secp384r1_sha512_test", "ecdsa_secp384r1_sha512_p1363_test",
    "rsa_signature_2048_sha256_test", "rsa_signature_2048_sha384_test", "rsa_signature_2048_sha512_test",
    "rsa_signature_3072_sha256_test", "rsa_signature_3072_sha384_test", "rsa_signature_3072_sha512_test",
    "rsa_signature_4096_sha256_test", "rsa_signature_4096_sha384_test", "rsa_signature_4096_sha512_test",
    "rsa_signature_8192_sha256_test", "rsa_signature_8192_sha384_test", "rsa_signature_8192_sha512_test",
    "rsa_pss_2048_sha256_mgf1_0_test", "rsa_pss_2048_sha256_mgf1_32_test", "rsa_pss_2048_sha256_mgf1sha1_20_test",
    "rsa_pss_2048_sha384_mgf1_48_test", "rsa_pss_3072_sha256_mgf1_32_test", "rsa_pss_4096_sha256_mgf1_32_test",
    "rsa_pss_4096_sha384_mgf1_48_test", "rsa_pss_4096_sha512_mgf1_32_test", "rsa_pss_4096_sha512_mgf1_64_test",
    "rsa_pss_misc_test",
    "rsa_pss_2048_sha256_mgf1_0_params_test", "rsa_pss_2048_sha256_mgf1_32_params_test",
    "rsa_pss_2048_sha512_mgf1sha256_32_params_test", "rsa_pss_3072_sha256_mgf1_32_params_test",
    "rsa_pss_4096_sha512_mgf1_32_params_test", "rsa_pss_4096_sha512_mgf1_64_params_test",
    "rsa_pss_misc_params_test",
]
HASHES = {"SHA-1": "sha1", "SHA-224": "sha224", "SHA-256": "sha256", "SHA-384": "sha384", "SHA-512": "sha512"}


def field(value):
    return value if value else "-"


def hash_name(name):
    return HASHES.get(name, name.lower().replace("/", "_"))


def strip(number):
    while len(number) > 2 and number.startswith("00"):
        number = number[2:]
    return number


def flags(test):
    return ",".join(test["flags"]) or "-"


def convert(source):
    data = json.loads(source.read_text())
    lines = []
    for group in data["testGroups"]:
        kind = group["type"]
        if kind in ("RsassaPkcs1Verify", "RsassaPssVerify", "RsassaPssWithParametersVerify"):
            key = group["publicKey"]
            head = f"key {strip(key['modulus'])} {strip(key['publicExponent'])}"
            if kind != "RsassaPkcs1Verify":
                head += f" {hash_name(group['sha'])} {hash_name(group['mgfSha'])} {group['sLen']}"
            lines.append(head)
        elif kind in ("EcdsaVerify", "EcdsaP1363Verify"):
            point = group["publicKey"]["uncompressed"]
            width = (len(point) - 2) // 2
            lines.append(f"key {point[2:2 + width]} {point[2 + width:]}")
        elif kind == "MacTest":
            lines.append(f"group {group['tagSize']}")
        for test in group["tests"]:
            result = test["result"]
            if kind == "AeadTest":
                parts = [test["key"], test["iv"], test["aad"], test["msg"], test["ct"], test["tag"]]
            elif kind == "MacTest":
                parts = [test["key"], test["msg"], test["tag"]]
            elif kind == "HkdfTest":
                parts = [test["ikm"], test["salt"], test["info"], f"{test['size']:x}".zfill(4), test["okm"]]
            elif kind in ("XdhComp", "EcdhTest", "EcdhEcpointTest"):
                parts = [test["public"], test["private"], test["shared"]]
            else:
                parts = [test["msg"], test["sig"]]
            lines.append(" ".join([result] + [field(p) for p in parts] + [flags(test)]))
    name = source.stem.replace("_test", "") + ".txt"
    (OUT / name).write_text("\n".join(lines) + "\n")
    return name, sum(1 for g in data["testGroups"] for _ in g["tests"])


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    folder = Path(sys.argv[1])
    OUT.mkdir(parents=True, exist_ok=True)
    sums = []
    for stem in FILES:
        source = folder / f"{stem}.json"
        name, count = convert(source)
        sums.append(f"{hashlib.sha256(source.read_bytes()).hexdigest()}  {stem}.json")
        print(f"{name}: {count} tests")
    (OUT / "SOURCE-SHA256SUMS").write_text("\n".join(sums) + "\n")


if __name__ == "__main__":
    main()
