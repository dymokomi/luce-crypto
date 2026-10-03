#!/usr/bin/env python3
"""Convert OpenSSL EVP test data into line files under tests/vectors/openssl/.

Usage: tools/openssl_vectors.py OPENSSL_CHECKOUT

Reads test/recipes/30-test_evp_data/*.txt of OpenSSL (Apache-2.0) at the
revision in REVISION. Only data is converted; no OpenSSL code is copied.
Every stanza of a family this package implements is written, including error
cases (RESULT names OpenSSL's expected error, "ok" otherwise); stanzas for
algorithms or modes this package does not implement are counted in
SUMMARY.txt so the README can list them. Fields are hex, "-" for empty and
"absent" for a parameter the stanza does not set.

  digest.txt   ALG OUTPUT CHUNK... (CHUNK is INPUT:NCOPY:COUNT, fed in order)
  hmac.txt     ALG KEY INPUT OUTPUT RESULT
  hkdf.txt     MODE ALG IKM SALT INFO OUTPUT RESULT
  cipher.txt   CIPHER OPERATION RESULT KEY IV AAD PLAIN CIPHERTEXT TAG
"""
import collections
import hashlib
from pathlib import Path
import sys

REVISION = "adb795d9b166b7342ad1227b6241f3d31d973438"
ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "tests/vectors/openssl"
DIGESTS = {"sha1": "sha1", "sha224": "sha224", "sha256": "sha256", "sha384": "sha384", "sha512": "sha512",
           "sha2-224": "sha224", "sha2-256": "sha256", "sha2-384": "sha384", "sha2-512": "sha512"}


def stanzas(path):
    """Blank-line separated stanzas as ordered (key, value) lists. PEM blocks
    following a key line become that key's value."""
    lines, out, current, at = path.read_text().splitlines(), [], [], 0
    while at < len(lines):
        line = lines[at]
        if line.startswith("#"):
            at += 1
            continue
        if not line.strip():
            if current:
                out.append(current)
            current = []
            at += 1
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if at + 1 < len(lines) and lines[at + 1].startswith("-----BEGIN"):
            pem = []
            at += 1
            while not lines[at].startswith("-----END"):
                pem.append(lines[at])
                at += 1
            pem.append(lines[at])
            current.append((key, value, "\n".join(pem)))
        else:
            current.append((key, value))
        at += 1
    if current:
        out.append(current)
    return out


def get(stanza, key, default=None):
    for item in stanza:
        if item[0] == key:
            return item[1]
    return default


def value_hex(text):
    """A test value: a quoted string, or hex."""
    if text is None:
        return "absent"
    if text.startswith('"'):
        return text.strip('"').encode().hex() or "-"
    return text.lower() or "-"


def ctrl_hex(text):
    """A Ctrl value such as hexkey:00ff, salt:text or digest:SHA256."""
    if text is None:
        return "absent"
    name, _, value = text.partition(":")
    if name.startswith("hex"):
        return value.lower() or "-"
    return value.encode().hex() or "-"


def provider_only(stanza):
    """Stanzas that only run in the FIPS provider test OpenSSL's FIPS policy."""
    available = get(stanza, "Availablein")
    return available is not None and "default" not in available


def digest(source, summary):
    lines = []
    for stanza in stanzas(source / "evpmd_sha.txt"):
        name = get(stanza, "Digest")
        if name is None:
            continue
        alg = DIGESTS.get(name.lower())
        if alg is None:
            summary[f"evpmd_sha.txt: {name} (hash not implemented)"] += 1
            continue
        chunks = []
        for item in stanza:
            if item[0] == "Input":
                chunks.append([value_hex(item[1]), "1", "1"])
            elif item[0] == "Ncopy":
                chunks[-1][1] = item[1]
            elif item[0] == "Count":
                chunks[-1][2] = item[1]
        lines.append(f"{alg} {value_hex(get(stanza, 'Output'))} " + " ".join(":".join(c) for c in chunks))
    return lines


def hmac(source, summary):
    lines = []
    for stanza in stanzas(source / "evpmac_common.txt"):
        if not (get(stanza, "MAC") or "").startswith("HMAC"):
            if get(stanza, "MAC"):
                summary[f"evpmac_common.txt: {get(stanza, 'MAC')} (MAC not implemented)"] += 1
            continue
        alg = DIGESTS.get((get(stanza, "Algorithm") or "").lower())
        if provider_only(stanza):
            summary["evpmac_common.txt: HMAC FIPS-provider-only policy checks"] += 1
            continue
        if alg is None:
            summary[f"evpmac_common.txt: HMAC-{get(stanza, 'Algorithm')} (hash not implemented)"] += 1
            continue
        lines.append(f"{alg} {value_hex(get(stanza, 'Key'))} {value_hex(get(stanza, 'Input'))} "
                     f"{value_hex(get(stanza, 'Output'))} {get(stanza, 'Result', 'ok')}")
    return lines


def hkdf(source, summary):
    lines = []
    for name, kind in (("evpkdf_hkdf.txt", "KDF"), ("evppkey_kdf_hkdf.txt", "PKEYKDF")):
        for stanza in stanzas(source / name):
            if get(stanza, kind) is None:
                continue
            if provider_only(stanza):
                summary[f"{name}: FIPS-provider-only policy checks"] += 1
                continue
            mode = {"mode:EXTRACT_ONLY": "extract", "mode:EXPAND_ONLY": "expand"}.get(get(stanza, "Ctrl.mode"), "both")
            digest_text = get(stanza, "Ctrl.digest") or get(stanza, "Ctrl.md")
            alg = "absent" if digest_text is None else DIGESTS.get(digest_text.partition(":")[2].lower(), digest_text.partition(":")[2])
            lines.append(f"{mode} {alg} {ctrl_hex(get(stanza, 'Ctrl.IKM'))} {ctrl_hex(get(stanza, 'Ctrl.salt'))} "
                         f"{ctrl_hex(get(stanza, 'Ctrl.info'))} {value_hex(get(stanza, 'Output'))} {get(stanza, 'Result', 'ok')}")
    return lines


def cipher(source, summary):
    lines = []
    for name in ("evpciph_aes_common.txt", "evpciph_chacha.txt"):
        for stanza in stanzas(source / name):
            kind = (get(stanza, "Cipher") or "").lower()
            if not kind:
                continue
            if kind not in ("aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20", "chacha20-poly1305"):
                summary[f"{name}: {kind} (mode not implemented)"] += 1
                continue
            operation = (get(stanza, "Operation") or "both").lower()
            fields = [value_hex(get(stanza, k)) for k in ("Key", "IV", "AAD", "Plaintext", "Ciphertext", "Tag")]
            lines.append(" ".join([kind, operation, get(stanza, "Result", "ok")] + fields))
    return lines


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    source = Path(sys.argv[1]) / "test/recipes/30-test_evp_data"
    OUT.mkdir(parents=True, exist_ok=True)
    summary = collections.Counter()
    for name, convert in (("digest", digest), ("hmac", hmac), ("hkdf", hkdf), ("cipher", cipher)):
        lines = convert(source, summary)
        (OUT / f"{name}.txt").write_text("\n".join(lines) + "\n")
        print(f"{name}.txt: {len(lines)} cases")
    (OUT / "SUMMARY.txt").write_text("".join(f"{count} {what}\n" for what, count in sorted(summary.items())))
    used = ["evpmd_sha.txt", "evpmac_common.txt", "evpkdf_hkdf.txt", "evppkey_kdf_hkdf.txt",
            "evpciph_aes_common.txt", "evpciph_chacha.txt"]
    (OUT / "SOURCE-SHA256SUMS").write_text(
        "".join(f"{hashlib.sha256((source / n).read_bytes()).hexdigest()}  {n}\n" for n in used))


if __name__ == "__main__":
    main()
