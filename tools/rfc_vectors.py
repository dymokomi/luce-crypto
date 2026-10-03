#!/usr/bin/env python3
"""Extract RFC test vectors into tests/vectors/rfc/*.txt.

Usage: tools/rfc_vectors.py RFC_DIR

RFC_DIR holds rfc8439.txt and rfc7748.txt from https://www.rfc-editor.org/.
Fields are hex, "-" for empty.

  rfc8439.txt
    block KEY NONCE COUNTER KEYSTREAM           (A.1)
    encrypt KEY NONCE COUNTER PLAIN CIPHER      (A.2)
    poly1305 KEY TEXT TAG                       (A.3)
    keygen KEY NONCE ONETIMEKEY                 (A.4)
    aead KEY NONCE AAD PLAIN CIPHER TAG         (A.5)
  rfc7748.txt
    x25519 SCALAR U OUTPUT                      (5.2)
    iterate COUNT OUTPUT                        (5.2)
    dh ALICE_PRIVATE ALICE_PUBLIC BOB_PRIVATE BOB_PUBLIC SHARED   (6.1)
"""
import hashlib
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "tests/vectors/rfc"
PAGE = re.compile(r"^(Nir & Langley|RFC 8439|Langley, et al\.|RFC 7748)\s")
DUMP = re.compile(r"^\s*\d{3}\s{2}((?:[0-9a-fA-F]{2} ){0,15}[0-9a-fA-F]{2})")
BARE = re.compile(r"^\s*((?:[0-9a-fA-F]{2} ){0,15}[0-9a-fA-F]{2})\s*$")


def body(path):
    return [line for line in path.read_text().splitlines() if not PAGE.match(line) and "\f" not in line]


def section(lines, start, end):
    begin = next(i for i, l in enumerate(lines) if l.startswith(start))
    finish = next(i for i, l in enumerate(lines) if i > begin and l.startswith(end))
    return lines[begin:finish]


def records(lines):
    """Split a section at 'Test Vector #' headings into label -> bytes maps."""
    out, current, label = [], None, None
    for line in lines:
        text = line.strip()
        if text.startswith("Test Vector #"):
            current = {}
            out.append(current)
            label = None
            continue
        if current is None:
            continue
        counter = re.match(r"(Initial )?Block Counter = (\d+)", text)
        if counter:
            current["counter"] = int(counter.group(2))
            continue
        dump = DUMP.match(line) or (BARE.match(line) if label in ("R", "S", "data", "tag") else None)
        if dump and label:
            current.setdefault(label, bytearray()).extend(bytes.fromhex(dump.group(1)))
            continue
        if text.endswith(":") or text in ("The ChaCha20 Key",):
            label = text.rstrip(":").strip()
            current.setdefault(label, bytearray())
    return out


def hexes(*values):
    return " ".join(bytes(v).hex() or "-" for v in values)


def rfc8439(folder):
    lines = body(folder / "rfc8439.txt")
    out = []
    for r in records(section(lines, "A.1.  ", "A.2.  ")):
        out.append(f"block {hexes(r['Key'], r['Nonce'])} {r['counter']} {hexes(r['Keystream'])}")
    for r in records(section(lines, "A.2.  ", "A.3.  ")):
        out.append(f"encrypt {hexes(r['Key'], r['Nonce'])} {r['counter']} {hexes(r['Plaintext'], r['Ciphertext'])}")
    for r in records(section(lines, "A.3.  ", "A.4.  ")):
        if "R" in r:
            out.append(f"poly1305 {hexes(r['R'] + r['S'], r['data'], r['tag'])}")
        else:
            out.append(f"poly1305 {hexes(r['One-time Poly1305 Key'], r['Text to MAC'], r['Tag'])}")
    for r in records(section(lines, "A.4.  ", "A.5.  ")):
        key = r.get("The ChaCha20 Key") or r.get("The ChaCha20 Key:")
        out.append(f"keygen {hexes(key, r['The nonce'], r['Poly1305 one-time key'])}")
    # A.5 has one unnumbered vector; its decrypted text is labelled "Plaintext::".
    a5 = records(["Test Vector #A.5"] + section(lines, "A.5.  ", "Appendix B")[1:])[0]
    out.append(f"aead {hexes(a5['The ChaCha20 Key'], a5['The nonce'], a5['The AAD'], a5['Plaintext'], a5['Ciphertext'], a5['Received Tag'])}")
    return out


def rfc7748(folder):
    text = (folder / "rfc7748.txt").read_text()
    out = []
    hexes_found = re.findall(r"Input scalar:\s*\n\s*([0-9a-f]{64})\s*\n.*?Input u-coordinate:\s*\n\s*([0-9a-f]{64})\s*\n"
                             r".*?Output u-coordinate:\s*\n\s*([0-9a-f]{64})", text, re.S)
    for scalar, u, result in hexes_found[:2]:
        out.append(f"x25519 {scalar} {u} {result}")
    for label, count in (("After one iteration", 1), ("After 1,000 iterations", 1000), ("After 1,000,000 iterations", 1000000)):
        match = re.search(re.escape(label) + r":\s*\n\s*([0-9a-f]{64})", text)
        out.append(f"iterate {count} {match.group(1)}")
    def value(label):
        return re.search(re.escape(label) + r":?\s*\n\s*([0-9a-f]{64})", text).group(1)
    out.append("dh " + " ".join(value(label) for label in (
        "Alice's private key, a", "Alice's public key, X25519(a, 9)",
        "Bob's private key, b", "Bob's public key, X25519(b, 9)", "Their shared secret, K")))
    return out


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    folder = Path(sys.argv[1])
    OUT.mkdir(parents=True, exist_ok=True)
    sums = []
    for name, convert in (("rfc8439", rfc8439), ("rfc7748", rfc7748)):
        lines = convert(folder)
        (OUT / f"{name}.txt").write_text("\n".join(lines) + "\n")
        sums.append(f"{hashlib.sha256((folder / f'{name}.txt').read_bytes()).hexdigest()}  {name}.txt")
        print(f"{name}.txt: {len(lines)} vectors")
    (OUT / "SOURCE-SHA256SUMS").write_text("\n".join(sums) + "\n")


if __name__ == "__main__":
    main()
