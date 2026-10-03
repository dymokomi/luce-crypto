#!/usr/bin/env python3
"""Extract BearSSL's known-answer tests into tests/vectors/bearssl/*.txt.

Usage: tools/bearssl_vectors.py BEARSSL_CHECKOUT

Reads test/test_crypto.c of BearSSL (MIT, Copyright (c) 2016 Thomas Pornin)
at the revision named in REVISION and writes line files of space-separated
hex fields ("-" for an empty field). Only data is extracted; no C code is
copied. Every vector BearSSL has for an in-scope primitive is written,
including those for parameters this package does not support; the Luce
tests count those explicitly as out of scope rather than dropping them here.

Some BearSSL checks draw their inputs from HMAC_DRBG (SP 800-90A) seeded with
a fixed string; for those (modular exponentiation, EC multiply-add) this tool
runs the same DRBG in Python and records the inputs together with expected
results computed with Python integers, so the Luce tests stay deterministic.
"""
import hashlib
import hmac
from pathlib import Path
import re
import sys

REVISION = "7bea48e5e850ab4cafbe68d3765cdaba13a86d6f"
ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "tests/vectors/bearssl"

TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|[A-Za-z_][A-Za-z0-9_]*|0[xX][0-9A-Fa-f]+|\d+|\S', re.S)


def tokens(text):
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return TOKEN.findall(text)


def strings(group):
    """Concatenate adjacent string literals; other tokens pass through."""
    out = []
    for token in group:
        if token.startswith('"'):
            value = bytes(token[1:-1], "utf-8").decode("unicode_escape")
            if out and isinstance(out[-1], Str):
                out[-1] = Str(out[-1] + value)
            else:
                out.append(Str(value))
        else:
            out.append(token)
    return out


class Str(str):
    pass


def calls(source, name):
    """Argument lists (string-joined) of every call `name(...)`."""
    toks = tokens(source)
    result = []
    for i, tok in enumerate(toks):
        if tok != name or i + 1 >= len(toks) or toks[i + 1] != "(":
            continue
        if i > 0 and toks[i - 1] in ("void", "static") or (i > 0 and re.match(r"[A-Za-z_]", toks[i - 1]) and toks[i - 1] not in ("return",)):
            continue
        depth, args, current = 0, [], []
        for tok2 in toks[i + 1:]:
            if tok2 == "(":
                depth += 1
                if depth == 1:
                    continue
            elif tok2 == ")":
                depth -= 1
                if depth == 0:
                    args.append(strings(current))
                    break
            elif tok2 == "," and depth == 1:
                args.append(strings(current))
                current = []
                continue
            current.append(tok2)
        result.append(args)
    return result


def array(source, name):
    """Elements of `NAME[] = { ... };`. A flat array yields strings, numbers
    and None for NULL; an array of structs yields one list per `{...}`. The
    all-zero terminator entry is dropped."""
    match = re.search(re.escape(name) + r"\s*\[\s*\]\s*=\s*\{", source)
    if not match:
        raise SystemExit(f"array {name} not found")
    depth, at = 1, match.end()
    while depth:
        depth += {"{": 1, "}": -1}.get(source[at], 0)
        at += 1
    body = strings(tokens(source[match.end():at - 1]))
    out, current, nested, depth = [], [], [], 0
    for tok in body + [","]:
        if tok == "{":
            depth += 1
            nested = []
        elif tok == "}":
            depth -= 1
            if current:
                nested.append(current[0] if len(current) == 1 else current)
            current = []
            if any(v not in ("0", "NULL") for v in nested):
                out.append(nested)
        elif tok == ",":
            if current:
                value = current[0] if len(current) == 1 else current
                if depth:
                    nested.append(value)
                elif value != "NULL":
                    out.append(value)
            current = []
        else:
            current.append(tok)
    return out


def text_hex(value):
    return value.encode("latin-1").hex()


def field(value):
    return value if value else "-"


def write(name, lines):
    (OUT / name).write_text("\n".join(lines) + "\n")
    print(f"{name}: {sum(1 for line in lines if not line.startswith('key'))} lines")


def single(args):
    return args[0] if isinstance(args, list) and len(args) == 1 else args


def hashes(src):
    lines = []
    for alg in ("md5", "sha1", "sha224", "sha256", "sha384", "sha512"):
        for args in calls(src, f"test_{alg}_internal"):
            lines.append(f"{alg} {field(text_hex(single(args[0])))} {single(args[1])}")
    for args in calls(src, "KAT_MILLION_A"):
        lines.append(f"{single(args[1])} million {single(args[2])}")
    write("hash.txt", lines)


def hmacs(src):
    lines = []
    for kind in ("hex_hex", "hex_str", "str_str"):
        for args in calls(src, f"do_KAT_HMAC_{kind}"):
            alg = single(args[0])[-1].replace("br_", "").replace("_vtable", "")
            key, data = single(args[1]), single(args[2])
            key = key if kind.startswith("hex") else text_hex(key)
            data = data if kind.endswith("hex") else text_hex(data)
            lines.append(f"{alg} {field(key.lower())} {field(data.lower())} {single(args[3])}")
    write("hmac.txt", lines)


def hkdfs(src):
    lines = []
    for args in calls(src, "test_HKDF_inner"):
        alg = single(args[0])[-1].replace("br_", "").replace("_vtable", "")
        salt = single(args[2])
        salt = "nosalt" if salt == "NULL" else field(salt)
        lines.append(f"{alg} {single(args[1])} {salt} {field(single(args[3]))} {single(args[4])}")
    write("hkdf.txt", lines)


def groups(values, size):
    """Split a flat array into records of `size` elements."""
    if len(values) % size:
        raise SystemExit("array length is not a multiple of the record size")
    return [values[i:i + size] for i in range(0, len(values), size)]


def aes(src):
    write("aes_ecb.txt", [" ".join(g) for g in groups(array(src, "KAT_AES"), 3)])
    write("aes_cbc.txt", [" ".join(g) for g in groups(array(src, "KAT_AES_CBC"), 4)])
    write("aes_ctr.txt", [" ".join(g) for g in groups(array(src, "KAT_AES_CTR"), 4)])
    lines = []
    for direction in ("encrypt", "decrypt"):
        for args in calls(src, f"monte_carlo_AES_{direction}"):
            if len(args) == 4 and isinstance(single(args[1]), Str):
                lines.append(f"{direction} {single(args[1])} {single(args[2])} {single(args[3])}")
    write("aes_monte_carlo.txt", lines)


def stream_ciphers(src):
    lines = []
    for entry in array(src, "KAT_CHACHA20"):
        key, nonce, counter, plain, cipher = entry
        lines.append(f"{key} {nonce} {counter} {plain} {cipher}")
    write("chacha20.txt", lines)
    lines = [" ".join(field(v) for v in g) for g in array(src, "KAT_POLY1305")]
    write("chacha20_poly1305.txt", lines)


def gcm(src):
    write("ghash.txt", [" ".join(field(v) for v in g) for g in groups(array(src, "KAT_GHASH"), 4)])
    write("gcm.txt", [" ".join(field(v) for v in g) for g in groups(array(src, "KAT_GCM"), 6)])


def curves(src):
    lines = []
    for g in array(src, "C25519_KAT"):
        lines.append(f"c25519 {g[0]} {g[1]} {g[2]}")
    for args in calls(src, "test_EC_inner"):
        if len(args) == 4 and isinstance(single(args[0]), Str):
            curve = single(args[3]).replace("BR_EC_", "")
            lines.append(f"{curve} {single(args[0])} {single(args[1])}")
    for args in calls(src, "test_EC_P256_carry_inner"):
        if isinstance(single(args[1]), Str):
            lines.append(f"p256carry {single(args[1])} {single(args[2])}")
    # test_EC_inner's multiply-add identities: per curve, ten rounds of
    # a, b, x, y drawn from HMAC_DRBG("seed for EC") as 80 bytes reduced mod n.
    for curve, order in (("secp256r1", N256), ("secp384r1", N384)):
        rng, width = Drbg(b"seed for EC"), (order.bit_length() + 7) // 8
        for _ in range(10):
            a, b, x, y = (int.from_bytes(rng.generate(80), "big") % order for _ in range(4))
            values = (a, b, x, y, (a * x + b * y) % order, (2 * a * x) % order, (order - a) % order)
            lines.append(f"muladd {curve} " + " ".join(v.to_bytes(width, "big").hex() for v in values))
    write("ec.txt", lines)


def bytes_of(src, name):
    match = re.search(re.escape(name) + r"\[\]\s*=\s*\{(.*?)\}", src, re.S)
    return bytes(int(v, 16) for v in re.findall(r"0x[0-9A-Fa-f]+", match.group(1))).hex()


def ecdsa(src):
    keys = {}
    for curve in ("P256", "P384", "P521"):
        keys[f"&EC_{curve}_PUB"] = (curve.lower(), bytes_of(src, f"EC_{curve}_PUB_POINT"),
                                     bytes_of(src, f"EC_{curve}_PRIV_X"))
    lines = [f"key {c} {pub} {priv}" for c, pub, priv in keys.values()]
    for pub, _, hf, msg, k, raw, asn1 in array(src, "ECDSA_KAT"):
        pub = "".join(pub) if isinstance(pub, list) else pub
        hf = (hf if isinstance(hf, str) else "".join(hf)).replace("&br_", "").replace("_vtable", "")
        lines.append(f"{keys[pub][0]} {hf} {text_hex(msg)} {k} {raw} {asn1}")
    write("ecdsa.txt", lines)


def rsa(src):
    values = array(src, "KAT_RSA_PSS")
    lines, at = [], 0
    while at < len(values):
        n, e = values[at], values[at + 1]
        lines.append(f"key {n} {e}")
        at += 8
        for _ in range(6):
            lines.append(f"sha1 {values[at]} {values[at + 1]} {values[at + 2]}")
            at += 3
    write("rsa_pss.txt", lines)
    # PKCS#1 v1.5 KATs of test_RSA_core / test_RSA_sign / test_RSA_signatures.
    n, e = bytes_of(src, "RSA_N"), bytes_of(src, "RSA_E")
    core = re.search(r"test_RSA_core.*?hextobin\(t1, \"([0-9A-F]+)\"\);\s*hextobin\(t2, \"([0-9A-F]+)\"\);"
                     r".*?hextobin\(t1, \"([0-9A-F]+)\"\);\s*hextobin\(t2, \"([0-9A-F]+)\"\);", src, re.S)
    lines = [f"key {n} {e}", f"public {core.group(1)} {core.group(2)}", f"public {core.group(3)} {core.group(4)}"]
    lines.append(f"pkcs1 sha1 {hashlib.sha1(b'test').hexdigest()} {core.group(1)}")
    sign = re.search(r'rsa_pk.nlen = hextobin\(rsa_n, "([0-9A-F]+)"\).*?hextobin\(rsa_e, "([0-9A-F]+)"\)'
                     r'.*?hextobin\(sig, "([0-9A-F]+)"\).*?hextobin\(hv2, "([0-9A-F]+)"\)', src, re.S)
    lines += [f"key {sign.group(1)} {sign.group(2)}", f"pkcs1 sha512 {sign.group(4)} {sign.group(3)}"]
    write("rsa_pkcs1.txt", lines)


N256 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
N384 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973


class Drbg:
    """HMAC_DRBG (SP 800-90A section 10.1.2) without reseeding, as BearSSL."""

    def __init__(self, seed, digest=hashlib.sha256):
        self.digest = digest
        size = digest().digest_size
        self.k, self.v = b"\0" * size, b"\1" * size
        self.update(seed)

    def mac(self, key, data):
        return hmac.new(key, data, self.digest).digest()

    def update(self, data):
        self.k = self.mac(self.k, self.v + b"\0" + data)
        self.v = self.mac(self.k, self.v)
        if data:
            self.k = self.mac(self.k, self.v + b"\1" + data)
            self.v = self.mac(self.k, self.v)

    def generate(self, count):
        out = b""
        while len(out) < count:
            self.v = self.mac(self.k, self.v)
            out += self.v
        self.k = self.mac(self.k, self.v + b"\0")
        self.v = self.mac(self.k, self.v)
        return out[:count]


def modpow():
    """test_modpow_i31 inputs: moduli of 10 to 500 bits, with results."""
    rng, lines = Drbg(b"seed modpow"), []
    for k in range(10, 501):
        size = (k + 7) >> 3
        bm, bx, be = bytearray(rng.generate(size)), bytearray(rng.generate(size)), rng.generate(size)
        bm[-1] |= 1
        mask = 0xFF >> ((size << 3) - k)
        bm[0] &= mask
        bm[0] |= mask - (mask >> 1)
        bx[0] &= mask >> 1
        m, x, e = (int.from_bytes(v, "big") for v in (bm, bx, be))
        lines.append(f"{bytes(bm).hex()} {bytes(bx).hex()} {be.hex()} {pow(x, e, m).to_bytes(size, 'big').hex()}")
    write("modpow.txt", lines)


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    path = Path(sys.argv[1]) / "test/test_crypto.c"
    src = path.read_text(encoding="latin-1")
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "SOURCE-SHA256SUMS").write_text(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  test/test_crypto.c\n")
    hashes(src)
    hmacs(src)
    hkdfs(src)
    aes(src)
    stream_ciphers(src)
    gcm(src)
    curves(src)
    ecdsa(src)
    rsa(src)
    modpow()


if __name__ == "__main__":
    main()
