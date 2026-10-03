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
  x25519.txt   derive RESULT PRIVATE PEER SHARED | keypair RESULT PRIVATE PUBLIC
  ecdh.txt     derive RESULT PRIVATE PEERX PEERY SHARED | keypair RESULT PRIVATE X Y   (P-256)
  ecdsa.txt    verify CURVE HASH X Y DIGEST SIG RESULT | digestverify CURVE HASH X Y MSG SIG RESULT
               | digestsign CURVE HASH PRIVATE MSG SIG | keypair CURVE RESULT PRIVATE X Y
"""
import base64
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


# ---- Keys ------------------------------------------------------------------

def tlv(data, at=0):
    """(tag, content, end) of the DER element at `at`."""
    tag, first = data[at], data[at + 1]
    at += 2
    if first & 0x80:
        count = first & 0x7F
        first = int.from_bytes(data[at:at + count], "big")
        at += count
    return tag, data[at:at + first], at + first


def children(data):
    out, at = [], 0
    while at < len(data):
        tag, content, end = tlv(data, at)
        out.append((tag, content, data[at:end]))
        at = end
    return out


OIDS = {"2b656e": "x25519", "2b656f": "x448", "2b6570": "ed25519", "2b6571": "ed448", "2a8648ce3d030107": "p256", "2b81040022": "p384",
        "2b81040023": "p521", "2a864886f70d010101": "rsa", "2a864886f70d01010a": "rsa-pss",
        "2a8648ce3d0201": "ec"}


def curve_name(oid):
    return OIDS.get(oid.hex(), "other-curve")


def pem_der(pem):
    body = "".join(line for line in pem.splitlines() if not line.startswith("-----"))
    return base64.b64decode(body)


class Key:
    """kind (x25519, p256, p384, rsa, ...), private scalar, public bytes or (n, e)."""

    def __init__(self, kind, private=None, public=None):
        self.kind, self.private, self.public = kind, private, public


def parse_key(pem, private):
    der = pem_der(pem)
    label = pem.splitlines()[0]
    parts = children(tlv(der)[1])
    if "RSA PRIVATE KEY" in label:
        fields = [c[1] for c in parts]
        return Key("rsa", None, (fields[1], fields[2]))
    if "EC PRIVATE KEY" in label:
        return ec_private(tlv(der)[1], None)
    if private:
        algorithm = children(parts[1][1])
        kind = curve_name(algorithm[0][1])
        inner = parts[2][1]
        if kind in ("x25519", "x448"):
            return Key(kind, tlv(inner)[1])
        if kind == "ec":
            named = curve_name(algorithm[1][1]) if algorithm[1][0] == 6 else "explicit-parameters"
            return ec_private(tlv(inner)[1], named)
        if kind in ("rsa", "rsa-pss"):
            fields = [c[1] for c in children(tlv(inner)[1])]
            return Key(kind, None, (fields[1], fields[2]))
        return Key(kind)
    algorithm = children(parts[0][1])
    kind = curve_name(algorithm[0][1])
    bits = parts[1][1][1:]
    if kind == "ec":
        return Key(curve_name(algorithm[1][1]) if algorithm[1][0] == 6 else "explicit-parameters", None, bits)
    if kind in ("rsa", "rsa-pss"):
        fields = [c[1] for c in children(tlv(bits)[1])]
        return Key(kind, None, (fields[0], fields[1]))
    return Key(kind, None, bits)


def ec_private(sequence, curve):
    fields = children(sequence)
    scalar, public = fields[1][1], None
    for tag, content, _ in fields[2:]:
        if tag == 0xA0:
            inner = tlv(content)
            curve = curve_name(inner[1]) if inner[0] == 6 else "explicit-parameters"
        elif tag == 0xA1:
            public = tlv(content)[1][1:]
    return Key(curve or "explicit-parameters", scalar, public)


def keys_of(stanzas_list):
    keys = {}
    for stanza in stanzas_list:
        for item in stanza:
            if item[0] in ("PrivateKey", "PublicKey") and len(item) == 3:
                try:
                    keys[item[1]] = parse_key(item[2], item[0] == "PrivateKey")
                except (IndexError, ValueError):
                    keys[item[1]] = Key("unparsable")
            elif item[0] in ("PrivateKeyRaw", "PublicKeyRaw"):
                name, kind, value = item[1].split(":", 2)
                key = Key(kind.lower())
                if item[0] == "PrivateKeyRaw":
                    key.private = bytes.fromhex(value)
                else:
                    key.public = bytes.fromhex(value)
                keys[name] = key
    return keys


CURVES = {
    "p256": (2**256 - 2**224 + 2**192 + 2**96 - 1,
             0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
             0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5, 32),
    "p384": (2**384 - 2**128 - 2**96 + 2**32 - 1,
             0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7,
             0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F, 48),
}


def ec_public(curve, scalar):
    """scalar * G in affine coordinates, as 04 || X || Y (public data, Python ints)."""
    p, gx, gy, width = CURVES[curve]
    def add(a, b):
        if a is None:
            return b
        if a[0] == b[0] and (a[1] + b[1]) % p == 0:
            return None
        if a == b:
            slope = (3 * a[0] * a[0] - 3) * pow(2 * a[1], -1, p) % p
        else:
            slope = (b[1] - a[1]) * pow(b[0] - a[0], -1, p) % p
        x = (slope * slope - a[0] - b[0]) % p
        return x, (slope * (a[0] - x) - a[1]) % p
    result, addend, k = None, (gx, gy), int.from_bytes(scalar, "big")
    while k:
        if k & 1:
            result = add(result, addend)
        addend = add(addend, addend)
        k >>= 1
    return b"\x04" + result[0].to_bytes(width, "big") + result[1].to_bytes(width, "big")


def point_xy(key):
    """The public point as X and Y hex for P-256/P-384, from the key or its
    private scalar; None when it is not an uncompressed point."""
    public = key.public if key.public else (ec_public(key.kind, key.private) if key.private else None)
    width = CURVES[key.kind][3]
    if public is None or len(public) != 1 + 2 * width or public[0] != 4:
        return None
    return public[1:1 + width].hex(), public[1 + width:].hex()


def scalar_hex(key):
    return key.private.rjust(CURVES[key.kind][3], b"\0").hex()


def ecdh(source, summary):
    lines = []
    blocks = stanzas(source / "evppkey_ecdh.txt")
    keys = keys_of(blocks)
    for stanza in blocks:
        if provider_only(stanza):
            if get(stanza, "Derive"):
                summary["evppkey_ecdh.txt: FIPS-provider-only derive checks"] += 1
            continue
        if get(stanza, "Derive"):
            mine = keys[get(stanza, "Derive")]
            peer_name = get(stanza, "PeerKey") or get(stanza, "PeerKeyValidate")
            peer = keys[peer_name]
            if mine.kind != "p256":
                summary[f"evppkey_ecdh.txt: {mine.kind} derive (only P-256 ECDH is implemented)"] += 1
                continue
            xy = point_xy(peer) if peer.kind == "p256" else None
            result = get(stanza, "Result", "ok")
            if xy is None:
                lines.append(f"derive {result} {scalar_hex(mine)} - - {value_hex(get(stanza, 'SharedSecret'))}")
            else:
                lines.append(f"derive {result} {scalar_hex(mine)} {xy[0]} {xy[1]} {value_hex(get(stanza, 'SharedSecret'))}")
        elif get(stanza, "PrivPubKeyPair"):
            mine, theirs = (keys[n] for n in get(stanza, "PrivPubKeyPair").split(":"))
            if mine.kind != "p256":
                summary[f"evppkey_ecdh.txt: {mine.kind} key pair (only P-256 ECDH is implemented)"] += 1
                continue
            xy = point_xy(theirs)
            lines.append(f"keypair {get(stanza, 'Result', 'ok')} {scalar_hex(mine)} {xy[0]} {xy[1]}")
    return lines


def ecdsa(source, summary):
    lines = []
    for name in ("evppkey_ecdsa.txt", "evppkey_ecdsa_rfc6979.txt"):
        blocks = stanzas(source / name)
        keys = keys_of(blocks)
        for stanza in blocks:
            if provider_only(stanza):
                summary[f"{name}: FIPS-provider-only policy checks"] += 1
                continue
            result = get(stanza, "Result", "ok")
            if get(stanza, "PrivPubKeyPair"):
                mine, theirs = (keys[n] for n in get(stanza, "PrivPubKeyPair").split(":"))
                if mine.kind not in CURVES:
                    summary[f"{name}: {mine.kind} key pair (curve not implemented)"] += 1
                    continue
                xy = point_xy(theirs)
                lines.append(f"keypair {mine.kind} {result} {scalar_hex(mine)} {xy[0]} {xy[1]}")
                continue
            for operation in ("Verify", "DigestVerify", "OneShotDigestVerify", "DigestSign", "Sign"):
                if get(stanza, operation) is not None:
                    break
            else:
                continue
            if operation in ("Verify", "Sign"):
                key = keys[get(stanza, operation)]
                hash_name = (get(stanza, "Ctrl") or "digest:none").partition(":")[2]
            else:
                key = keys[get(stanza, "Key")]
                hash_name = get(stanza, operation)
            hash_name = DIGESTS.get(hash_name.lower(), hash_name.lower())
            if key.kind not in CURVES:
                summary[f"{name}: {operation} with a {key.kind} key (curve or encoding not implemented)"] += 1
                continue
            if operation == "Sign" or (operation == "DigestSign" and (key.kind != "p256" or get(stanza, "NonceType") != "deterministic")):
                summary[f"{name}: {operation} on {key.kind} (only deterministic P-256 signing is implemented)"] += 1
                continue
            if operation == "DigestSign":
                lines.append(f"digestsign {key.kind} {hash_name} {scalar_hex(key)} {value_hex(get(stanza, 'Input'))} {value_hex(get(stanza, 'Output'))}")
                continue
            xy = point_xy(key)
            kind = "verify" if operation == "Verify" else "digestverify"
            lines.append(f"{kind} {key.kind} {hash_name} {xy[0]} {xy[1]} {value_hex(get(stanza, 'Input'))} "
                         f"{value_hex(get(stanza, 'Output'))} {result}")
    return lines


def hexs(value):
    return value.hex() if value else "-"


def x25519(source, summary):
    lines = []
    blocks = stanzas(source / "evppkey_ecx.txt")
    keys = keys_of(blocks)
    for stanza in blocks:
        if provider_only(stanza):
            if get(stanza, "Derive"):
                summary["evppkey_ecx.txt: FIPS-provider-only derive checks"] += 1
            continue
        if get(stanza, "Derive"):
            mine, peer = keys[get(stanza, "Derive")], keys[get(stanza, "PeerKey")]
            if mine.kind != "x25519":
                summary[f"evppkey_ecx.txt: {mine.kind} derive (curve not implemented)"] += 1
                continue
            lines.append(f"derive {get(stanza, 'Result', 'ok')} {hexs(mine.private)} {hexs(peer.public)} {value_hex(get(stanza, 'SharedSecret'))}")
        elif get(stanza, "PrivPubKeyPair"):
            mine, theirs = (keys[n] for n in get(stanza, "PrivPubKeyPair").split(":"))
            if mine.kind != "x25519" or theirs.kind != "x25519":
                summary[f"evppkey_ecx.txt: {mine.kind}/{theirs.kind} key pair (curve not implemented)"] += 1
                continue
            lines.append(f"keypair {get(stanza, 'Result', 'ok')} {hexs(mine.private)} {hexs(theirs.public)}")
        elif any(get(stanza, k) for k in ("OneShotDigestSign", "OneShotDigestVerify", "Sign", "Verify")):
            summary["evppkey_ecx.txt: Ed25519/Ed448 signatures (not implemented)"] += 1
    return lines


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
    for name, convert in (("digest", digest), ("hmac", hmac), ("hkdf", hkdf), ("cipher", cipher),
                          ("x25519", x25519), ("ecdh", ecdh), ("ecdsa", ecdsa)):
        lines = convert(source, summary)
        (OUT / f"{name}.txt").write_text("\n".join(lines) + "\n")
        print(f"{name}.txt: {len(lines)} cases")
    (OUT / "SUMMARY.txt").write_text("".join(f"{count} {what}\n" for what, count in sorted(summary.items())))
    used = ["evpmd_sha.txt", "evpmac_common.txt", "evpkdf_hkdf.txt", "evppkey_kdf_hkdf.txt",
            "evpciph_aes_common.txt", "evpciph_chacha.txt", "evppkey_ecx.txt", "evppkey_ecdh.txt",
            "evppkey_ecdsa.txt", "evppkey_ecdsa_rfc6979.txt"]
    (OUT / "SOURCE-SHA256SUMS").write_text(
        "".join(f"{hashlib.sha256((source / n).read_bytes()).hexdigest()}  {n}\n" for n in used))


if __name__ == "__main__":
    main()
