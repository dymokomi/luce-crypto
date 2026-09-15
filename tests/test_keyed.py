#!/usr/bin/env python3
from collections import Counter
import contextlib
import hashlib
import io
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import check_keyed as keyed


class KeyedTests(unittest.TestCase):
    def test_counts_and_rfc_agreement(self):
        self.assertEqual(Counter(case[-1] for case in keyed.cases()),
                         {"rfc_hmac": 21, "generated_hmac": 504, "generated_hkdf": 225, "rfc_hkdf": 3})

    def test_corpus_fingerprint(self):
        records = [keyed.encode(index, case) for index, case in enumerate(keyed.cases())]
        digest = hashlib.sha256()
        for start in range(0, len(records), 64):
            group = records[start:start + 64]
            digest.update(keyed.MAGIC + struct.pack("<I", len(group)) + b"".join(group))
        self.assertEqual(digest.hexdigest(), "f803e4371704a49259ed7499364a4460ac88474b435a1f52f2f6eff41401a500")

    def test_record_roundtrip(self):
        case = next(keyed.cases())
        data = keyed.encode(42, case)
        self.assertEqual(struct.unpack_from("<III", data), (42, 1, 256))
        position, fields = 12, []
        for _ in range(5):
            length, = struct.unpack_from("<I", data, position)
            position += 4
            fields.append(data[position:position + length])
            position += length
        self.assertEqual(position, len(data))
        self.assertEqual(fields, list(case[2:7]))

    def test_bad_rfc_data_rejected(self):
        damaged = list(keyed.HMAC_TAGS["sha256"])
        damaged[0] = "00" * 32
        with patch.dict(keyed.HMAC_TAGS, {"sha256": damaged}):
            with self.assertRaisesRegex(AssertionError, "RFC 4231"): next(keyed.cases())

    def test_kdf_bounds(self):
        for algorithm, size in (("sha256", 32), ("sha384", 48), ("sha512", 64)):
            self.assertEqual(keyed.derive(algorithm, b"", b"", b"", 0)[1], b"")
            self.assertEqual(len(keyed.derive(algorithm, b"", b"", b"", 255 * size)[1]), 255 * size)
            for length in (-1, 255 * size + 1):
                with self.assertRaises(ValueError): keyed.derive(algorithm, b"", b"", b"", length)

    def test_failure_saved(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(keyed, "ROOT", Path(temporary)), \
             patch.object(keyed, "checked", side_effect=AssertionError("sentinel")), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(AssertionError, "sentinel"): keyed.check_keyed("unused")
            saved = list((Path(temporary) / "build/failures").iterdir())
            self.assertEqual(len(saved), 1)
            self.assertTrue(saved[0].read_bytes().startswith(keyed.MAGIC))

    def test_readonly_preserves_failure(self):
        with patch.object(keyed, "checked", side_effect=AssertionError("sentinel")), \
             patch.object(Path, "mkdir", side_effect=OSError("readonly")), contextlib.redirect_stdout(io.StringIO()) as output:
            with self.assertRaisesRegex(AssertionError, "sentinel"): keyed.check_keyed("unused")
            self.assertIn("REPRO_UNAVAILABLE", output.getvalue())


if __name__ == "__main__": unittest.main()
