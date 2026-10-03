#!/usr/bin/env python3
import hashlib
from pathlib import Path
import tempfile
import unittest
from check_hashes import vectors, cases, ROOT


class VectorTests(unittest.TestCase):
    def test_pinned_files(self):
        for line in (ROOT / "tests/vectors/SHA256SUMS").read_text().splitlines():
            expected, name = line.split("  ")
            self.assertEqual(hashlib.sha256((ROOT / "tests/vectors" / name).read_bytes()).hexdigest(), expected)

    def test_all_counts(self):
        counts = {"nist": 0, "generated": 0}
        for _, _, _, group in cases(): counts[group] += 1
        self.assertEqual(counts, {"nist": 643, "generated": 1629})

    def test_rejects_malformed(self):
        for text in ("Len = 8\nMsg = 00\n", "Len = 1\nMsg = 00\nMD = ff\n",
                     "Len = 16\nMsg = 00\nMD = ff\n", "Len = 0\nMsg = ff\nMD = ff\n",
                     "Len = 8\nLen = 8\nMsg = 00\nMD = ff\n"):
            with self.subTest(text=text), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "vector.rsp"
                path.write_text(text)
                with self.assertRaises(AssertionError): list(vectors(path))

    def test_empty_placeholder(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "vector.rsp"
            path.write_text("# test\n[L = 32]\n\nLen = 0\nMsg = 00\nMD = ff\n")
            self.assertEqual(list(vectors(path)), [(b"", b"\xff")])


if __name__ == "__main__": unittest.main()
