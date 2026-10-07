#!/usr/bin/env python3
"""Guard fixture/oracle/batch harnesses independently of the native implementation."""
from collections import Counter
import contextlib
import hashlib
import io
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import check_argon as argon
import check_blake as blake


class PasswordKdfTests(unittest.TestCase):
    def test_blake_counts_and_parameterized_output(self):
        self.assertEqual(Counter(case[-1] for case in blake.cases()), {"rfc7693": 1, "blake2b": 770, "hprime": 102})
        self.assertNotEqual(hashlib.blake2b(b"abc", digest_size=32).digest(), hashlib.blake2b(b"abc").digest()[:32])

    def test_hprime_boundaries(self):
        for invalid in (-1, 0, 0x100000000):
            with self.assertRaises(ValueError): blake.expand(b"", invalid)
        for length in (1, 32, 64):
            self.assertEqual(blake.expand(b"abc", length), hashlib.blake2b(struct.pack("<I", length) + b"abc", digest_size=length).digest())
        first = hashlib.blake2b(struct.pack("<I", 65) + b"abc").digest()
        self.assertEqual(blake.expand(b"abc", 65), first[:32] + hashlib.blake2b(first, digest_size=33).digest())

    def test_argon_fixture_identity_and_coverage(self):
        fixture = argon.load_fixture()
        cases = fixture["cases"]
        self.assertEqual(Counter(case["group"] for case in cases), {"rfc9106": 1, "quick": 135, "extended": 2})
        self.assertEqual(cases[0]["expected"], "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
        self.assertEqual({case["lanes"] for case in cases}, {1, 2, 3, 4, 7, 8, 17, 64})
        self.assertTrue(any(case["memory_kib"] % (4 * case["lanes"]) for case in cases))
        self.assertTrue(any(case["length"] == 65536 for case in cases))

    def test_mutated_fixture_rejected(self):
        with patch.object(Path, "read_bytes", return_value=b"{}"):
            with self.assertRaisesRegex(AssertionError, "fixture digest"): argon.load_fixture()

    def test_argon_serial_parallel_batch_fingerprint(self):
        seen = []
        def checked(command):
            data = Path(command[1]).read_bytes()
            self.assertTrue(data.startswith(argon.MAGIC))
            count, = struct.unpack_from("<I", data, 8)
            position = 12
            for _ in range(count):
                identity, memory, passes, lanes, workers = struct.unpack_from("<IIIII", data, position)
                position += 20
                self.assertGreaterEqual(memory, 8 * lanes)
                self.assertGreaterEqual(passes, 1)
                seen.append((identity, workers))
                for _ in range(5):
                    length, = struct.unpack_from("<I", data, position)
                    position += 4 + length
                    self.assertLessEqual(position, len(data))
            self.assertEqual(position, len(data))
            return SimpleNamespace(stdout=f"PASS argon batch {count}\n".encode())
        with patch.object(argon, "checked", side_effect=checked), contextlib.redirect_stdout(io.StringIO()) as output:
            argon.check_argon("unused")
        self.assertEqual(len(seen), 493)
        self.assertIn("d5eb7622bf99ada4a4dec07f46aa56fe8fb4b729e5502b696c24728bb08e156d", output.getvalue())
        self.assertEqual({workers for _, workers in seen}, {1, 2, 4, 8})

    def test_failures_saved_and_readonly_original_preserved(self):
        for module, run in ((argon, argon.check_argon), (blake, blake.check_blake)):
            with tempfile.TemporaryDirectory() as temporary, patch.object(module, "ROOT", Path(temporary)), \
                 patch.object(module, "checked", side_effect=AssertionError("sentinel")), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(AssertionError, "sentinel"): run("unused")
                saved = list((Path(temporary) / "build/failures").iterdir())
                self.assertEqual(len(saved), 1)
                self.assertTrue(saved[0].read_bytes().startswith(module.MAGIC))
            with patch.object(module, "checked", side_effect=AssertionError("sentinel")), \
                 patch.object(Path, "mkdir", side_effect=OSError("readonly")), contextlib.redirect_stdout(io.StringIO()) as output:
                with self.assertRaisesRegex(AssertionError, "sentinel"): run("unused")
                self.assertIn("REPRO_UNAVAILABLE", output.getvalue())


if __name__ == "__main__": unittest.main()
