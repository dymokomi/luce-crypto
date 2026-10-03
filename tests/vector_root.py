"""Where the test vectors live: the luce-crypto-vectors checkout.

LUCE_CRYPTO_VECTORS names it; otherwise it is ../luce-crypto-vectors beside
this checkout (bootstrap/PACKAGES pins its revision). A missing checkout is an
error, never a reason to skip tests.
"""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def vector_root():
    path = Path(os.environ.get("LUCE_CRYPTO_VECTORS") or ROOT.parent / "luce-crypto-vectors").resolve()
    if not (path / "NOTICE.md").is_file():
        raise SystemExit(f"luce-crypto test vectors not found at {path}: clone "
                         "https://github.com/dymokomi/luce-crypto-vectors beside luce-crypto "
                         "(at the revision in bootstrap/PACKAGES) or set LUCE_CRYPTO_VECTORS")
    return path
