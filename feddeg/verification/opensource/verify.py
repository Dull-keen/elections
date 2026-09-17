#!/usr/bin/env python3
"""Verify an original DEG blockchain dump without creating intermediate files.

Usage::

    python3 verify.py /data/edg2025.zip
    python3 verify.py /data/edg2025.zip --results-only
    python3 verify.py /data/edg2025.zip --workers 4

Transactions are read as a stream.  The verifier retains only contract state,
voter-key uniqueness sets and one Jacobian ciphertext accumulator per active
election; it does not materialize the raw dump or write CSV/report files.
"""

from __future__ import annotations

import sys

# The verifier is intentionally read-only: do not create Python bytecode files
# next to the source while importing the crypto package.
sys.dont_write_bytecode = True

import argparse
from pathlib import Path

from crypto.stream import verify


def positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("dump", type=Path,
                        help="original JSONL, ZIP/gzip dump, or JSONL chunk directory")
    parser.add_argument(
        "--results-only", action="store_true",
        help="skip transaction/ballot signatures and checks; only aggregate ciphertexts and verify results",
    )
    parser.add_argument(
        "--workers", "--threads", dest="workers", type=positive_int, default=1,
        help="parallel ballot-verification processes (default: 1)",
    )
    args = parser.parse_args(argv)
    if not args.dump.exists():
        parser.error(f"dump does not exist: {args.dump}")
    return verify(args.dump, workers=args.workers, results_only=args.results_only)


if __name__ == "__main__":
    raise SystemExit(main())
