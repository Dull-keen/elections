#!/usr/bin/env python3
"""Create balanced batch directories for the official observer tool.

The observer tool's batch mode derives an id from the part before the first
underscore in each filename.  Therefore the links are intentionally named
``<contractId>_dump.zip`` rather than just ``<contractId>.zip``.

``BASE`` must be the directory produced by ``dump_to_official.py`` and contain
``files/`` plus ``manifest.json``.  The script never changes those files.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
from pathlib import Path


def link_or_copy(source: Path, destination: Path, *, copy: bool) -> None:
    if copy:
        if source.is_dir():
            shutil.copytree(source, destination)
        else:
            shutil.copy2(source, destination)
        return
    try:
        # Relative links keep a batch directory relocatable.
        destination.symlink_to(
            os.path.relpath(source, destination.parent),
            target_is_directory=source.is_dir(),
        )
    except (OSError, NotImplementedError) as error:
        raise RuntimeError(
            f"cannot create a symlink at {destination}; rerun with --copy on "
            "a platform without symlink support"
        ) from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, required=True,
                        help="official export directory (contains files/manifest.json)")
    parser.add_argument("--batches", type=int, default=24,
                        help="number of batches (default: %(default)s)")
    parser.add_argument("--copy", action="store_true",
                        help="copy archives instead of creating symlinks")
    parser.add_argument("--force", action="store_true",
                        help="replace an existing BASE/batches directory")
    args = parser.parse_args(argv)

    base = args.base.resolve()
    manifest_path = base / "manifest.json"
    files_dir = base / "files"
    if not manifest_path.is_file():
        parser.error(f"manifest not found: {manifest_path}")
    if not files_dir.is_dir():
        parser.error(f"files directory not found: {files_dir}")
    if args.batches < 1:
        parser.error("--batches must be positive")

    try:
        contracts = json.loads(manifest_path.read_text(encoding="utf-8"))["contracts"]
    except (OSError, json.JSONDecodeError, KeyError) as error:
        parser.error(f"invalid manifest: {error}")

    output = base / "batches"
    if output.exists():
        if not args.force:
            parser.error(f"batch directory already exists; pass --force: {output}")
        shutil.rmtree(output)
    output.mkdir()

    buckets: list[list[tuple[str, int]]] = [[] for _ in range(args.batches)]
    loads = [0] * args.batches
    for contract, stats in sorted(contracts.items(), key=lambda item: -item[1]["lines"]):
        index = min(range(args.batches), key=loads.__getitem__)
        lines = int(stats["lines"])
        buckets[index].append((contract, lines))
        loads[index] += lines

    for index, bucket in enumerate(buckets):
        directory = output / f"batch-{index:02d}"
        batch_files = directory / "files"
        batch_files.mkdir(parents=True)
        library = base / "lib"
        if library.exists():
            link_or_copy(library, directory / "lib", copy=args.copy)
        for contract, _lines in bucket:
            source = files_dir / f"{contract}.zip"
            if not source.is_file():
                raise FileNotFoundError(source)
            link_or_copy(source, batch_files / f"{contract}_dump.zip", copy=args.copy)

    print(f"created {args.batches} batches, {len(contracts)} contracts, "
          f"{sum(loads):,} transaction lines; largest batch {max(loads):,}")
    if not (base / "lib").exists():
        print("warning: BASE/lib is missing; native official runs need the two shared libraries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
