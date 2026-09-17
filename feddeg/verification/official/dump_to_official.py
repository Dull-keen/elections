#!/usr/bin/env python3
"""Convert a raw DEG blockchain dump to the official observer-tool format.

The observer tool does not consume the JSONL blockchain dump directly.  It
expects one ZIP archive per voting, containing a semicolon-separated CSV with
these twelve fields::

    nestedTxId;type;signature;version;ts;senderPublicKey;fee;feeAssetId;
    params;diff;extra;rollback

``params``, ``diff`` and ``extra`` are JSON strings.  This adapter deliberately
uses only the Python standard library, so it can also be used on Windows/WSL
(the observer tool itself still has the official CryptoPro/Linux dependency).

The raw dump is read only.  The output directory must not already exist unless
``--force`` is supplied.

Examples::

    python dump_to_official.py \
        --dump /data/edg2025.zip \
        --out /data/edg2025-official

    python dump_to_official.py \
        --dump /data/edg2025.zip \
        --out /data/one-voting \
        --contracts D6amFqdazz8DxfxUxmFZKpFioXhhEXQ3jkgRMeab1A4t
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import shutil
import sys
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Iterator, TextIO

STATE_OPERATIONS = {
    "addMainKey",
    "startVoting",
    "finishVoting",
    "decryption",
    "commissionDecryption",
    "results",
}


def log(message: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)


def official_entry(entry: dict) -> dict:
    """Convert a node ``{key,type,value}`` entry to portal spelling."""
    kind = entry["type"]
    value = entry["value"]
    output = {"key": entry["key"]}
    if kind == "string":
        output["stringValue"] = value
    elif kind == "integer":
        output["intValue"] = value
    elif kind == "boolean":
        output["boolValue"] = value
    elif kind == "binary":
        if not isinstance(value, str) or not value.startswith("base64:"):
            raise ValueError(f"binary entry without base64 prefix: {entry['key']}")
        # The official parser expects base64 without the node's ``base64:``
        # marker.  It decodes the same bytes when reconstructing signatures.
        output["binaryValue"] = value[len("base64:"):]
    else:
        raise ValueError(f"unknown data entry type {kind!r} for key {entry['key']}")
    return output


def json_field(entries: list[dict]) -> str:
    """Serialize one CSV JSON field without introducing a semicolon."""
    text = json.dumps(entries, ensure_ascii=False, separators=(",", ":"))
    if ";" in text:
        # The official parser splits on semicolons before JSON.parse.  Escaping
        # the character keeps the serialized value lossless after JSON.parse.
        text = text.replace(";", "\\u003b")
    if "\n" in text or "\r" in text:
        raise ValueError("raw newline in serialized entries")
    return text


def csv_line(tx: dict, results: list[dict], *, rollback: str = "") -> tuple[str, str, list[dict]]:
    """Return ``(CSV line, contract id, official diff entries)`` for one tx."""
    inner = tx["tx"]
    inner_type = inner["type"]
    params = [official_entry(entry) for entry in inner.get("params") or []]
    diff = [official_entry(entry) for entry in results]
    proofs = inner.get("proofs") or []
    signature = proofs[0] if proofs else ""

    if inner_type == 103:
        extra = {
            "image": inner.get("image") or "",
            "imageHash": inner.get("imageHash") or "",
            "contractName": inner.get("contractName") or "",
        }
        # A createContract transaction's own id is the contract id.
        contract_id = inner["id"]
    elif inner_type == 104:
        extra = {"contractVersion": inner.get("contractVersion", 0)}
        contract_id = inner["contractId"]
    else:
        raise ValueError(f"unexpected inner transaction type {inner_type}")

    extra_text = json.dumps(extra, ensure_ascii=False, separators=(",", ":"))
    # ``extra`` is also a semicolon-delimited field, even though the normal
    # image/name values do not contain semicolons.
    extra_text = extra_text.replace(";", "\\u003b")
    fields = [
        inner["id"],
        str(inner_type),
        signature,
        str(inner["version"]),
        str(inner["timestamp"]),
        inner["senderPublicKey"],
        str(inner.get("fee", 0)),
        inner.get("feeAssetId") or "",
        json_field(params),
        json_field(diff),
        extra_text,
        rollback,
    ]
    return ";".join(fields), contract_id, diff


def _iter_plain_file(path: Path) -> Iterator[str]:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        yield from handle


def iter_dump_lines(path: Path) -> Iterator[str]:
    """Yield JSONL lines from a plain file, ZIP, gzip file, or chunk directory."""
    path = Path(path)
    if path.is_dir():
        files = sorted(
            child for child in path.iterdir()
            if child.is_file() and child.suffix.lower() in {".json", ".jsonl"}
        )
        if not files:
            raise ValueError(f"no .json/.jsonl chunks found in {path}")
        for child in files:
            yield from _iter_plain_file(child)
        return

    if path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as archive:
            members = sorted(
                name for name in archive.namelist()
                if not name.endswith("/") and Path(name).suffix.lower() in {".json", ".jsonl"}
            )
            if not members:
                raise ValueError(f"no .json/.jsonl member found in {path}")
            for name in members:
                with archive.open(name, "r") as binary:
                    # TextIOWrapper streams decompression; the full 20 GB JSON
                    # member is never materialized in memory.
                    import io
                    with io.TextIOWrapper(binary, encoding="utf-8", errors="replace") as text:
                        yield from text
        return

    if path.suffix.lower() == ".gz":
        import gzip
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
            yield from handle
        return

    yield from _iter_plain_file(path)


class CsvSink:
    """Append per-contract CSV lines while bounding open file descriptors."""

    def __init__(self, directory: Path, max_open: int = 256) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.max_open = max_open
        self.handles: collections.OrderedDict[str, TextIO] = collections.OrderedDict()
        self.stats: dict[str, dict] = {}

    def path(self, contract_id: str) -> Path:
        return self.directory / f"{contract_id}.csv"

    def write(self, contract_id: str, line: str, operation: str, timestamp: int) -> None:
        handle = self.handles.get(contract_id)
        if handle is None:
            if len(self.handles) >= self.max_open:
                _, evicted = self.handles.popitem(last=False)
                evicted.close()
            handle = self.path(contract_id).open("a", encoding="utf-8")
            self.handles[contract_id] = handle
        else:
            self.handles.move_to_end(contract_id)
        handle.write(line)
        handle.write("\n")

        stats = self.stats.setdefault(contract_id, {
            "lines": 0,
            "bytes": 0,
            "operations": collections.Counter(),
            "ts_min": timestamp,
            "ts_max": timestamp,
        })
        stats["lines"] += 1
        stats["bytes"] += len(line) + 1
        stats["operations"][operation] += 1
        stats["ts_min"] = min(stats["ts_min"], timestamp)
        stats["ts_max"] = max(stats["ts_max"], timestamp)

    def close(self) -> None:
        for handle in self.handles.values():
            handle.close()
        self.handles.clear()


def operation_of(params: list[dict], inner_type: int) -> str:
    for entry in params:
        if entry["key"] == "operation":
            return str(entry["value"])
    return "createContract" if inner_type == 103 else "?"


def convert_dump(
    dump: Path,
    sink: CsvSink,
    contracts: set[str] | None = None,
    max_blocks: int | None = None,
    state_dir: Path | None = None,
    skip_blocks: int = 0,
) -> collections.Counter:
    """Stream the raw dump into ``sink`` and return conversion counters."""
    if skip_blocks < 0 or (max_blocks is not None and max_blocks < 1):
        raise ValueError("skip_blocks must be nonnegative and max_blocks positive")

    counts: collections.Counter = collections.Counter()
    started = time.time()
    seen_blocks = 0
    for line_number, line in enumerate(iter_dump_lines(Path(dump)), 1):
        if not line.strip():
            continue
        seen_blocks += 1
        if seen_blocks <= skip_blocks:
            continue
        if max_blocks is not None and seen_blocks > max_blocks:
            break
        try:
            block = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"invalid JSON in block {seen_blocks} (input line {line_number})") from error

        for transaction in block.get("transactions") or []:
            if transaction.get("type") != 105:
                counts["skipped:not-contract-tx"] += 1
                continue
            inner = transaction.get("tx")
            if not isinstance(inner, dict) or inner.get("type") not in (103, 104):
                counts["skipped:not-create-or-invoke"] += 1
                continue
            try:
                text, contract_id, diff = csv_line(transaction, transaction.get("results") or [])
            except (KeyError, TypeError, ValueError) as error:
                counts["skipped:conversion-error"] += 1
                if counts["skipped:conversion-error"] <= 5:
                    log(f"conversion error in block {seen_blocks}: {error}")
                continue
            if contracts is not None and contract_id not in contracts:
                counts["skipped:filtered"] += 1
                continue
            operation = operation_of(inner.get("params") or [], inner["type"])
            sink.write(contract_id, text, operation, int(inner["timestamp"]))
            counts[f"op:{operation}"] += 1

            if state_dir is not None and (inner["type"] == 103 or operation in STATE_OPERATIONS):
                state_dir.mkdir(parents=True, exist_ok=True)
                with (state_dir / f"{contract_id}.jsonl").open("a", encoding="utf-8") as output:
                    output.write(json.dumps({
                        "operation": operation,
                        "txId": inner["id"],
                        "ts": inner["timestamp"],
                        "results": diff,
                    }, ensure_ascii=False, separators=(",", ":")) + "\n")

        if seen_blocks and seen_blocks % 5000 == 0:
            log(f"{seen_blocks} blocks, {counts.get('op:vote', 0)} vote lines, "
                f"{counts.get('op:blindSigIssue', 0)} blindSigIssue lines "
                f"({time.time() - started:.0f}s)")

    counts["blocks"] = seen_blocks
    return counts


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 22), b""):
            digest.update(chunk)
    return digest.hexdigest()


def zip_one(csv_path: Path, zip_path: Path) -> tuple[str, int, str]:
    temporary = zip_path.with_name(zip_path.name + ".part")
    with zipfile.ZipFile(temporary, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        archive.write(csv_path, arcname=csv_path.name)
    os.replace(temporary, zip_path)
    return csv_path.stem, zip_path.stat().st_size, sha256_file(csv_path)


def parse_contracts(value: str | None) -> set[str] | None:
    if value is None:
        return None
    contracts = {item.strip() for item in value.split(",") if item.strip()}
    if not contracts:
        raise ValueError("--contracts must contain at least one id")
    return contracts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--dump", type=Path, required=True,
                        help="raw JSONL dump, ZIP/gzip dump, or directory of JSONL chunks")
    parser.add_argument("--out", type=Path, required=True,
                        help="new output directory containing files/<contractId>.zip")
    parser.add_argument("--csv-dir", type=Path, default=None,
                        help="intermediate CSV directory (default: OUT/csv)")
    parser.add_argument("--contracts", help="comma-separated contract id filter")
    parser.add_argument("--max-blocks", type=int)
    parser.add_argument("--skip-blocks", type=int, default=0)
    parser.add_argument("--keep-csv", action="store_true", help="retain intermediate CSV files")
    parser.add_argument("--state", action="store_true", help="also write selected state changes as JSONL")
    parser.add_argument("--workers", type=int, default=min(16, os.cpu_count() or 4))
    parser.add_argument("--force", action="store_true",
                        help="delete an existing OUT directory before writing (use explicitly)")
    args = parser.parse_args(argv)

    if args.workers < 1:
        parser.error("--workers must be positive")
    if args.skip_blocks < 0:
        parser.error("--skip-blocks must be nonnegative")
    if args.max_blocks is not None and args.max_blocks < 1:
        parser.error("--max-blocks must be positive")
    if not args.dump.exists():
        parser.error(f"dump does not exist: {args.dump}")

    out = args.out.resolve()
    if out.exists():
        if not args.force:
            parser.error(f"output already exists; choose a new path or pass --force: {out}")
        shutil.rmtree(out)
    out.mkdir(parents=True)

    csv_dir = (args.csv_dir or out / "csv").resolve()
    if csv_dir.exists():
        if not args.force:
            parser.error(f"CSV output already exists: {csv_dir}")
        shutil.rmtree(csv_dir)
    files_dir = out / "files"
    files_dir.mkdir()
    state_dir = out / "state" if args.state else None
    contracts = parse_contracts(args.contracts)

    log(f"converting {args.dump} -> {csv_dir}")
    sink = CsvSink(csv_dir)
    started = time.time()
    try:
        counts = convert_dump(args.dump, sink, contracts, args.max_blocks, state_dir,
                              args.skip_blocks)
    finally:
        sink.close()
    log(f"parsed in {time.time() - started:.1f}s: "
        + ", ".join(f"{key}={value}" for key, value in sorted(counts.items())
                     if not key.startswith("op:")))

    log(f"zipping {len(sink.stats)} contracts with {args.workers} threads")
    manifest = {
        "dump": str(args.dump.resolve()),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "counts": dict(counts),
        "contracts": {},
    }
    jobs = [(sink.path(contract), files_dir / f"{contract}.zip")
            for contract in sorted(sink.stats)]
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = list(pool.map(lambda paths: zip_one(*paths), jobs))
    for (csv_path, _zip_path), (contract, zip_size, digest) in zip(jobs, results):
        stats = sink.stats[contract]
        manifest["contracts"][contract] = {
            "lines": stats["lines"],
            "csv_bytes": stats["bytes"],
            "zip_bytes": zip_size,
            "csv_sha256": digest,
            "operations": dict(sorted(stats["operations"].items())),
            "ts_min": stats["ts_min"],
            "ts_max": stats["ts_max"],
        }
        if not args.keep_csv:
            csv_path.unlink()

    if not args.keep_csv and csv_dir.exists():
        csv_dir.rmdir()
    (out / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=1, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    total_lines = sum(item["lines"] for item in manifest["contracts"].values())
    total_zip = sum(item["zip_bytes"] for item in manifest["contracts"].values())
    log(f"done: {len(manifest['contracts'])} contracts, {total_lines} transaction lines, "
        f"{total_zip / 2**20:.1f} MiB of zips in {time.time() - started:.1f}s")
    log(f"manifest: {out / 'manifest.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
