#!/usr/bin/env python3
"""Resumable, chunked dump of the three DEG blockchain shards.

Each shard has two observer nodes.  The second node is only a fallback for the
same shard: downloading both would duplicate the blockchain data.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import requests


# Nodes 5 and 6 are replicas of one shard, not separate data sources.
SHARDS = {
    "shard-0": ("172.25.26.139", "172.25.202.132"),
    "shard-1": ("172.25.10.133", "172.25.154.135"),
    "shard-2": ("172.25.138.146", "172.25.218.135"),
}
DEFAULT_CHUNK_SIZE = 100
CHUNK_NAME = re.compile(r"^(\d+)-(\d+)\.jsonl$")


def log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def atomic_write(path: Path, content: str) -> None:
    """Durably replace a small text file without exposing a partial version."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as temporary:
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def write_chunk(path: Path, blocks: list[Any]) -> None:
    # A chunk is only visible under its final name after every line is written.
    content = "".join(
        json.dumps(block, ensure_ascii=False, separators=(",", ":")) + "\n"
        for block in blocks
    )
    atomic_write(path, content)


def completed_through(shard_dir: Path) -> int:
    """Return the end of the contiguous sequence of already complete chunks."""
    expected_start = 1
    chunks: list[tuple[int, int]] = []
    for path in shard_dir.glob("*.jsonl"):
        match = CHUNK_NAME.match(path.name)
        if match:
            chunks.append((int(match.group(1)), int(match.group(2))))
    for start, end in sorted(chunks):
        if start != expected_start or end < start:
            break
        expected_start = end + 1
    return expected_start - 1


class ShardClient:
    def __init__(self, nodes: tuple[str, ...], port: int, timeout: tuple[float, float]) -> None:
        self.nodes = nodes
        self.port = port
        self.timeout = timeout
        self.session = requests.Session()
        # The dump host is isolated; only the configured private addresses may
        # be contacted, even if a proxy variable appears in its environment.
        self.session.trust_env = False

    def get_json(self, path: str) -> tuple[Any, str]:
        errors = []
        for node in self.nodes:
            url = f"http://{node}:{self.port}{path}"
            try:
                response = self.session.get(url, timeout=self.timeout)
                response.raise_for_status()
                return response.json(), node
            except (requests.RequestException, ValueError) as error:
                errors.append(f"{node}: {type(error).__name__}: {error}")
        raise RuntimeError(f"all observer nodes failed for {path}: {'; '.join(errors)}")

    def close(self) -> None:
        self.session.close()


def dump_shard(
    name: str,
    nodes: tuple[str, ...],
    output_dir: Path,
    chunk_size: int,
    port: int,
    timeout: tuple[float, float],
) -> None:
    shard_dir = output_dir / name
    state_path = shard_dir / "state.json"
    start = completed_through(shard_dir) + 1
    client = ShardClient(nodes, port, timeout)
    try:
        height_value, height_node = client.get_json("/blocks/height")
        if not isinstance(height_value, dict) or not isinstance(height_value.get("height"), int):
            raise RuntimeError(f"{height_node} returned an invalid /blocks/height response")
        height = height_value["height"]
        log(f"{name}: height {height} from {height_node}; resuming at {start}")

        while start <= height:
            end = min(start + chunk_size - 1, height)
            chunk_path = shard_dir / f"{start:09d}-{end:09d}.jsonl"
            if chunk_path.exists():
                # A previous process may have completed the atomic rename just
                # before interruption; accept it and refresh state below.
                log(f"{name}: keeping existing {chunk_path.name}")
            else:
                blocks, source_node = client.get_json(f"/blocks/seq/{start}/{end}")
                if not isinstance(blocks, list) or len(blocks) != end - start + 1:
                    actual = len(blocks) if isinstance(blocks, list) else type(blocks).__name__
                    raise RuntimeError(
                        f"{name}: expected {end - start + 1} blocks for {start}-{end}, got {actual}"
                    )
                write_chunk(chunk_path, blocks)
                log(f"{name}: wrote {chunk_path.name} from {source_node}")

            atomic_write(
                state_path,
                json.dumps(
                    {
                        "schema": 1,
                        "shard": name,
                        "nodes": list(nodes),
                        "completed_through": end,
                        "observed_height": height,
                        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
            )
            start = end + 1
    finally:
        client.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("block-dump"),
        help="directory for per-shard JSONL chunks (default: %(default)s)",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=DEFAULT_CHUNK_SIZE,
        help="blocks per durable JSONL chunk (default: %(default)s)",
    )
    parser.add_argument("--port", type=int, default=6862, help="observer-node HTTP port (default: %(default)s)")
    parser.add_argument("--connect-timeout", type=float, default=5.0)
    parser.add_argument("--read-timeout", type=float, default=60.0)
    parser.add_argument(
        "--follow",
        action="store_true",
        help="keep polling for new blocks after each complete pass",
    )
    parser.add_argument(
        "--poll-seconds",
        type=float,
        default=30.0,
        help="delay between --follow passes (default: %(default)s)",
    )
    args = parser.parse_args()
    if (
        args.chunk_size < 1
        or not 1 <= args.port <= 65535
        or args.connect_timeout <= 0
        or args.read_timeout <= 0
        or args.poll_seconds <= 0
    ):
        parser.error("chunk size, port, timeouts, and poll interval must be positive")
    return args


def main() -> int:
    args = parse_args()
    output_dir = args.output_dir.resolve()
    log(f"writing chunks to {output_dir}")
    while True:
        for name, nodes in SHARDS.items():
            dump_shard(
                name,
                nodes,
                output_dir,
                args.chunk_size,
                args.port,
                (args.connect_timeout, args.read_timeout),
            )
        if not args.follow:
            return 0
        log(f"all shards caught up; waiting {args.poll_seconds:g} seconds")
        time.sleep(args.poll_seconds)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyboardInterrupt, requests.RequestException) as error:
        log(f"stopped: {type(error).__name__}: {error}")
        raise SystemExit(130)
    except Exception as error:
        log(f"failed: {type(error).__name__}: {error}")
        raise SystemExit(1)
