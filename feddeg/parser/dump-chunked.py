#!/usr/bin/env python3
"""Resumable, chunked dump of the DEG blockchain.

The configured observer hosts are discovered at startup.  Hosts that return the
same blocks at several shared heights are treated as replicas of one logical
chain; hosts that disagree are written to separate output directories instead
of being merged and double-counted.

Every downloaded block is validated before an atomic rename.  Existing chunks
from an older run are validated before they are resumed, so this script can
replace an earlier version mid-dump: it continues from state.json, keeps the
chunk format the directory already uses (.jsonl or .jsonl.gz - a directory the
previous version started gzipped stays gzipped) and never re-downloads a range
that is already on disk.

Seven chains run in parallel, fetching one bounded block at a time directly into gzip.
No whole chunks are buffered or prefetched. All operational settings are hardcoded;
run this script without flags from the directory containing block-dump.  Every log line is
timestamped (MSK) and the dump lines carry the chain height together with a rate-based ETA, e.g.

  [18.09 20:14:03] shard-0: wrote 000009001-000009100.jsonl.gz from 172.25.26.139;
      height 9100/9152 (99.4%); 132.7 MB -> 18.4 MB (7.2x); 38 blocks/min; ETA 00:01:22
"""

from __future__ import annotations

import argparse
import contextlib
import gzip
import hashlib
import json
import os
import random
import signal
from email.utils import parsedate_to_datetime
import re
import sys
import tempfile
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

import requests


# Keep all known observers in deterministic order.  The old script assumed that
# fixed pairs were logical shards; the captured data showed that this can be
# false when chains share a long prefix or the observer topology changes.
OBSERVER_NODES = (
    # Inventory names are i<host>nodeobs<NN>, where the two-digit NN is the observer index inside
    # the DEG.  The indices known on 2026-09-18 are 05, 15, 25, 35, 45, 55, 65 - observer #5 of
    # seven different slots - spread over three physical hosts (i102, i115, i121):
    "172.25.26.139",   # i102nodeobs05
    "172.25.26.200",   # i102nodeobs65
    "172.25.154.135",  # i115nodeobs15
    "172.25.154.197",  # i115nodeobs45
    "172.25.218.135",  # i121nodeobs25
    "172.25.218.138",  # i121nodeobs35
    "172.25.218.199",  # i121nodeobs55
)
# Observer index -> slot, decoded from the inventory names: i102nodeobs05 is observer 05, i.e.
# observer #5 of slot 0 (index = slot * 10 + 5).  Used only to give a new chain a meaningful
# directory name; a chain we already have keeps the name from its state.json instead.
OBSERVER_SLOTS = {
    "172.25.26.139": "0",   # i102nodeobs05
    "172.25.26.200": "6",   # i102nodeobs65
    "172.25.154.135": "1",  # i115nodeobs15
    "172.25.154.197": "4",  # i115nodeobs45
    "172.25.218.135": "2",  # i121nodeobs25
    "172.25.218.138": "3",  # i121nodeobs35
    "172.25.218.199": "5",  # i121nodeobs55
}
DEFAULT_CHUNK_SIZE = 100
STATE_SCHEMA = 3
CHUNK_NAME = re.compile(r"^(\d+)-(\d+)\.jsonl(\.gz)?$")
MSK = timezone(timedelta(hours=3))
COMPRESSION_CHOICES = ("auto", "gzip", "none")

# Seven chain workers, one HTTP block each; compress before fetching the next block.
# Chunk count is NOT a memory bound: block sizes vary substantially on the actual USB dump.
SHARD_WORKERS = 7
FETCH_DEPTH = 1
MAX_INFLIGHT_CHUNKS = 7    # compatibility only; no chunk buffering
INITIAL_CONCURRENCY = 7    # starting number of in-flight HTTP requests
MIN_CONCURRENCY = 1
MAX_CONCURRENCY = 7
CONCURRENCY_COOLDOWN = 30.0
MAX_RSS_MB = 900           # watchdog: drop to one request above this RSS
FSYNC_CHUNKS = True        # fsync each chunk; a lost tail is detected and re-fetched anyway
VERIFY_TAIL = 3            # newest chunks per chain re-read at startup (0 would skip the check)
RETRIES = 4                # attempts per node before moving to its replica
PROBE_RETRIES = 2          # attempts for discovery probes
RETRY_BACKOFF = 1.5        # first retry delay, doubling and jittered
# Status codes that mean "you are asking too often" rather than "this request is wrong".
THROTTLE_STATUSES = frozenset({429, 500, 502, 503, 504})
LOG_LOCK = threading.Lock()
LOG_PATH: Path | None = None
STOP = threading.Event()
# Bound decoded HTTP bytes BEFORE JSON parsing; oversized blocks fail closed.
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
REQUEST_DEADLINE = 90.0


def check_stop() -> None:
    if STOP.is_set():
        raise InterruptedError("download stopped")


def sync_directory(path: Path) -> None:
    # Windows has no portable directory fsync; files are synced before rename.
    if os.name != "posix":
        return
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

# Defaults are sized for the polling-station laptop: 4 GB of RAM shared with Windows/Linux and a
# browser.  One 100-block chunk is ~130 MB of parsed Python objects and the writer streams it out
# line by line, so peak RSS is roughly `max_inflight_chunks` x 130 MB (~520 MB by default) plus the
# interpreter.  Bigger machines can raise --shard-workers/--max-inflight-chunks; the memory
# watchdog (--max-rss-mb) is the backstop when a run still grows.


@dataclass(frozen=True)
class NodeObservation:
    node: str
    height: int
    probe_markers: tuple[str, ...]


@dataclass(frozen=True)
class ChainInfo:
    name: str
    nodes: tuple[str, ...]
    height: int
    probe_heights: tuple[int, ...]
    probe_markers: tuple[str, ...]

    @property
    def fingerprint(self) -> str:
        # The first block marker is stable as a persisted identity.  The other
        # probe markers are still checked live but their heights are dynamic.
        return self.probe_markers[0]


def log(message: str) -> None:
    """Timestamped (MSK) stderr line - the dump runs for hours, hours matter.

    With --log-file the same line is appended to that file, so a hang or a power cut still leaves
    evidence of what the script was doing.
    """
    stamp = datetime.now(MSK).strftime("%d.%m %H:%M:%S")
    line = f"[{stamp}] {message}"
    with LOG_LOCK:
        print(line, file=sys.stderr, flush=True)
        if LOG_PATH is not None:
            try:
                with LOG_PATH.open("a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
            except OSError:
                pass


def resident_memory_mb() -> float | None:
    """Resident set size of this process in MB, or None if it cannot be read here."""
    try:
        with open("/proc/self/status", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) / 1024
    except (OSError, ValueError, IndexError):
        pass
    try:
        import resource

        usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return usage / 1024 if sys.platform != "darwin" else usage / (1024 * 1024)
    except Exception:  # noqa: BLE001 - resource is absent on Windows
        return None


def start_memory_watchdog(limiter: AdaptiveLimiter, limit_mb: int | None, interval: float = 10.0,
                          report_every: int = 6):
    """Shrink concurrency when the process grows past --max-rss-mb, and keep RSS in the log.

    On a small laptop the dump can push the machine into swap, which feels exactly like a hang, and
    the usual cause is too many parsed chunks in memory.  The watchdog logs the number (every
    `report_every` samples, so ~a minute) and drops to one in-flight request when the limit is
    crossed, so the backlog drains instead of growing.  The RSS line is what makes "was it my
    script?" answerable after the fact: a hang with a flat 300 MB line is not a memory problem.
    """
    stop = threading.Event()

    def watch() -> None:
        warned = False
        tick = 0
        while not stop.wait(interval):
            rss = resident_memory_mb()
            if rss is None:
                return
            tick += 1
            if limit_mb and rss > limit_mb:
                if not warned:
                    log(f"memory watchdog: RSS {rss:.0f} MB exceeds --max-rss-mb {limit_mb}; "
                        f"lowering concurrency (reduce --max-inflight-chunks if this repeats)")
                    warned = True
                limiter.force_minimum(f"RSS {rss:.0f} MB over {limit_mb} MB")
            elif limit_mb and warned and rss < limit_mb * 0.7:
                warned = False
            if report_every and tick % report_every == 0:
                log(f"memory: RSS {rss:.0f} MB"
                    + (f" (limit {limit_mb} MB)" if limit_mb else "")
                    + f", concurrency {limiter.limit}")

    thread = threading.Thread(target=watch, name="memory-watchdog", daemon=True)
    thread.start()
    return stop


def human_bytes(value: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(value) < 1000 or unit == "TB":
            return f"{value:.1f} {unit}"
        value /= 1000
    return f"{value:.1f} TB"


def human_duration(seconds: float) -> str:
    if seconds < 0 or seconds != seconds or seconds == float("inf"):
        return "--:--:--"
    seconds = int(seconds)
    return f"{seconds // 3600:02d}:{seconds % 3600 // 60:02d}:{seconds % 60:02d}"


def open_chunk(path: Path):
    """Read a chunk file, transparently gunzipping .jsonl.gz."""
    if path.name.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8")
    return path.open(encoding="utf-8")


# A USB stick pulled out without sync/eject can lose whatever was written last, even though the
# atomic rename already happened: the file is there, but its tail (or the gzip footer) is gone.
# Only the newest few chunks are worth re-reading - the dump writes one chunk every ~15 s during a
# catch-up, so a time-based window would mean re-reading gigabytes at every start.  A damaged chunk
# is renamed aside, never deleted, so the range is simply fetched again.
DEFAULT_VERIFY_TAIL = 3


def verify_chunk(path: Path, start: int, end: int) -> str | None:
    """Return why a chunk is damaged, or None when it is complete.  Reads the whole chunk."""
    expected = end - start + 1
    height = start
    try:
        with open_chunk(path) as stream:
            for line in stream:
                if not line.strip():
                    return "blank line"
                block = json.loads(line)
                validate_block(block, height)
                height += 1
    except Exception as error:  # truncation shows up as EOFError, CRC errors, JSON errors, OSError
        return f"{type(error).__name__}: {error}"
    if height != end + 1:
        return f"holds {height - start} of {expected} blocks"
    return None


def quarantine_damaged_chunks(shard_dir: Path, verify_tail: int = DEFAULT_VERIFY_TAIL) -> list[str]:
    """Verify the newest `verify_tail` chunks and rename the damaged ones aside.

    `verify_tail` counts chunks, not seconds: the number of chunks written in the last N minutes
    depends on link speed, and during a catch-up that is one chunk every 15 s per chain - a time
    window would turn every start into gigabytes of re-reading.  The dumper writes chunks strictly in
    order, so damage from an unsynced unplug lives in the newest handful; raise --verify-tail if the
    machine was powered off in the middle of a fast catch-up.  Renaming keeps the bytes for
    forensics and drops the range out of `completed_through`, so it is fetched again.
    """
    chunks = chunk_paths(shard_dir)
    if not chunks or verify_tail <= 0:
        return []
    suspects = [(path, start, end) for path, start, end in chunks[-verify_tail:]]
    size = sum(path.stat().st_size for path, _start, _end in suspects)
    log(f"{shard_dir.name}: verifying newest {len(suspects)} chunk(s), {human_bytes(size)}")
    started = time.monotonic()
    messages: list[str] = []
    for path, start, end in suspects:
        reason = verify_chunk(path, start, end)
        if reason is None:
            continue
        stamp = datetime.now(MSK).strftime("%Y%m%dT%H%M%S%f")
        damaged = path.with_name(f"{path.name}.corrupt-{stamp}")
        try:
            path.rename(damaged)
            sync_directory(shard_dir)
        except OSError as error:
            raise RuntimeError(f"cannot quarantine damaged chunk {path}: {error}") from error
        messages.append(f"{path.name}: damaged ({reason}) -> {damaged.name}")
    if not messages:
        log(f"{shard_dir.name}: {len(suspects)} chunk(s) verified in {time.monotonic() - started:.1f}s")
    return messages


class Progress:
    """Blocks per minute and ETA for one chain, from the chunk write times.

    The rate is a rolling average over the last few chunks (a stalled node would drag a whole-run
    average down for hours), with the run average as the initial estimate.  ETA is only printed
    when there is a rate to extrapolate, so the first line of a pass never invents a number.
    """

    def __init__(self, chain_name: str, start_height: int, target_height: int, window: int = 5) -> None:
        self.chain_name = chain_name
        self.start_height = start_height
        self.target_height = target_height
        self.progress_height = max(start_height - 1, 0)
        self.started_at = time.monotonic()
        self.samples: deque[tuple[float, int]] = deque(maxlen=window)
        self.blocks_written = 0
        self.raw_bytes = 0
        self.stored_bytes = 0

    def update(self, completed: int, raw_bytes: int = 0, stored_bytes: int = 0) -> str:
        """Record a finished chunk and return the progress part of the log line."""
        self.blocks_written += max(0, completed - self.progress_height)
        self.progress_height = completed
        self.raw_bytes += raw_bytes
        self.stored_bytes += stored_bytes
        self.samples.append((time.monotonic(), completed))
        return self.describe()

    def blocks_per_minute(self) -> float:
        if len(self.samples) >= 2:
            (first_time, first_height), (last_time, last_height) = self.samples[0], self.samples[-1]
            elapsed = last_time - first_time
            if elapsed > 0:
                return (last_height - first_height) / elapsed * 60
        elapsed = time.monotonic() - self.started_at
        return self.blocks_written / elapsed * 60 if elapsed > 0 and self.blocks_written else 0.0

    def describe(self) -> str:
        total = max(self.target_height - self.start_height + 1, 0)
        remaining = max(self.target_height - self.progress_height, 0)
        percentage = 100.0 if not total else 100 * (total - remaining) / total
        parts = [f"height {self.progress_height}/{self.target_height} ({percentage:.1f}%)"]
        if self.blocks_written:
            parts.append(f"+{self.blocks_written} blocks this pass")
        rate = self.blocks_per_minute()
        if rate and remaining:
            parts.append(f"{rate:.0f} blocks/min")
            parts.append(f"ETA {human_duration(remaining / rate * 60)}")
        if self.raw_bytes and self.stored_bytes and self.raw_bytes != self.stored_bytes:
            ratio = self.raw_bytes / self.stored_bytes
            parts.append(f"{human_bytes(self.raw_bytes)} -> {human_bytes(self.stored_bytes)} ({ratio:.1f}x)")
        return "; ".join(parts)


def atomic_write(path: Path, content: str, fsync: bool = True) -> None:
    """Durably replace a small text file without exposing a partial version.

    fsync=False is for weak machines writing to slow USB sticks: the rename is still atomic, and a
    tail lost to an unsynced unplug is caught by the chunk verification on the next start.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as temporary:
            temporary.write(content)
            temporary.flush()
            if fsync:
                os.fsync(temporary.fileno())
        os.replace(temporary_name, path)
        if fsync:
            sync_directory(path.parent)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def block_fingerprint(block: dict[str, Any]) -> str:
    """Hash a canonical block representation for replica/chain comparisons."""
    encoded = json.dumps(
        block,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_block(block: Any, expected_height: int) -> dict[str, Any]:
    """Reject malformed or out-of-order blocks before they become durable."""
    if not isinstance(block, dict):
        raise ValueError(f"block {expected_height} is not an object")
    if block.get("height") != expected_height:
        raise ValueError(
            f"expected block height {expected_height}, got {block.get('height')!r}"
        )
    transactions = block.get("transactions")
    if not isinstance(transactions, list):
        raise ValueError(f"block {expected_height} has no transaction list")
    transaction_count = block.get("transactionCount")
    if transaction_count is not None and transaction_count != len(transactions):
        raise ValueError(
            f"block {expected_height} advertises {transaction_count} transactions, "
            f"received {len(transactions)}"
        )
    return block


def validate_blocks(payload: Any, start: int, end: int) -> list[dict[str, Any]]:
    """Validate an observer response, including every inclusive block height."""
    expected_count = end - start + 1
    if not isinstance(payload, list) or len(payload) != expected_count:
        actual = len(payload) if isinstance(payload, list) else type(payload).__name__
        raise ValueError(f"expected {expected_count} blocks for {start}-{end}, got {actual}")
    return [validate_block(block, start + offset) for offset, block in enumerate(payload)]


def chunk_paths(shard_dir: Path) -> list[tuple[Path, int, int]]:
    """Chunks in height order; both .jsonl and .jsonl.gz count as chunks."""
    chunks: list[tuple[Path, int, int]] = []
    for path in shard_dir.glob("*.jsonl*"):
        match = CHUNK_NAME.match(path.name)
        if match and path.is_file():
            chunks.append((path, int(match.group(1)), int(match.group(2))))
    return sorted(chunks, key=lambda item: item[1])


def chunk_suffix(shard_dir: Path) -> str | None:
    """Suffix of the newest chunk in a directory, or None when the directory is empty."""
    paths = chunk_paths(shard_dir)
    if not paths:
        return None
    return ".jsonl.gz" if paths[-1][0].name.endswith(".gz") else ".jsonl"


def chunk_format(shard_dir: Path, requested: str) -> str:
    """Resolve --compression: never change an existing directory's format.

    'auto' exists so this script can take over a running dump mid-flight: a directory keeps whatever
    it already uses (.jsonl stays .jsonl, .jsonl.gz stays packed) and a new one starts gzipped, the
    same default as the previous iteration, so a swapped-in script keeps writing the same files.
    """
    if requested != "auto":
        return requested
    suffix = chunk_suffix(shard_dir)
    if suffix is None:
        return "gzip"
    return "gzip" if suffix.endswith(".gz") else "none"


def completed_through(shard_dir: Path) -> int:
    """Return the end of the contiguous sequence of complete chunks."""
    expected_start = 1
    for _path, start, end in chunk_paths(shard_dir):
        if start != expected_start or end < start:
            break
        expected_start = end + 1
    return expected_start - 1


def validate_existing_chunks(shard_dir: Path) -> int:
    """Validate an old or untrusted directory and return its completed height."""
    expected_height = 1
    for path, start, end in chunk_paths(shard_dir):
        if start != expected_height or end < start:
            raise RuntimeError(
                f"{shard_dir}: chunk sequence is not contiguous before {path.name}"
            )
        lines = 0
        line_number = 0
        try:
            with open_chunk(path) as stream:
                for line_number, line in enumerate(stream, 1):
                    if not line.strip():
                        raise ValueError("blank JSONL line")
                    block = json.loads(line)
                    validate_block(block, expected_height)
                    expected_height += 1
                    lines += 1
        except (OSError, json.JSONDecodeError, ValueError) as error:
            raise RuntimeError(f"invalid block data in {path}:{line_number}: {error}") from error
        expected_lines = end - start + 1
        if lines != expected_lines:
            raise RuntimeError(
                f"{path}: filename promises {expected_lines} lines, found {lines}"
            )
    return expected_height - 1


def iter_blocks(shard_dir: Path) -> Iterator[dict[str, Any]]:
    """Yield blocks in height order; callers should validate the directory first."""
    for path, _start, _end in chunk_paths(shard_dir):
        with open_chunk(path) as stream:
            for line in stream:
                yield json.loads(line)


def write_chunk(
    path: Path,
    blocks: list[Any],
    start: int,
    end: int,
    compression: str = "none",
    level: int = 6,
    fsync: bool = True,
) -> tuple[int, int]:
    """Write a validated chunk atomically; returns (raw bytes, bytes on disk).

    Validation happens before the chunk becomes visible under its final name, and gzip output is
    written to a temporary file first, so an interrupted run never leaves a half-written chunk.
    """
    # Consume a generator: never materialize a 100-block chunk in memory.
    valid_blocks = iter(blocks)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    os.close(fd)
    raw_bytes = 0
    try:
        # Lines are written straight out: joining the whole chunk into one string first would add
        # another ~100 MB per writing chain, which is exactly the kind of spike that pushes a 4 GB
        # machine into swap.
        if compression == "gzip":
            stream = gzip.open(temporary_name, "wt", encoding="utf-8", compresslevel=level)
        else:
            stream = open(temporary_name, "w", encoding="utf-8")
        with stream:
            count = 0
            for block in valid_blocks:
                check_stop()
                validate_block(block, start + count)
                if start + count > end:
                    raise ValueError("too many blocks")
                line = json.dumps(block, ensure_ascii=False, separators=(",", ":")) + "\n"
                stream.write(line)
                raw_bytes += len(line.encode("utf-8"))
                count += 1
            if count != end - start + 1:
                raise ValueError("incomplete chunk")
        # gzip.close writes its footer: syncing BEFORE close loses that footer on power failure.
        if fsync:
            with open(temporary_name, "rb") as durable:
                os.fsync(durable.fileno())
        os.replace(temporary_name, path)
        if fsync:
            sync_directory(path.parent)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise
    return raw_bytes, path.stat().st_size


def read_json_file(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"cannot read {path}: {error}") from error
    if not isinstance(value, dict):
        raise RuntimeError(f"{path} does not contain a JSON object")
    return value


def last_existing_block_fingerprint(shard_dir: Path, completed: int) -> str | None:
    """Fingerprint of the block at `completed`, read from the chunk that ends there.

    The persisted chain identity is block 1, but two histories can share a genesis block and diverge
    afterwards (the September training chain and the election chain do exactly that: block 1 equal,
    block 2 different).  Before appending, the last stored block is compared with what the live chain
    serves at that height, so a changed history can be reconciled without silently mixing suffixes.
    """
    for path, start, end in reversed(chunk_paths(shard_dir)):
        if end != completed:
            continue
        last_line = None
        try:
            with open_chunk(path) as stream:
                for line in stream:
                    if line.strip():
                        last_line = line
        except OSError as error:
            raise RuntimeError(f"cannot read {path}: {error}") from error
        if last_line is None:
            return None
        block = json.loads(last_line)
        if not isinstance(block, dict) or block.get("height") != completed:
            return None
        return block_fingerprint(block)
    return None


def first_existing_block_fingerprint(shard_dir: Path) -> str | None:
    for path, start, _end in chunk_paths(shard_dir):
        if start != 1:
            continue
        try:
            with open_chunk(path) as stream:
                line = stream.readline()
            block = validate_block(json.loads(line), 1)
        except (OSError, json.JSONDecodeError, ValueError) as error:
            raise RuntimeError(f"cannot inspect first block in {path}: {error}") from error
        return block_fingerprint(block)
    return None


def quarantine_history_tail(shard_dir: Path, tail_height: int) -> tuple[int, list[str]]:
    """Move the chunk containing the local tail aside and return the new contiguous height.

    The live check is deliberately limited to the last stored block: the ledger is append-only, so
    only its tip may change between observations.  A chunk containing that block is moved in full;
    retaining its valid prefix would require rewriting an existing file.  Later dangling chunks are
    moved too, while the old bytes remain next to the dump for forensics.
    """
    chunks = chunk_paths(shard_dir)
    suffix = [(path, start, end) for path, start, end in chunks if end >= tail_height]
    if not suffix:
        raise RuntimeError(f"no stored chunk contains tail block {tail_height}")
    stamp = datetime.now(MSK).strftime("%Y%m%dT%H%M%S%f")
    preserved: list[str] = []
    try:
        for path, _start, _end in suffix:
            archived = path.with_name(f"{path.name}.history-{stamp}")
            counter = 2
            while archived.exists():
                archived = path.with_name(f"{path.name}.history-{stamp}-{counter}")
                counter += 1
            path.rename(archived)
            preserved.append(archived.name)
        sync_directory(shard_dir)
    except OSError as error:
        raise RuntimeError(f"cannot quarantine divergent history in {shard_dir}: {error}") from error
    return completed_through(shard_dir), preserved


class AdaptiveLimiter:
    """AIMD concurrency limiter for an unknown server-side rate limit.

    Additive increase on a run of successes, multiplicative decrease on a throttle signal (HTTP 429
    or 503, or a stall) - the same shape as TCP congestion control, which is the right response when
    the limit is unknown and only the server can tell us.  After every decrease the limit is frozen
    for a cooldown so the run cannot oscillate between "fast" and "throttled".  `slot()` is the
    only way to make a request, so the in-flight count can never exceed the current limit.
    """

    def __init__(self, initial: int = 4, minimum: int = 1, maximum: int = 8,
                 cooldown: float = 30.0, success_streak: int = 12) -> None:
        self.limit = max(minimum, min(initial, maximum))
        self.minimum = minimum
        self.maximum = maximum
        self.cooldown = cooldown
        self.success_streak = success_streak
        self.in_flight = 0
        self.throttles = 0
        self.slowdowns = 0
        self._successes = 0
        self._cooldown_until = 0.0
        self._condition = threading.Condition()

    @contextlib.contextmanager
    def slot(self):
        with self._condition:
            while self.in_flight >= self.limit:
                check_stop()
                self._condition.wait(timeout=0.2)
            check_stop()
            self.in_flight += 1
        try:
            yield
        finally:
            with self._condition:
                self.in_flight -= 1
                self._condition.notify_all()

    def note_success(self) -> None:
        with self._condition:
            if time.monotonic() < self._cooldown_until:
                return
            self._successes += 1
            if self._successes >= self.success_streak and self.limit < self.maximum:
                self.limit += 1
                self._successes = 0
                log(f"concurrency: limit raised to {self.limit}")
                self._condition.notify_all()

    def _decrease(self, reason: str, factor: float, counter: str) -> None:
        with self._condition:
            setattr(self, counter, getattr(self, counter) + 1)
            target = max(self.minimum, int(self.limit * factor))
            self._cooldown_until = time.monotonic() + self.cooldown
            self._successes = 0
            if target != self.limit:
                log(f"concurrency: {reason}; limit {self.limit} -> {target}")
                self.limit = target
            else:
                log(f"concurrency: {reason}; already at limit {self.limit}")
            self._condition.notify_all()

    def note_throttle(self, reason: str) -> None:
        self._decrease(reason, 0.5, "throttles")

    def note_stall(self, reason: str) -> None:
        self._decrease(reason, 0.75, "slowdowns")

    def force_minimum(self, reason: str) -> None:
        """Drop to one in-flight request - used by the memory watchdog."""
        with self._condition:
            self._cooldown_until = time.monotonic() + self.cooldown
            self._successes = 0
            if self.limit != self.minimum:
                log(f"concurrency: {reason}; limit {self.limit} -> {self.minimum}")
                self.limit = self.minimum
                self._condition.notify_all()

    def describe(self) -> str:
        return (f"concurrency limit {self.limit} (start {self.limit if not self.throttles else '?'}, "
                f"throttles {self.throttles}, slowdowns {self.slowdowns})")


class ShardClient:
    def __init__(self, nodes: tuple[str, ...], port: int, timeout: tuple[float, float],
                 limiter: AdaptiveLimiter | None = None, retries: int = 4,
                 backoff: float = 1.5, probe_retries: int = 2) -> None:
        self.nodes = nodes
        self.port = port
        self.timeout = timeout
        self.limiter = limiter or AdaptiveLimiter()
        self.retries = max(1, retries)
        self.probe_retries = max(1, probe_retries)
        self.backoff = max(0.1, backoff)
        # requests.Session is not thread-safe, so every worker thread gets its own session.
        self._local = threading.local()
        self._sessions: list[requests.Session] = []
        self._sessions_lock = threading.Lock()

    @property
    def session(self) -> requests.Session:
        session = getattr(self._local, "session", None)
        if session is None:
            session = requests.Session()
            # The dump host is isolated; only the configured private addresses may be contacted,
            # even if a proxy variable appears in its environment.
            session.trust_env = False
            self._local.session = session
            with self._sessions_lock:
                self._sessions.append(session)
        return session

    def sleep_backoff(self, attempt: int) -> None:
        """Exponential backoff with jitter: several chains retrying in lockstep is the best way to
        keep a limiter angry."""
        delay = min(self.backoff * (2 ** attempt), 30.0)
        STOP.wait(delay * (0.5 + random.random()))
        check_stop()

    def get_node_json(self, node: str, path: str) -> Any:
        # A node may be given as host or host:port; the port in the string wins.  Keeping the
        # original string in manifests/logs means a mixed-topology run stays readable, and it
        # also lets tests point at fake observers on ephemeral ports.
        host, _, port = node.partition(":")
        check_stop()
        started = time.monotonic()
        with self.session.get(f"http://{host}:{port or self.port}{path}",
                              timeout=self.timeout, stream=True, allow_redirects=False) as response:
            response.raise_for_status()
            body = bytearray()
            for piece in response.iter_content(64 * 1024):
                check_stop()
                if time.monotonic() - started > REQUEST_DEADLINE:
                    raise requests.Timeout("response deadline exceeded")
                if len(body) + len(piece) > MAX_RESPONSE_BYTES:
                    raise ValueError("response exceeds safe 32 MiB limit; refusing oversized block")
                body.extend(piece)
            return json.loads(body)

    def _retry_reason(self, error: BaseException) -> str | None:
        """Why retrying the same node makes sense, or None when it does not.

        A 429/503 or a timeout usually means "too fast, come back" - retry with backoff and shrink
        the concurrency limit.  A refused connection or a payload that is not the chain we expect
        means the node itself is unusable right now: move on to its replica immediately.
        """
        if isinstance(error, requests.HTTPError):
            status = error.response.status_code if error.response is not None else 0
            return f"HTTP {status}" if status in THROTTLE_STATUSES else None
        if isinstance(error, requests.Timeout):
            return "timeout"
        return None

    def _handle_retry(self, node: str, error: BaseException, attempt: int) -> None:
        reason = self._retry_reason(error) or ""
        if reason.startswith("HTTP"):
            self.limiter.note_throttle(f"{reason} from {node}")
        else:
            self.limiter.note_stall(f"{reason or type(error).__name__} from {node}")
        response = getattr(error, "response", None)
        retry_after = response.headers.get("Retry-After") if response is not None else None
        if retry_after:
            try:
                delay = float(retry_after)
            except ValueError:
                try:
                    delay = parsedate_to_datetime(retry_after).timestamp() - time.time()
                except (ValueError, TypeError, OverflowError):
                    delay = 0
            STOP.wait(max(0, delay))
            check_stop()
        self.sleep_backoff(attempt)

    def probe_json(self, node: str, path: str) -> Any:
        """GET a JSON probe with the same throttle-aware retry policy as block fetching.

        Probes get fewer attempts than data fetches: an unreachable node should cost seconds, not
        minutes, because discovery is what blocks the start of a pass.
        """
        last_error = "failed"
        for attempt in range(self.probe_retries):
            try:
                with self.limiter.slot():
                    payload = self.get_node_json(node, path)
                self.limiter.note_success()
                return payload
            except (requests.RequestException, ValueError) as error:
                reason = self._retry_reason(error)
                last_error = reason or f"{type(error).__name__}: {error}"
                if reason is None:
                    break
                self._handle_retry(node, error, attempt)
        raise RuntimeError(last_error)

    def discover_chains(self, existing_names: dict[str, str] | None = None) -> list[ChainInfo]:
        """Probe all observers and split them by their verified block sequence.

        existing_names maps a chain fingerprint to the directory that already holds it.  A chain we
        have keeps that name forever - naming by list position alone would rename chains whenever a
        node fails to answer, and the directories on disk would stop matching the observers.
        """
        heights: dict[str, int] = {}

        def height_of(node: str) -> tuple[str, int | str]:
            try:
                payload = self.probe_json(node, "/blocks/height")
                height = payload.get("height") if isinstance(payload, dict) else None
                if not isinstance(height, int) or height < 1:
                    return node, f"invalid height response: {payload!r}"
                return node, height
            except (RuntimeError, ValueError) as error:
                return node, str(error)

        # Discovery probes are independent, so they run in parallel: ten nodes with a few dead
        # addresses used to cost tens of seconds of sequential timeouts before the pass started.
        probe_workers = min(8, max(1, len(self.nodes)))
        with ThreadPoolExecutor(max_workers=probe_workers, thread_name_prefix="probe") as pool:
            height_results = list(pool.map(height_of, self.nodes))
        for node, value in height_results:
            if isinstance(value, int):
                heights[node] = value
            else:
                log(f"observer {node} unavailable for height: {value}")

        if not heights:
            raise RuntimeError("all configured observers failed for /blocks/height")

        minimum_height = min(heights.values())
        probe_heights = tuple(
            dict.fromkeys((1, max(1, minimum_height // 2), minimum_height))
        )

        def markers_of(node: str) -> tuple[str, tuple[str, ...] | str]:
            try:
                markers: list[str] = []
                for probe_height in probe_heights:
                    payload = self.probe_json(node, f"/blocks/seq/{probe_height}/{probe_height}")
                    blocks = validate_blocks(payload, probe_height, probe_height)
                    markers.append(block_fingerprint(blocks[0]))
                return node, tuple(markers)
            except (RuntimeError, ValueError) as error:
                return node, str(error)

        observations: list[NodeObservation] = []
        with ThreadPoolExecutor(max_workers=probe_workers, thread_name_prefix="probe") as pool:
            marker_results = list(pool.map(markers_of, list(heights)))
        for node, value in marker_results:
            if isinstance(value, tuple):
                observations.append(NodeObservation(node, heights[node], value))
            else:
                log(f"observer {node} failed chain probe: {value}")

        if not observations:
            raise RuntimeError("no observer passed the chain probes")

        groups: dict[tuple[str, ...], list[NodeObservation]] = {}
        for observation in observations:
            groups.setdefault(observation.probe_markers, []).append(observation)
        if len(groups) > 1:
            log(
                f"observers split into {len(groups)} distinct chain identities; "
                "writing separate chains instead of merging them"
            )

        order = {node: index for index, node in enumerate(self.nodes)}
        sorted_groups = sorted(groups.values(), key=lambda group: min(order[x.node] for x in group))
        known_names = existing_names or {}
        used_names: set[str] = set(known_names.values())
        chains: list[ChainInfo] = []
        assigned_names: set[str] = set()
        for group in sorted_groups:
            first_index = min(order[x.node] for x in group)
            fingerprint = group[0].probe_markers[0]
            slot = next(
                (OBSERVER_SLOTS[x.node.split(":")[0]] for x in group if x.node.split(":")[0] in OBSERVER_SLOTS),
                None,
            )
            base_name = f"shard-{slot}" if slot is not None else f"shard-{first_index // 2}"
            name = known_names.get(fingerprint) or base_name
            if name not in known_names.values() or name in assigned_names:
                suffix = 2
                while name in used_names:
                    name = f"{base_name}-fork-{suffix}"
                    suffix += 1
                used_names.add(name)
            assigned_names.add(name)
            chain = ChainInfo(
                name=name,
                nodes=tuple(x.node for x in group),
                height=max(x.height for x in group),
                probe_heights=probe_heights,
                probe_markers=group[0].probe_markers,
            )
            chains.append(chain)
            log(
                f"{name}: height {chain.height}; observers: {', '.join(chain.nodes)}; "
                f"fingerprint {chain.fingerprint[:12]}"
            )
        return chains

    def get_blocks(self, chain: ChainInfo, start: int, end: int) -> tuple[list[dict[str, Any]], str]:
        """Fetch a validated range, trying every verified replica before failing.

        Throttling and stalls are retried on the same node with backoff (and shrink the global
        concurrency limit); hard errors - a node that answers with the wrong number of blocks, or
        a different chain - move on to the next replica immediately.
        """
        errors: list[str] = []
        for node in chain.nodes:
            for attempt in range(self.retries):
                try:
                    with self.limiter.slot():
                        payload = self.get_node_json(node, f"/blocks/seq/{start}/{end}")
                    blocks = validate_blocks(payload, start, end)
                    self.limiter.note_success()
                    return blocks, node
                except (requests.RequestException, ValueError) as error:
                    reason = self._retry_reason(error)
                    errors.append(f"{node}: {reason or type(error).__name__}: {error}")
                    if reason is None:
                        break
                    self._handle_retry(node, error, attempt)
        raise RuntimeError(
            f"{chain.name}: all verified observers failed for {start}-{end}: {'; '.join(errors[-6:])}"
        )

    def close(self) -> None:
        with self._sessions_lock:
            for session in self._sessions:
                session.close()
            self._sessions.clear()


def load_known_chains(output_dir: Path) -> dict[str, ChainInfo]:
    """Chains we already have on disk, rebuilt from their state.json files.

    Used as a fallback when a node does not answer during discovery: a chain directory must not
    become "unexpected" just because its observer is briefly throttled or unreachable, otherwise a
    single hiccup at startup would abort the whole run.  The stored fingerprint is what keeps the
    directory trusted, and the stored node list is still tried when fetching.
    """
    chains: dict[str, ChainInfo] = {}
    if not output_dir.is_dir():
        return chains
    for directory in sorted(output_dir.glob("shard-*")):
        state_path = directory / "state.json"
        if not state_path.exists():
            continue
        try:
            state = read_json_file(state_path)
        except RuntimeError:
            fingerprint = first_existing_block_fingerprint(directory)
            if not fingerprint:
                continue
            state = {"chain_fingerprint": fingerprint, "shard": directory.name}
        fingerprint = state.get("chain_fingerprint")
        if not fingerprint:
            continue
        probe_heights = tuple(state.get("probe_heights") or ())
        markers = (fingerprint, *("" for _ in probe_heights[1:]))
        completed = int(state.get("completed_through") or 0)
        chains[fingerprint] = ChainInfo(
            name=state.get("shard") or directory.name,
            nodes=tuple(state.get("nodes") or ()),
            height=max(int(state.get("observed_height") or 0), completed),
            probe_heights=probe_heights,
            probe_markers=tuple(markers),
        )
    return chains


def write_state(path: Path, chain: ChainInfo, completed: int) -> None:
    atomic_write(
        path,
        json.dumps(
            {
                "schema": STATE_SCHEMA,
                "shard": chain.name,
                "nodes": list(chain.nodes),
                "chain_fingerprint": chain.fingerprint,
                "probe_heights": list(chain.probe_heights),
                "completed_through": completed,
                "observed_height": chain.height,
                "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
    )


def chunk_ranges(completed: int, height: int, chunk_size: int) -> list[tuple[int, int]]:
    """Chunk boundaries for the remaining height, computed up front so fetches can be queued."""
    ranges: list[tuple[int, int]] = []
    start = completed + 1
    while start <= height:
        end = min(start + chunk_size - 1, height)
        ranges.append((start, end))
        start = end + 1
    return ranges


def dump_shard(
    chain: ChainInfo,
    output_dir: Path,
    chunk_size: int,
    client: ShardClient,
    compression: str = "auto",
    gzip_level: int = 6,
    chunk_budget: threading.Semaphore | None = None,
) -> tuple[ChainInfo, Progress]:
    """Stream individual blocks into atomic gzip chunks; files, not state, determine resume."""
    shard_dir = output_dir / chain.name
    state_path = shard_dir / "state.json"
    shard_dir.mkdir(parents=True, exist_ok=True)
    try:
        state = read_json_file(state_path) if state_path.exists() else {}
    except RuntimeError:
        log(f"{chain.name}: damaged state.json; rebuilding from chunks")
        state = {}
    for message in quarantine_damaged_chunks(shard_dir, VERIFY_TAIL):
        log(f"{chain.name}: {message}")
    # Recomputing from the surviving files is what makes a quarantined chunk get re-fetched.
    completed = completed_through(shard_dir)

    # Old files predate chain fingerprints.  Validate them once, then write
    # schema-3 state so subsequent resumptions can rely on atomic chunks.
    if completed and (state.get("schema") != STATE_SCHEMA or not state.get("chain_fingerprint")):
        validation_started = time.monotonic()
        completed = validate_existing_chunks(shard_dir)
        log(f"{chain.name}: validated legacy chunks through {completed} "
            f"({time.monotonic() - validation_started:.1f}s; this full read happens once per "
            f"directory, later starts only check the newest chunks)")

    existing_first = first_existing_block_fingerprint(shard_dir)
    if existing_first is not None and existing_first != chain.probe_markers[0]:
        raise RuntimeError(f"{chain.name}: existing files belong to a different chain")
    saved_fingerprint = state.get("chain_fingerprint")
    if saved_fingerprint is not None and saved_fingerprint != chain.fingerprint:
        raise RuntimeError(f"{chain.name}: state file belongs to a different chain")
    if completed > chain.height:
        raise RuntimeError(
            f"{chain.name}: saved height {completed} exceeds observed height {chain.height}"
        )

    # Check the local tail even when it is exactly the observed tip: under the append-only model,
    # only that last block may have changed between observations.  If it did, the containing chunk
    # is rewritten below and the dump still ends in a contiguous, current state.
    if completed and chain.nodes:
        local_tail = last_existing_block_fingerprint(shard_dir, completed)
        if local_tail is None:
            raise RuntimeError(f"{chain.name}: cannot identify stored tail")
        try:
            blocks, _node = client.get_blocks(chain, completed, completed)
            live_tail = block_fingerprint(blocks[0])
        except RuntimeError as error:
            raise RuntimeError(f"{chain.name}: cannot verify live history; refusing to append") from error
        if local_tail != live_tail:
            # The only permitted mismatch is the local tip.  Rewriting its containing chunk keeps
            # the active JSONL sequence contiguous without touching the older, trusted chunks.
            tail_height = completed
            completed, preserved = quarantine_history_tail(shard_dir, tail_height)
            log(
                f"{chain.name}: live tail differs at block {tail_height}; preserved "
                f"{len(preserved)} old chunk(s) and resumed from {completed + 1}"
            )
        else:
            log(f"{chain.name}: tail check ok (block {completed} matches the live chain)")

    start = completed + 1
    mode = chunk_format(shard_dir, compression)
    suffix = ".jsonl.gz" if mode == "gzip" else ".jsonl"
    backlog = max(chain.height - completed, 0)
    progress = Progress(chain.name, start, chain.height)
    log(
        f"{chain.name}: resuming at {start}; height {chain.height}; {backlog} block(s) behind; "
        f"writing {suffix}" + (f", gzip level {gzip_level}" if mode == "gzip" else "")
    )
    write_state(state_path, chain, completed)

    def store(start_height: int, end_height: int, blocks: list[Any], node: str) -> None:
        chunk_path = shard_dir / f"{start_height:09d}-{end_height:09d}{suffix}"
        raw_bytes, stored_bytes = write_chunk(
            chunk_path, blocks, start_height, end_height, mode, gzip_level, FSYNC_CHUNKS
        )
        write_state(state_path, chain, end_height)
        log(
            f"{chain.name}: wrote {chunk_path.name} from {node}; "
            f"{progress.update(end_height, raw_bytes, stored_bytes)}"
        )

    # Respect surviving ranges after a corrupt chunk, even when old chunk sizes differ.
    survivors = {a: (path, b) for path, a, b in chunk_paths(shard_dir)}
    cursor = completed + 1
    while cursor <= chain.height:
        check_stop()
        if cursor in survivors:
            path, end = survivors[cursor]
            reason = verify_chunk(path, cursor, end)
            if reason:
                raise RuntimeError(f"invalid surviving chunk {path}: {reason}")
            cursor = end + 1
            write_state(state_path, chain, end)
            continue
        next_start = min((a for a in survivors if a > cursor), default=chain.height + 1)
        end = min(cursor + chunk_size - 1, chain.height, next_start - 1)

        def fetch_blocks():
            for height in range(cursor, end + 1):
                check_stop()
                blocks, _node = client.get_blocks(chain, height, height)
                yield blocks[0]
                del blocks

        store(cursor, end, fetch_blocks(), ", ".join(chain.nodes))
        cursor = end + 1
    return chain, progress


def check_existing_directories(output_dir: Path, chains: list[ChainInfo]) -> None:
    """Fail closed instead of silently mixing stale directories into new output."""
    active_names = {chain.name for chain in chains}
    unexpected = sorted(
        path.name
        for path in output_dir.glob("shard-*")
        if path.is_dir() and path.name not in active_names
    )
    if unexpected:
        raise RuntimeError(
            "unexpected existing chain directories: "
            + ", ".join(unexpected)
            + "; move them aside or use a fresh --output-dir"
        )


def write_manifest(output_dir: Path, chains: list[ChainInfo]) -> None:
    atomic_write(
        output_dir / "manifest.json",
        json.dumps(
            {
                "schema": STATE_SCHEMA,
                "active_chains": [
                    {
                        "name": chain.name,
                        "nodes": list(chain.nodes),
                        "height": chain.height,
                        "chain_fingerprint": chain.fingerprint,
                    }
                    for chain in chains
                ],
                "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
    )


def parse_args() -> argparse.Namespace:
    """All operational parameters are deliberately hardcoded; run without flags."""
    return argparse.Namespace(
        output_dir=Path("block-dump"), chunk_size=100, port=6862,
        connect_timeout=5.0, read_timeout=10.0, node=[], follow=True,
        poll_seconds=30.0, compression="gzip", gzip_level=1,
        log_file=Path("block-dump/dump.log"),
    )


def lock_output(output_dir: Path):
    """OS lock releases on crashes, unlike a stale PID marker."""
    handle = (output_dir / ".dump.lock").open("a+b")
    try:
        if os.name == "nt":
            import msvcrt
            handle.write(b"0")
            handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as error:
        handle.close()
        raise RuntimeError("another dumper holds this output directory") from error
    return handle


def main() -> int:
    args = parse_args()
    # Linux/WSL: enforce a process ceiling, not merely a reactive RSS warning.
    # Allocation failure leaves only an unpublished temporary chunk. Other platforms
    # retain bounded HTTP responses and one-block-at-a-time processing.
    if sys.platform.startswith("linux"):
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        ceiling = 3 * 1024 ** 3
        if soft != resource.RLIM_INFINITY:
            ceiling = min(ceiling, soft)
        if hard != resource.RLIM_INFINITY:
            ceiling = min(ceiling, hard)
        resource.setrlimit(resource.RLIMIT_AS, (ceiling, hard))
    STOP.clear()
    signal.signal(signal.SIGINT, lambda *_: STOP.set())
    signal.signal(signal.SIGTERM, lambda *_: STOP.set())
    global LOG_PATH
    LOG_PATH = args.log_file
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    output_lock = lock_output(output_dir)
    log(f"writing unique chains to {output_dir}")
    limiter = AdaptiveLimiter(
        initial=INITIAL_CONCURRENCY,
        minimum=MIN_CONCURRENCY,
        maximum=MAX_CONCURRENCY,
        cooldown=CONCURRENCY_COOLDOWN,
    )
    budget = threading.Semaphore(MAX_INFLIGHT_CHUNKS)
    watchdog = start_memory_watchdog(limiter, MAX_RSS_MB)
    client = ShardClient(
        tuple(args.node) if args.node else OBSERVER_NODES,
        args.port,
        (args.connect_timeout, args.read_timeout),
        limiter=limiter,
        retries=RETRIES,
        backoff=RETRY_BACKOFF,
        probe_retries=PROBE_RETRIES,
    )
    try:
        pass_number = 0
        while True:
            check_stop()
            pass_number += 1
            pass_started = time.monotonic()
            discovery_started = time.monotonic()
            try:
                chains = client.discover_chains(
                    {fingerprint: cached.name for fingerprint, cached in load_known_chains(output_dir).items()}
                )
            except RuntimeError as error:
                log(f"discovery failed: {error}; retrying in {args.poll_seconds}s")
                client.close()
                STOP.wait(args.poll_seconds)
                continue
            # Offline/legacy directories are preserved, not fetched through stale node lists.
            active_names = {chain.name for chain in chains}
            for directory in output_dir.glob("shard-*"):
                if directory.is_dir() and directory.name not in active_names:
                    log(f"{directory.name}: preserved offline (no verified active observer)")
            # Startup cost is otherwise invisible: a slow resume is either discovery, the tail
            # verification or the legacy full validation, and each now reports its own time.
            log(f"discovery: {len(chains)} chain(s) in {time.monotonic() - discovery_started:.1f}s")
            workers = SHARD_WORKERS or len(chains)
            log(
                f"pass {pass_number}: {len(chains)} chain(s), heights "
                + ", ".join(f"{chain.name}={chain.height}" for chain in chains)
                + f"; chain workers {max(1, min(workers, len(chains)))}, fetch depth {FETCH_DEPTH}, "
                f"concurrency {limiter.limit}-{limiter.maximum}, memory cap {MAX_INFLIGHT_CHUNKS} chunks, "
                f"fsync {'on' if FSYNC_CHUNKS else 'off'}, RSS limit {MAX_RSS_MB or 'off'} MB, "
                f"verify tail {VERIFY_TAIL} chunk(s)"
            )
            progress_list: list[Progress] = []
            failures: dict[str, str] = {}
            with ThreadPoolExecutor(
                max_workers=max(1, min(workers, len(chains))), thread_name_prefix="chain"
            ) as pool:
                futures = {
                    pool.submit(
                        dump_shard, chain, output_dir, args.chunk_size, client,
                        args.compression, args.gzip_level, budget,
                    ): chain
                    for chain in chains
                }
                for future in as_completed(futures):
                    chain = futures[future]
                    try:
                        _dumped, progress = future.result()
                        progress_list.append(progress)
                    except Exception as error:  # one bad chain must not kill the rest
                        failures[chain.name] = f"{type(error).__name__}: {error}"
                        log(f"{chain.name}: FAILED this pass - {failures[chain.name]}")
            check_stop()
            write_manifest(output_dir, chains)
            total_blocks = sum(progress.blocks_written for progress in progress_list)
            total_stored = sum(progress.stored_bytes for progress in progress_list)
            total_raw = sum(progress.raw_bytes for progress in progress_list)
            log(
                f"pass {pass_number} done in {human_duration(time.monotonic() - pass_started)}: "
                f"{len(progress_list)}/{len(chains)} chain(s) caught up, {total_blocks} block(s) "
                f"written, {human_bytes(total_raw)} raw -> {human_bytes(total_stored)} on disk; "
                f"{limiter.describe()}; RSS {resident_memory_mb() or 0:.0f} MB"
            )
            if failures:
                log("failed chains: " + "; ".join(f"{name} ({error[:80]})" for name, error in failures.items()))
            if not args.follow:
                return 1 if failures else 0
            client.close()  # worker threads are recreated each pass; do not retain their sessions
            log(f"pass finished; retry/poll in {args.poll_seconds:g} seconds")
            STOP.wait(args.poll_seconds)
            check_stop()
    finally:
        if watchdog is not None:
            watchdog.set()
        client.close()
        output_lock.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyboardInterrupt, InterruptedError, requests.RequestException) as error:
        log(f"stopped: {type(error).__name__}: {error}")
        raise SystemExit(130)
    except Exception as error:
        log(f"failed: {type(error).__name__}: {error}")
        raise SystemExit(1)
