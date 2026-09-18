#!/usr/bin/env python3
"""Build the standard DEG tables (README format) from a dump plus portal metadata.

Tables, all joinable on contract_id (written to --out):
  elections.csv          contract_id,region,election,district
  results.csv            contract_id,candidates,results
  ballots.csv            contract_id,uik,timestamp
  votes.csv              contract_id,timestamp
  voter_list_events.csv  contract_id,uik,timestamp,count,type
  per_contract.csv       dump-vs-portal diagnostic, not part of the published set

voter_list_events.csv replaced the aggregate uiks.csv in 2026: with in-person voting a voter
leaves the electronic list, so the list is a stream of events, not a fixed number.  One row per
chain transaction, `type` is the chain operation folded to initial/addVotersList, restore/
addToVotersList and remove/removeFromVotersList, `count` is the number of voter hashes in that
transaction (removals are always one voter).  The chain carries no reason for a removal, so
`remove` is "left the electronic list": in 2026 that is almost always in-person voting, but it is
a proxy, not proof.  Electronic votes are anonymous, so a removed voter who also voted remotely
is undetectable from these tables alone.

Optional extras, so that one command reproduces the whole delivery:
  --archive DEST          ZIP with the five published tables; DEST may be a directory,
                          then the name is feddeg_<MSK timestamp>.zip inside it
  --turnout-comparison P  PNG with one histogram panel per dataset (the side-by-side
                          turnout graph); older datasets come from --reference LABEL=ZIP

Metadata comes from the observation portal API (stat.vybory.gov.ru/api), which is
open for reading; responses are cached under --cache so reruns are cheap.

Typical run (dump already on disk, no copying involved):

  python3 parse.py --dump /media/sereja/Terabyte/deg/block-dump \
      --out /tmp/feddeg-run/tables --cache /tmp/feddeg-portal-cache \
      --archive ../../data/feddeg-data \
      --turnout-comparison turnout_comparison_2024_2025_2026.png \
      --reference 2024=../../data/feddeg-data/edg2024.zip \
      --reference 2025=../../data/feddeg-data/edg2025.zip
"""

from __future__ import annotations

import argparse
import gzip
import json
import re
import sys
import threading
import time
import zipfile
from collections import defaultdict
from collections.abc import Iterable, Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import requests

API = "https://stat.vybory.gov.ru/api"
MSK = timezone(timedelta(hours=3))
# Chain operation -> published event type.  The chain has no other list operations.
LIST_EVENT_TYPES = {
    "addVotersList": "initial",
    "addToVotersList": "restore",
    "removeFromVotersList": "remove",
}
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/140.0 Safari/537.36"
    )
}
PRINT_LOCK = threading.Lock()


def as_uik(value):
    """The portal/dump send the UIK number as a string; the published tables use ints."""
    return int(value) if isinstance(value, str) and value.isdigit() else value


def log(message: str) -> None:
    with PRINT_LOCK:
        print(message, file=sys.stderr, flush=True)


class Portal:
    def __init__(self, cache_dir: Path, workers: int = 8, base: str = API) -> None:
        self.cache_dir = cache_dir
        self.base = base.rstrip("/")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.pool = ThreadPoolExecutor(workers)
        self.calls = 0
        self.cache_hits = 0

    def path_to_file(self, path: str) -> Path:
        safe = "".join(character if character.isalnum() or character in "-." else "_" for character in path)
        return self.cache_dir / f"{safe[:180]}.json"

    def get(self, path: str, attempts: int = 4):
        cached = self.path_to_file(path)
        if cached.exists():
            self.cache_hits += 1
            return json.loads(cached.read_text())
        last_error: Exception | None = None
        for attempt in range(attempts):
            try:
                response = self.session.get(f"{self.base}/{path}", timeout=45)
                if response.status_code == 200:
                    payload = response.json()
                    cached.write_text(json.dumps(payload, ensure_ascii=False))
                    self.calls += 1
                    return payload
                last_error = RuntimeError(f"HTTP {response.status_code} for {path}")
            except Exception as error:  # noqa: BLE001 - retried below
                last_error = error
            time.sleep(1.0 + attempt)
        raise RuntimeError(f"failed to fetch {path}: {last_error}")

    def get_many(self, paths: list[str]) -> list:
        return list(self.pool.map(self.get, paths))


def collect_metadata(portal: Portal) -> tuple[dict, dict, dict]:
    """Return (map_contracts, map_regions, counters)."""
    regions = portal.get("voting/regions")["data"]["regions"]
    map_regions = {region["code"]: (region["name"], region["description"]) for region in regions}
    log(f"regions: {len(regions)}")

    election_paths = [f"elections/region/{region['code']}/elections" for region in regions]
    district_paths: list[str] = []
    for region, payload in zip(regions, portal.get_many(election_paths)):
        for level in payload["data"]["elections"]:
            for election in level["elections"]:
                district_paths.append(
                    f"elections/districts?regionCode={region['code']}&electionId={election['electionId']}"
                )
    log(f"elections: {len(district_paths)} -> districts")

    voting_paths: list[str] = []
    district_results = portal.get_many(district_paths)
    for path, payload in zip(district_paths, district_results):
        election_id = path.split("electionId=")[1]
        for district in payload["data"]:
            voting_paths.append(f"statistics/voting?electionId={election_id}&districtId={district['id']}")
    log(f"districts: {len(voting_paths)} -> votings")

    map_contracts: dict[str, tuple[str, str, str]] = {}
    counters: dict[str, dict] = {}
    for payload in portal.get_many(voting_paths):
        data = payload["data"]
        region_description = map_regions.get(data["regionCode"], ("", data.get("regionName")))[1]
        for voting in data["votings"]:
            contract_id = voting["counters"]["contractId"]
            map_contracts[contract_id] = (
                region_description,
                data["electionName"],
                data["districtName"],
            )
            counters[contract_id] = voting["counters"]
    log(f"contracts with metadata: {len(map_contracts)}")
    return map_contracts, map_regions, counters


def collect_results(portal: Portal, contract_ids: list[str]) -> dict:
    payloads = portal.get_many([f"results/voting/{contract_id}" for contract_id in contract_ids])
    results = {}
    for contract_id, payload in zip(contract_ids, payloads):
        data = payload.get("data") or {}
        answers = data.get("answers") or []
        if answers:
            results[contract_id] = (
                [answer["name"] for answer in answers],
                [answer["value"] for answer in answers],
            )
    log(f"contracts with published results: {len(results)} of {len(contract_ids)}")
    return results


CHUNK_NAME = re.compile(r"^(\d+)-(\d+)\.jsonl(\.gz)?$")


def dump_files(path: Path) -> list[Path]:
    """Files of a dump, in stream order.

    --dump may be a single file (/dev/stdin included) or the block-dump directory written by
    dump-chunked.py; in the directory case every chain is streamed one after another and chain
    boundaries are recovered from the block heights inside (a height of 1 starts a new chain).
    Chunks may be plain .jsonl or gzipped .jsonl.gz.
    """
    if not path.is_dir():
        return [path]
    chunks = [item for item in path.glob("shard-*/*.jsonl*") if CHUNK_NAME.match(item.name)]
    return sorted(
        chunks, key=lambda item: (item.parent.name, int(CHUNK_NAME.match(item.name).group(1)))
    )


def iter_dump_lines(files: list[Path]) -> Iterator[str]:
    for chunk in files:
        if chunk.name.endswith(".gz"):
            with gzip.open(chunk, "rt", encoding="utf-8", errors="replace") as handle:
                yield from handle
        else:
            with chunk.open(encoding="utf-8", errors="replace") as handle:
                yield from handle


def parse_dump(path: Path) -> tuple[dict, dict, dict, dict, dict]:
    """Single streaming pass over the dump."""
    ballots = defaultdict(list)  # contract -> [(uik, dt)]
    votes = defaultdict(list)  # contract -> [dt]
    voter_lists = defaultdict(list)  # (contract, uik) -> [(optype, count)]
    tallies = {}  # contract -> [votes per candidate] (from the on-chain 'results' operation)
    contract_regions = {}  # contract -> primaryUikRegionCode as seen on chain
    stats = {"blocks": 0, "ops": defaultdict(int), "shard_lengths": [], "bad_lines": 0}
    previous_height = None
    files = dump_files(path)
    log(f"dump files: {len(files)} in {len({item.parent.name for item in files})} chain(s)")
    for line in iter_dump_lines(files):
        line = line.strip()
        if not line:
            continue
        try:
            block = json.loads(line)
        except json.JSONDecodeError:
            stats["bad_lines"] += 1
            continue
        height = block.get("height")
        if previous_height is not None and height == 1:
            stats["shard_lengths"].append(previous_height)
        previous_height = height
        stats["blocks"] += 1
        for transaction in block["transactions"]:
            if transaction.get("type") != 105 or transaction["tx"]["type"] != 104:
                continue
            params = {p["key"]: p["value"] for p in transaction["tx"]["params"]}
            operation = params.get("operation")
            stats["ops"][operation] += 1
            timestamp = transaction["tx"]["timestamp"]
            when = datetime.fromtimestamp(timestamp / 1000, tz=timezone.utc).astimezone(MSK).replace(
                tzinfo=None, microsecond=0
            )
            contract_id = transaction["tx"]["contractId"]
            if "primaryUikRegionCode" in params and contract_id not in contract_regions:
                contract_regions[contract_id] = str(params["primaryUikRegionCode"])
            if operation == "blindSigIssue":
                ballots[contract_id].append((as_uik(params["primaryUikNumber"]), when))
            elif operation == "vote":
                votes[contract_id].append(when)
            elif operation in ("addVotersList", "removeFromVotersList", "addToVotersList"):
                count = len(json.loads(params["userIdHashes"]))
                voter_lists[(contract_id, as_uik(params["primaryUikNumber"]))].append(
                    (operation, when, count)
                )
            elif operation == "results" and params.get("results"):
                # Multi-dimension bulletins are nested: [[candidate tallies], ...] -> first dimension.
                tallies[contract_id] = json.loads(params["results"])[0]
    stats["shard_lengths"].append(previous_height)
    return ballots, votes, voter_lists, tallies, contract_regions, stats


def write_tables(
    out_dir: Path,
    map_contracts: dict,
    map_regions: dict,
    results: dict,
    ballots: dict,
    votes: dict,
    voter_lists: dict,
    tallies: dict,
    counters: dict,
    contract_regions: dict,
) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)

    # Rows follow the chain (that is what the dump contains); the portal adds names only where it
    # knows the contract. Chain-only contracts get their region from primaryUikRegionCode, while
    # election/district stay empty.
    chain_contracts = sorted(set(ballots) | set(votes) | set(tallies) | {c for c, _ in voter_lists})
    rows = []
    for contract_id in chain_contracts:
        region, election, district = map_contracts.get(contract_id, ("", "", ""))
        if not region:
            code = contract_regions.get(contract_id)
            if code is not None and code.isdigit() and int(code) in map_regions:
                region = map_regions[int(code)][1]
        rows.append((contract_id, region, election, district))
    elections_df = pd.DataFrame(rows, columns=["contract_id", "region", "election", "district"])
    elections_df.to_csv(out_dir / "elections.csv", index=False)

    # Candidate names come from the portal, tallies from the chain (the 2024/2025 pipeline did the
    # same and asserted both agree); if the portal has nothing published, the names stay empty.
    results_df = pd.DataFrame(
        [
            (
                contract_id,
                results.get(contract_id, ([], None))[0],
                results[contract_id][1] if contract_id in results else tallies.get(contract_id, []),
            )
            for contract_id in chain_contracts
        ],
        columns=["contract_id", "candidates", "results"],
    )
    results_df.to_csv(out_dir / "results.csv", index=False)

    # Diagnostic: dump counts vs the portal's live counters, per chain contract.
    list_initial: dict[str, int] = defaultdict(int)
    list_removed: dict[str, int] = defaultdict(int)
    for (contract_id, _uik), rows in voter_lists.items():
        for operation, _when, count in rows:
            if operation == "addVotersList":
                list_initial[contract_id] += count
            elif operation == "removeFromVotersList":
                list_removed[contract_id] += count
    diagnostics = [
        (
            contract_id,
            len(ballots.get(contract_id, [])),
            len(votes.get(contract_id, [])),
            counters.get(contract_id, {}).get("issued"),
            counters.get(contract_id, {}).get("voted"),
            len(tallies.get(contract_id, [])),
            bool(map_contracts.get(contract_id)),
            list_initial[contract_id],
            list_removed[contract_id],
        )
        for contract_id in chain_contracts
    ]
    pd.DataFrame(
        diagnostics,
        columns=[
            "contract_id",
            "dump_ballots",
            "dump_votes",
            "api_issued",
            "api_voted",
            "tally_len",
            "in_portal_metadata",
            "list_initial",
            "list_removed",
        ],
    ).to_csv(out_dir / "per_contract.csv", index=False)

    ballots_df = pd.DataFrame(
        [
            (contract_id, uik, when)
            for contract_id, rows in sorted(ballots.items())
            for uik, when in sorted(rows, key=lambda row: row[1])
        ],
        columns=["contract_id", "uik", "timestamp"],
    )
    ballots_df.to_csv(out_dir / "ballots.csv", index=False)

    votes_df = pd.DataFrame(
        [
            (contract_id, when)
            for contract_id, rows in sorted(votes.items())
            for when in sorted(rows)
        ],
        columns=["contract_id", "timestamp"],
    )
    votes_df.to_csv(out_dir / "votes.csv", index=False)

    # Voter-list stream.  Published as events because the list changes while voting is running:
    # a blank aggregate would hide when people were removed, and with in-person voting that is
    # the whole point of the table.  aggregations belong to the analyst (see the README recipe).
    events_df = pd.DataFrame(
        [
            (contract_id, uik, when, count, LIST_EVENT_TYPES[operation])
            for (contract_id, uik), rows in sorted(voter_lists.items())
            for operation, when, count in sorted(rows, key=lambda row: row[1])
        ],
        columns=["contract_id", "uik", "timestamp", "count", "type"],
    )
    events_df.to_csv(out_dir / "voter_list_events.csv", index=False)

    return {
        "elections.csv": len(elections_df),
        "results.csv": len(results_df),
        "ballots.csv": len(ballots_df),
        "votes.csv": len(votes_df),
        "voter_list_events.csv": len(events_df),
        "per_contract.csv": len(diagnostics),
    }


ARCHIVE_TABLES = ("elections.csv", "results.csv", "ballots.csv", "votes.csv", "voter_list_events.csv")
DEFAULT_PANEL_COLORS = ("#1769aa", "#c05621", "#2f855a", "#6b46c1", "#2c7a7b")


def resolve_archive_path(dest: Path) -> Path:
    """Turn --archive into a file path: a directory means the usual timestamped name.

    Existing files are never overwritten: a directory gets a new feddeg_<stamp>_N.zip, an
    explicit file path that already exists is an error.
    """
    if dest.is_dir():
        stamp = datetime.now(MSK).strftime("feddeg_%Y%m%dT%H%M%S+0300")
        candidate = dest / f"{stamp}.zip"
        index = 0
        while candidate.exists():
            index += 1
            candidate = dest / f"{stamp}_{index}.zip"
        return candidate
    if dest.exists():
        raise SystemExit(f"refusing to overwrite {dest}; pass a directory or remove the file")
    return dest


def write_archive(dest: Path, out_dir: Path) -> Path:
    """Zip the five published tables; per_contract.csv is a diagnostic and stays out."""
    path = resolve_archive_path(dest)
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for name in ARCHIVE_TABLES:
            archive.write(out_dir / name, name)
    log(f"archive: {path} ({path.stat().st_size / 1e6:.1f} MB)")
    return path


def read_ballot_timestamps(source: Path) -> pd.Series:
    """Ballot timestamps from a table directory or from a published ZIP with ballots.csv."""
    if source.is_dir():
        frame = pd.read_csv(source / "ballots.csv", usecols=["timestamp"], parse_dates=["timestamp"])
    else:
        with zipfile.ZipFile(source) as archive, archive.open("ballots.csv") as stream:
            frame = pd.read_csv(stream, usecols=["timestamp"], parse_dates=["timestamp"])
    # An empty column comes back as object dtype, so normalise before any max()/format calls.
    return pd.to_datetime(frame["timestamp"])


def parse_reference(spec: str) -> tuple[str, Path]:
    """--reference takes LABEL=PATH; a bare path is labelled by its file name."""
    label, separator, raw_path = spec.partition("=")
    if not separator:
        label, raw_path = Path(spec).stem, spec
    path = Path(raw_path).expanduser()
    if not path.exists():
        raise SystemExit(f"reference not found: {path}")
    return label, path


def parse_marker(spec: str) -> tuple[float, str]:
    """--mark-elapsed takes HOURS=LABEL, where HOURS are counted from the first ballot."""
    hours, separator, label = spec.partition("=")
    if not separator:
        raise SystemExit(f"expected HOURS=LABEL, got {spec!r}")
    return float(hours), label


def write_turnout_comparison(
    path: Path,
    series: list[tuple[str, pd.Series, str]],
    markers: Iterable[tuple[float, str]] = (),
    hours: float = 72.0,
    bins: int = 200,
    dpi: int = 180,
    title: str | None = None,
) -> Path:
    """Side-by-side turnout graph: one histogram panel per dataset on a common hour axis.

    Every panel counts ballots by hours elapsed since that dataset's first ballot, so datasets
    of different length and turnout stay comparable. Markers are vertical dashed lines drawn on
    the last (current) panel - use them to flag outages so a truncated tail is not read as a
    real turnout drop. Plotting imports stay local: the table/archive path needs no matplotlib.
    """
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np
    import seaborn as sns
    from matplotlib.ticker import MultipleLocator

    edges = np.linspace(0, hours, bins + 1)
    for label, stamps, _ in series:
        if len(stamps) == 0:
            raise SystemExit(f"no ballots to plot for panel {label!r}")
    figure, axes = plt.subplots(
        len(series), 1, figsize=(20, 5 * len(series)), sharex=True, sharey=True,
        constrained_layout=True,
    )
    for index, (ax, (label, stamps, color)) in enumerate(zip(np.atleast_1d(axes), series)):
        elapsed = (stamps - stamps.min()).dt.total_seconds() / 3600
        sns.histplot(elapsed, bins=edges, ax=ax, color=color, edgecolor="white", linewidth=0.25)
        ax.set_xlim(0, hours)
        ax.xaxis.set_major_locator(MultipleLocator(12))
        ax.grid(axis="y", color="#d9d9d9", linewidth=0.7)
        ax.set_axisbelow(True)
        ax.set_title(
            f"{label}\nn = {len(stamps):,} бюллетеней; наблюдение до {stamps.max():%d.%m %H:%M} МСК".replace(
                ",", "\u202f"
            ),
            fontsize=15,
        )
        ax.set_ylabel("Бюллетени", fontsize=13)
        ax.set_xlabel("Часы от первого бюллетеня (МСК)" if index == len(series) - 1 else "", fontsize=13)
        if index == len(series) - 1:
            top = ax.get_ylim()[1]
            for position, note in markers:
                ax.axvline(position, color="#7b341e", linestyle="--", linewidth=1.2)
                ax.annotate(
                    note,
                    xy=(position, top * 0.8),
                    xytext=(position + hours * 0.02, top * 0.8),
                    fontsize=12,
                    color="#7b341e",
                    va="center",
                    arrowprops={"arrowstyle": "-", "color": "#7b341e", "linewidth": 1},
                )

    figure.suptitle(title or "Выдача электронных бюллетеней", fontsize=20)
    path.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(path, dpi=dpi)
    plt.close(figure)
    log(f"turnout comparison: {path}")
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dump", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cache", type=Path, default=None, help="API response cache (default: OUT/cache)")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument(
        "--api",
        default=API,
        help="portal base URL (use https://teststat.deg.rt.ru/api from the test network)",
    )
    parser.add_argument("--skip-api", action="store_true", help="build only dump-derived tables")
    parser.add_argument(
        "--archive",
        type=Path,
        default=None,
        metavar="DEST",
        help="also write the published ZIP with the five tables; a directory means "
        "DEST/feddeg_<MSK timestamp>.zip",
    )
    parser.add_argument(
        "--turnout-comparison",
        type=Path,
        default=None,
        metavar="PNG",
        help="also write the side-by-side turnout graph: one panel per dataset",
    )
    parser.add_argument(
        "--reference",
        action="append",
        default=[],
        metavar="LABEL=ZIP",
        help="earlier archive (ZIP or table directory) added to the turnout graph; repeatable",
    )
    parser.add_argument(
        "--turnout-current-label",
        default=None,
        help="panel label for the current dump (default: '<year> (частичные данные)')",
    )
    parser.add_argument(
        "--mark-elapsed",
        action="append",
        default=[],
        metavar="HOURS=LABEL",
        help="vertical dashed marker on the current panel; repeatable",
    )
    parser.add_argument("--turnout-hours", type=float, default=72.0, help="x-axis length in hours (default: %(default)s)")
    parser.add_argument("--turnout-bins", type=int, default=200, help="histogram bins per panel (default: %(default)s)")
    args = parser.parse_args()

    out_dir = args.out.resolve()
    cache_dir = args.cache or out_dir / "cache"

    if args.skip_api:
        map_contracts, map_regions, results, counters = {}, {}, {}, {}
    else:
        portal = Portal(cache_dir, args.workers, args.api)
        map_contracts, map_regions, counters = collect_metadata(portal)
        results = collect_results(portal, sorted(map_contracts))
        log(f"API calls: {portal.calls}, cache hits: {portal.cache_hits}")

    log(f"parsing dump {args.dump}")
    ballots, votes, voter_lists, tallies, contract_regions, stats = parse_dump(args.dump)
    log(f"on-chain tallies: {len(tallies)}")
    log(f"blocks: {stats['blocks']}, shard lengths: {stats['shard_lengths']}, ops: {dict(stats['ops'])}")
    if stats["bad_lines"]:
        log(f"WARNING: skipped {stats['bad_lines']} unparsable lines")

    counts = write_tables(
        out_dir,
        map_contracts,
        map_regions,
        results,
        ballots,
        votes,
        voter_lists,
        tallies,
        counters,
        contract_regions,
    )
    log(f"wrote {counts} into {out_dir}")

    archive = write_archive(args.archive, out_dir) if args.archive else None
    if args.turnout_comparison:
        series = []
        for index, spec in enumerate(args.reference):
            label, source = parse_reference(spec)
            color = DEFAULT_PANEL_COLORS[index % len(DEFAULT_PANEL_COLORS)]
            series.append((label, read_ballot_timestamps(source), color))
        current_source = archive if archive is not None else out_dir
        current_stamps = read_ballot_timestamps(current_source)
        newest = pd.Timestamp(current_stamps.max())
        current_label = args.turnout_current_label or f"{newest:%Y} (частичные данные)"
        series.append(
            (
                current_label,
                current_stamps,
                DEFAULT_PANEL_COLORS[len(series) % len(DEFAULT_PANEL_COLORS)],
            )
        )
        write_turnout_comparison(
            args.turnout_comparison,
            series,
            markers=[parse_marker(spec) for spec in args.mark_elapsed],
            hours=args.turnout_hours,
            bins=args.turnout_bins,
        )
    elif args.reference or args.mark_elapsed:
        log("note: --reference/--mark-elapsed only matter together with --turnout-comparison")

    if counters:
        issued = sum(c["issued"] for c in counters.values())
        voted = sum(c["voted"] for c in counters.values())
        all_voters = sum(c["all"] for c in counters.values())
        dump_ballots = sum(len(rows) for rows in ballots.values())
        dump_votes = sum(len(rows) for rows in votes.values())
        print(f"portal counters: all={all_voters} issued={issued} voted={voted}")
        print(f"dump:            ballots={dump_ballots} votes={dump_votes}")
        print(
            "coverage: "
            f"ballots={dump_ballots / issued:.1%} votes={dump_votes / voted:.1%}"
            if issued and voted
            else "coverage: n/a"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
