#!/usr/bin/env python3
"""Validate the committed EEST state dumps with the host executor."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


CASE_NAME = re.compile(r"(?:\./)?([0-9a-f]{64})\.json$")


@dataclass(frozen=True)
class CaseResult:
    case_id: str
    dump: Path
    log: str
    passed: bool


@dataclass
class Waiver:
    shard: str
    maximum: int
    pattern: re.Pattern[str]
    reason: str
    seen: int = 0


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_waivers(path: Path) -> list[Waiver]:
    waivers: list[Waiver] = []
    for line_number, line in enumerate(path.read_text().splitlines(), 1):
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) != 4:
            raise ValueError(f"{path}:{line_number}: expected four tab-separated fields")
        shard, maximum, pattern, reason = fields
        waivers.append(Waiver(shard, int(maximum), re.compile(pattern), reason))
    return waivers


def safe_archive_members(archive: Path) -> list[str]:
    result = subprocess.run(
        ["tar", "--zstd", "-tf", str(archive)],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    members = [line for line in result.stdout.splitlines() if line not in (".", "./")]
    if not members or any(CASE_NAME.fullmatch(member) is None for member in members):
        raise ValueError(f"{archive}: archive contains an invalid member name")
    if len(members) != len(set(members)):
        raise ValueError(f"{archive}: archive contains duplicate member names")
    return members


def run_case(reader: Path, dump: Path, case_root: Path) -> CaseResult:
    match = CASE_NAME.fullmatch(dump.name)
    if match is None:
        raise ValueError(f"invalid case name: {dump}")
    case_id = match.group(1)
    if sha256(dump) != case_id:
        return CaseResult(case_id, dump, "content digest differs from case name", False)

    case_output = case_root / case_id
    case_output.mkdir()
    result = subprocess.run(
        [
            "bash",
            "-c",
            'ulimit -v 12582912; exec "$@"',
            "eest-reader",
            str(reader),
            str(dump),
            str(case_output),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    shutil.rmtree(case_output)
    return CaseResult(case_id, dump, result.stdout, result.returncode == 0)


def validate_manifest(manifest: dict[str, object], corpus_root: Path) -> list[dict[str, object]]:
    if manifest.get("schema_version") != 1:
        raise ValueError("unsupported EEST corpus manifest schema")
    shards = manifest.get("shards")
    if not isinstance(shards, list) or not shards:
        raise ValueError("manifest must contain at least one shard")

    seen_ids: set[str] = set()
    seen_files: set[str] = set()
    for shard in shards:
        if not isinstance(shard, dict):
            raise ValueError("each shard entry must be an object")
        shard_id = shard.get("id")
        relative_file = shard.get("file")
        if not isinstance(shard_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", shard_id):
            raise ValueError(f"invalid shard ID: {shard_id!r}")
        if not isinstance(relative_file, str) or not re.fullmatch(
            r"shards/[A-Za-z0-9_-]+\.tar\.zst", relative_file
        ):
            raise ValueError(f"invalid shard path: {relative_file!r}")
        if shard_id in seen_ids or relative_file in seen_files:
            raise ValueError(f"duplicate shard identity: {shard_id}")
        seen_ids.add(shard_id)
        seen_files.add(relative_file)

        archive = corpus_root / relative_file
        if not archive.is_file():
            raise ValueError(f"missing corpus shard: {archive}")
        if archive.stat().st_size != shard.get("bytes"):
            raise ValueError(f"{archive}: size differs from manifest")
        if sha256(archive) != shard.get("sha256"):
            raise ValueError(f"{archive}: SHA-256 differs from manifest")
    return shards


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path(__file__).resolve().parent / "eest-corpus" / "manifest.json",
    )
    parser.add_argument("--reader", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=min(8, os.cpu_count() or 1))
    parser.add_argument(
        "--waivers",
        type=Path,
        default=Path(__file__).resolve().parent / "corpus-waivers.tsv",
    )
    args = parser.parse_args()

    if args.jobs < 1:
        raise ValueError("--jobs must be positive")
    reader = args.reader.resolve()
    if not reader.is_file() or not os.access(reader, os.X_OK):
        raise ValueError(f"reader is not executable: {reader}")
    if args.output.exists() and any(args.output.iterdir()):
        raise ValueError(f"output directory is not empty: {args.output}")
    args.output.mkdir(parents=True, exist_ok=True)

    manifest = json.loads(args.manifest.read_text())
    corpus_root = args.manifest.resolve().parent
    shards = validate_manifest(manifest, corpus_root)
    waivers = read_waivers(args.waivers)
    failures_root = args.output / "failures"
    work_root = args.output / "work"
    work_root.mkdir()

    total_passed = 0
    total_source = 0
    total_waived = 0
    total_unique = 0
    for index, shard in enumerate(shards, 1):
        shard_id = str(shard["id"])
        archive = corpus_root / str(shard["file"])
        members = safe_archive_members(archive)
        expected_unique = int(shard["unique_cases"])
        if len(members) != expected_unique:
            raise ValueError(
                f"{archive}: contains {len(members)} cases; expected {expected_unique}"
            )

        extract_root = work_root / shard_id / "dumps"
        case_root = work_root / shard_id / "cases"
        extract_root.mkdir(parents=True)
        case_root.mkdir()
        subprocess.run(
            ["tar", "--zstd", "-xf", str(archive), "-C", str(extract_root)],
            check=True,
        )
        # The runner owns the extraction directory, so archive metadata cannot
        # deny traversal before case enumeration.
        extract_root.chmod(0o755)
        dumps = sorted(extract_root.glob("*.json"))
        if len(dumps) != expected_unique:
            raise ValueError(f"{archive}: extraction count differs from manifest")

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as executor:
            results = list(executor.map(lambda dump: run_case(reader, dump, case_root), dumps))

        passed = sum(result.passed for result in results)
        waived = 0
        unexpected: list[CaseResult] = []
        for result in sorted((item for item in results if not item.passed), key=lambda item: item.case_id):
            waiver = next(
                (
                    item
                    for item in waivers
                    if item.shard == shard_id
                    and item.seen < item.maximum
                    and item.pattern.search(result.log)
                ),
                None,
            )
            if waiver is not None:
                waiver.seen += 1
                waived += 1
                continue
            unexpected.append(result)

        if unexpected:
            shard_failures = failures_root / shard_id
            shard_failures.mkdir(parents=True, exist_ok=True)
            for result in unexpected:
                shutil.copy2(result.dump, shard_failures / result.dump.name)
                (shard_failures / f"{result.case_id}.log").write_text(result.log)

        total_passed += passed
        total_source += int(shard["source_cases"])
        total_waived += waived
        total_unique += len(results)
        status = "PASS" if not unexpected else "FAIL"
        print(
            f"[{index:03}/{len(shards):03}] {status} {shard_id}: "
            f"source={shard['source_cases']} unique={len(results)} "
            f"passed={passed} waived={waived} unexpected={len(unexpected)}",
            flush=True,
        )
        shutil.rmtree(work_root / shard_id)

    expected_total = int(manifest["unique_case_count"])
    if total_unique != expected_total:
        raise ValueError(f"validated {total_unique} cases; manifest declares {expected_total}")
    expected_source = int(manifest["source_case_count"])
    if total_source != expected_source:
        raise ValueError(
            f"shards describe {total_source} source cases; manifest declares {expected_source}"
        )

    unexpected_count = sum(1 for _ in failures_root.rglob("*.log")) if failures_root.exists() else 0
    print(
        f"EEST native summary: unique={total_unique} passed={total_passed} "
        f"waived={total_waived} unexpected={unexpected_count}",
        flush=True,
    )
    if unexpected_count:
        print(f"failure artifacts: {failures_root}", file=sys.stderr)
        return 1
    shutil.rmtree(work_root)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
