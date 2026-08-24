#!/usr/bin/env bash
set -euo pipefail

# Build canonical, content-addressed native-reference shards from EEST.
# Use a dedicated checkout because enabling the complete fixture index is a
# deliberate worktree-local mutation.

ZKOS_DUMP_COMMIT=736fd93ca9f20bf576240cc0de92d5d483da15a3
EEST_VERSION=5.4.0

if [[ $# -lt 3 ]]; then
    echo "usage: $0 <zksync-os-dump-checkout> <ethereum-fixtures> <output-directory> [filter ...]" >&2
    exit 2
fi

zkos_checkout=$(realpath "$1")
fixtures=$(realpath "$2")
output=$(realpath -m "$3")
shift 3
if [[ -n ${CORPUS_BUILD_DIR:-} ]]; then
    mkdir -p "$CORPUS_BUILD_DIR"
    work_root=$(mktemp -d "$CORPUS_BUILD_DIR/eest-corpus.XXXXXX")
else
    work_root=$(mktemp -d)
fi
target_dir=${CARGO_TARGET_DIR:-$work_root/cargo-target}
eest_threads=${EEST_THREADS:-4}

test "$(git -C "$zkos_checkout" rev-parse HEAD)" = "$ZKOS_DUMP_COMMIT"
test -d "$fixtures/stable/state_tests"
test -d "$fixtures/develop/state_tests"
if [[ -e "$output" ]] && find "$output" -mindepth 1 -print -quit | grep -q .; then
    echo "ERROR: output directory is not empty: $output" >&2
    exit 1
fi
mkdir -p "$output/shards" "$work_root/logs"

fixture_link="$zkos_checkout/tests/evm_tester/ethereum-fixtures"
if [[ ! -e "$fixture_link" ]]; then
    ln -s "$fixtures" "$fixture_link"
fi
test "$(realpath "$fixture_link")" = "$fixtures"
sed -i 's/enabled: false/enabled: true/' "$zkos_checkout/tests/evm_tester/indexes/"*.yaml

export CARGO_TARGET_DIR="$target_dir"
export CARGO_PROFILE_TEST_DEBUG=0 CARGO_PROFILE_DEV_DEBUG=0
export ZKSYNC_USE_CUDA_STUBS=1
(cd "$zkos_checkout/tests/evm_tester" && cargo build --release --bin evm-tester)
evm_tester="$target_dir/release/evm-tester"
test -x "$evm_tester"

filters_file="$work_root/filters.txt"
if [[ $# -gt 0 ]]; then
    printf '%s\n' "$@" | sort -u > "$filters_file"
else
    {
        for channel in stable develop; do
            find "$fixtures/$channel/state_tests" -mindepth 2 -maxdepth 2 -type d \
                | sed "s|$fixtures/$channel/state_tests/||" \
                | grep -v '^static/state_tests$'
        done
    } | sort -u > "$filters_file"
fi

records="$work_root/shards.jsonl"
skipped_records="$work_root/skipped.jsonl"
: > "$records"
python3 - <<'PY' > "$skipped_records"
import json

print(json.dumps({
    "filter": "static/state_tests",
    "reason": "excluded from the per-PR corpus: native reference generation contains pathological long-running cases",
}, sort_keys=True))
PY
while IFS= read -r filter; do
    shard_id=${filter//\//_}
    shard_work="$work_root/$shard_id"
    dumps="$shard_work/dumps"
    normalized="$shard_work/normalized"
    mkdir -p "$dumps" "$normalized"

    echo "=== $filter ==="
    set +e
    (cd "$zkos_checkout/tests/evm_tester" && \
        ZKOS_STATE_DUMP_DIR="$dumps" nice -n 10 "$evm_tester" \
            -p "$filter" -t "$eest_threads" --quiet) \
            >/dev/null 2>"$work_root/logs/$shard_id.log"
    tester_status=$?
    set -e

    source_cases=$(find "$dumps" -type f -name '*.json' | wc -l)
    if [[ "$source_cases" -eq 0 ]]; then
        FILTER="$filter" TESTER_STATUS="$tester_status" python3 - <<'PY' >> "$skipped_records"
import json
import os

print(json.dumps({
    "filter": os.environ["FILTER"],
    "reason": f"no state dumps; evm-tester exit {os.environ['TESTER_STATUS']}",
}, sort_keys=True))
PY
        echo "    SKIP no state dumps; evm-tester exit $tester_status"
        rm -rf "$shard_work"
        continue
    fi

    DUMPS="$dumps" NORMALIZED="$normalized" python3 - <<'PY'
import hashlib
import json
import os
from pathlib import Path

dumps = Path(os.environ["DUMPS"])
normalized = Path(os.environ["NORMALIZED"])
for source in sorted(dumps.glob("*.json")):
    payload = json.loads(source.read_text())
    for state_name in ("pre", "post"):
        state = payload[state_name]
        state["leaves"].sort(key=lambda leaf: leaf["index"])
        state["preimages"].sort(key=lambda preimage: preimage["hash"])
    canonical = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    digest = hashlib.sha256(canonical).hexdigest()
    destination = normalized / f"{digest}.json"
    if not destination.exists():
        destination.write_bytes(canonical)
PY

    unique_cases=$(find "$normalized" -type f -name '*.json' | wc -l)
    archive="$output/shards/$shard_id.tar.zst"
    tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
        --mode='u+rwX,go+rX-w' -C "$normalized" -cf - . \
        | zstd -q -10 -T1 -o "$archive"
    archive_sha=$(sha256sum "$archive" | cut -d' ' -f1)
    archive_bytes=$(stat --format=%s "$archive")

    FILTER="$filter" SHARD_ID="$shard_id" ARCHIVE_SHA="$archive_sha" \
        ARCHIVE_BYTES="$archive_bytes" SOURCE_CASES="$source_cases" \
        UNIQUE_CASES="$unique_cases" python3 - <<'PY' >> "$records"
import json
import os

print(json.dumps({
    "id": os.environ["SHARD_ID"],
    "filter": os.environ["FILTER"],
    "file": f"shards/{os.environ['SHARD_ID']}.tar.zst",
    "sha256": os.environ["ARCHIVE_SHA"],
    "bytes": int(os.environ["ARCHIVE_BYTES"]),
    "source_cases": int(os.environ["SOURCE_CASES"]),
    "unique_cases": int(os.environ["UNIQUE_CASES"]),
}, sort_keys=True))
PY
    printf '    source=%s unique=%s archive=%s bytes=%s tester_exit=%s\n' \
        "$source_cases" "$unique_cases" "$archive_sha" "$archive_bytes" "$tester_status"
    rm -rf "$shard_work"
done < "$filters_file"

RECORDS="$records" SKIPPED_RECORDS="$skipped_records" OUTPUT="$output" \
    EEST_VERSION="$EEST_VERSION" python3 - <<'PY'
import json
import os
from pathlib import Path

records = [json.loads(line) for line in Path(os.environ["RECORDS"]).read_text().splitlines()]
skipped = [
    json.loads(line) for line in Path(os.environ["SKIPPED_RECORDS"]).read_text().splitlines()
]
manifest = {
    "schema_version": 1,
    "eest_version": os.environ["EEST_VERSION"],
    "native_reference": {
        "repository": "antoniolocascio-bot/zksync-os",
        "commit": "736fd93ca9f20bf576240cc0de92d5d483da15a3",
        "protocol_version_minor": 31,
    },
    "format": {
        "archive": "tar+zstd",
        "case": "zkos-state-dump-json",
        "case_name": "sha256-of-uncompressed-json",
    },
    "source_case_count": sum(record["source_cases"] for record in records),
    "unique_case_count": sum(record["unique_cases"] for record in records),
    "skipped_filters": skipped,
    "shards": records,
}
output = Path(os.environ["OUTPUT"])
(output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
print(
    f"manifest: shards={len(records)} source={manifest['source_case_count']} "
    f"unique={manifest['unique_case_count']} skipped_filters={len(skipped)}"
)
PY
echo "generation logs: $work_root/logs"
