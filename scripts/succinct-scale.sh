#!/usr/bin/env bash
# Isolated, memory-contained release evaluations. Each result is a real run;
# no extrapolated aggregate capacity is reported as tested capacity.
set -euo pipefail
profile="${1:-baseline}"
case "$profile" in
baseline)
	default_counts="1000,10000,100000,1000000"
	default_readers=100
	;;
endurance)
	default_counts="10000000,100000000,1000000000"
	default_readers=100
	;;
full)
	default_counts="1000,10000,100000,1000000,10000000,100000000,1000000000"
	default_readers=100
	;;
smoke)
	default_counts="512"
	default_readers=4
	;;
-h | --help)
	echo "Usage: bash scripts/succinct-scale.sh [baseline|endurance|full|smoke]"
	echo "Default: baseline. Each population runs separately, limited to 80G RAM, no swap."
	exit 0
	;;
*)
	echo "Unknown profile: $profile (use --help)" >&2
	exit 2
	;;
esac
[[ $# -le 1 ]] || {
	echo "Expected one profile (use --help)" >&2
	exit 2
}
root="$(git rev-parse --show-toplevel)"
cd "$root"
counts="${KAPPA_SCALE_COUNTS:-$default_counts}"
populations="${KAPPA_SCALE_POPULATIONS:-sha256 sha512 prefix}"
memory="${KAPPA_SCALE_MEMORY_MAX:-80G}"
runtime="${KAPPA_SCALE_RUNTIME_MAX:-6h}"
output="${KAPPA_SCALE_OUTPUT:-${TMPDIR:-/tmp}/kappa-scale-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$output"
command -v systemd-run >/dev/null
# Build once outside measured children. Discover the exact Cargo artifact,
# rather than accidentally executing an older feature/profile build.
cargo test --release -p kappa-succinct --test production_workloads --no-run --message-format=json >"$output/build.jsonl"
binary="$(
	python3 - "$output/build.jsonl" <<'PY'
import json, sys
paths = []
with open(sys.argv[1]) as source:
    for line in source:
        item = json.loads(line)
        if item.get('reason') == 'compiler-artifact' and item.get('target', {}).get('name') == 'production_workloads' and item.get('executable'):
            paths.append(item['executable'])
if len(paths) != 1:
    raise SystemExit('expected exactly one production_workloads executable')
print(paths[0])
PY
)"
# Metric columns of results.tsv, in order: the fields of the test's one
# `scale_result` record per run (integer nanoseconds and KiB). The
# performance report (kappa-perf perf-report) reads these columns.
metrics=(final_keys readers rounds mutation_calls elapsed_ns peak_rss_kib
	mutation_batch_p99_ns rebuild_p99_ns seek_p50_min_ns seek_p50_max_ns
	seek_p99_min_ns seek_p99_max_ns)
# Fields of the run's scale_result record in metric order, tab-separated.
# A successful run must have printed exactly one record; a failed run yields
# empty fields so its row still records the failure.
record_fields() {
	python3 - "$1" "$2" "${metrics[@]}" <<'PY'
import sys
log, status, names = sys.argv[1], int(sys.argv[2]), sys.argv[3:]
with open(log, errors='replace') as source:
    records = [line.split()[1:] for line in source if line.startswith('scale_result ')]
if status != 0 and not records:
    print('\t'.join('' for _ in names))
    raise SystemExit(0)
if len(records) != 1:
    raise SystemExit(f'{log}: expected one scale_result record, found {len(records)}')
fields = dict(pair.split('=', 1) for pair in records[0])
missing = [name for name in names if name not in fields]
if missing:
    raise SystemExit(f'{log}: scale_result lacks {missing}')
print('\t'.join(fields[name] for name in names))
PY
}
printf 'keys\tpopulation\texit_status\tlog' >"$output/results.tsv"
printf '\t%s' "${metrics[@]}" >>"$output/results.tsv"
printf '\n' >>"$output/results.tsv"
failed=0
IFS=',' read -r -a rungs <<<"$counts"
for count in "${rungs[@]}"; do
	[[ "$count" =~ ^[1-9][0-9]*$ ]] || {
		echo "Invalid scale: $count" >&2
		exit 2
	}
	for population in $populations; do
		log="$output/$count-$population.log"
		echo "Evaluating keys=$count population=$population memory=$memory timeout=$runtime log=$log"
		status=0
		systemd-run --user --quiet --wait --pipe --collect \
			--unit="kappa-scale-$$-$count-$population" \
			-p "MemoryMax=$memory" -p MemorySwapMax=0 -p "RuntimeMaxSec=$runtime" \
			-p MemoryAccounting=yes \
			--setenv="KAPPA_SCALE_KEYS=$count" \
			--setenv="KAPPA_SCALE_POPULATION=$population" \
			--setenv="KAPPA_SCALE_READERS=${KAPPA_SCALE_READERS:-$default_readers}" \
			--setenv="KAPPA_SCALE_ROUNDS=${KAPPA_SCALE_ROUNDS:-8}" \
			--setenv="KAPPA_SCALE_MUTATIONS_PER_ROUND=${KAPPA_SCALE_MUTATIONS_PER_ROUND:-1024}" \
			"$binary" realistic_identity_scale_endurance --exact --ignored --nocapture --test-threads=1 \
			2>&1 | tee "$log" || status=$?
		fields="$(record_fields "$log" "$status")"
		printf '%s\t%s\t%s\t%s\t%s\n' "$count" "$population" "$status" "$log" "$fields" >>"$output/results.tsv"
		if ((status != 0)); then
			failed=1
			# Preserve the failed rung; do not launch still larger allocations.
			echo "Evaluation failed at $count/$population (status $status); results: $output" >&2
			exit "$status"
		fi
	done
done
echo "Results: $output/results.tsv"
exit "$failed"
