#!/usr/bin/env bash
# One complete performance run: the calibrated floors, workloads and
# contention benchmarks at a tier, the succinct scale evaluation at a
# profile, and the report rendered from exactly those results. Everything
# the run produces lands in one directory that no other run touches:
#
#   tmp/perf/<UTC timestamp>-<tier>-<profile>/
#     manifest.txt                 commit, worktree state, tier, profile, stage exit codes
#     calibration_<session>.jsonl  calibration datasets (floors, workloads, contention)
#     criterion/                   criterion results the datasets were backfilled from
#     bench.log                    benchmark output
#     scale/                       results.tsv, per-rung logs, build record
#     scale.log                    scale evaluation output
#     perf-report.md               the report
#     report.log                   report generator output
#
# A failed stage does not stop the stages after it: the scale evaluation
# does not depend on the benchmarks, and the report renders whatever was
# recorded, including every failure. The exit status is the first failed
# stage's.
set -euo pipefail
usage() {
	echo "Usage: bash scripts/perf-run.sh [smoke|standard|full] [smoke|baseline|endurance|full]"
	echo "Default: standard baseline. The first argument is the benchmark tier, the second the"
	echo "succinct scale profile. KAPPA_PERF_DEVICE_DIR selects the filesystem under test."
}
case "${1:-}" in
-h | --help)
	usage
	exit 0
	;;
esac
[[ $# -le 2 ]] || {
	usage >&2
	exit 2
}
tier="${1:-standard}"
profile="${2:-baseline}"
case "$tier" in
smoke | standard | full) ;;
*)
	echo "Unknown tier: $tier (expected smoke, standard or full)" >&2
	exit 2
	;;
esac
case "$profile" in
smoke | baseline | endurance | full) ;;
*)
	echo "Unknown scale profile: $profile (expected smoke, baseline, endurance or full)" >&2
	exit 2
	;;
esac
root="$(git rev-parse --show-toplevel)"
run="$root/tmp/perf/$(date -u +%Y%m%dT%H%M%SZ)-$tier-$profile"
mkdir -p "$run"
manifest="$run/manifest.txt"
{
	printf 'commit: %s\n' "$(git -C "$root" rev-parse HEAD)"
	printf 'started: %s\n' "$(date -u +%FT%TZ)"
	printf 'tier: %s\n' "$tier"
	printf 'scale_profile: %s\n' "$profile"
	printf 'device_dir: %s\n' "${KAPPA_PERF_DEVICE_DIR:-default}"
	printf 'worktree:\n'
	git -C "$root" status --porcelain=v1 | sed 's/^/  /'
} >"$manifest"

export KAPPA_PERF_DATASET_DIR="$run"
export CRITERION_HOME="$run/criterion"

status=0
# Run one stage with its complete output in <run>/<name>.log and on the
# terminal; record its exit code and keep the first failure.
stage() {
	local name="$1"
	shift
	local code=0
	echo "== $name: $*"
	"$@" 2>&1 | tee "$run/$name.log" || code=$?
	printf 'stage %s: exit %s\n' "$name" "$code" >>"$manifest"
	if ((code != 0 && status == 0)); then
		status=$code
	fi
}

stage bench bash "$root/scripts/perf.sh" "$tier" all
stage scale env KAPPA_SCALE_OUTPUT="$run/scale" bash "$root/scripts/succinct-scale.sh" "$profile"
report_args=(--datasets "$run" --out "$run/perf-report.md")
if [[ -s "$run/scale/results.tsv" ]]; then
	report_args+=(--scale "$run/scale/results.tsv")
fi
stage report cargo run --release --manifest-path "$root/Cargo.toml" -p kappa-perf --bin perf-report -- "${report_args[@]}"

printf 'finished: %s\nexit: %s\n' "$(date -u +%FT%TZ)" "$status" >>"$manifest"
echo "Run: $run"
echo "Report: $run/perf-report.md"
exit "$status"
