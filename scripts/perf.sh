#!/usr/bin/env bash
# Calibrated kappa-perf benchmarks. Floors are measured first: workloads
# and contention are validated and graded against the same-host floors in
# <datasets>/calibration_floors.jsonl, and refuse to run when that dataset
# is absent. <datasets> is $KAPPA_PERF_DATASET_DIR, else the cargo target
# directory; criterion writes under $CRITERION_HOME, else <target>/criterion.
set -euo pipefail
usage() {
	echo "Usage: bash scripts/perf.sh [smoke|standard|full] [all|floors|workloads|contention|http]"
	echo "Default: standard all. KAPPA_PERF_DEVICE_DIR selects the filesystem under test."
	echo "Criterion arguments follow --, e.g. bash scripts/perf.sh smoke floors -- device_"
}
tier="${1:-standard}"
case "$tier" in
smoke | standard | full) ;;
-h | --help)
	usage
	exit 0
	;;
*)
	echo "Unknown tier: $tier (expected smoke, standard or full)" >&2
	exit 2
	;;
esac
bench="${2:-all}"
case "$bench" in
all) benches=(floors workloads contention http) ;;
floors | workloads | contention | http) benches=("$bench") ;;
*)
	echo "Unknown bench: $bench (expected all, floors, workloads, contention or http)" >&2
	exit 2
	;;
esac
shift $(($# < 2 ? $# : 2))
criterion_args=()
if [[ $# -gt 0 ]]; then
	[[ "$1" == "--" ]] || {
		echo "Unexpected argument: $1 (criterion arguments follow --)" >&2
		exit 2
	}
	shift
	criterion_args=("$@")
fi
root="$(git rev-parse --show-toplevel)"
cd "$root"
target="${CARGO_TARGET_DIR:-$root/target}"
datasets="${KAPPA_PERF_DATASET_DIR:-$target}"
for name in "${benches[@]}"; do
	if [[ "$name" != floors && ! -s "$datasets/calibration_floors.jsonl" ]]; then
		echo "No floors dataset at $datasets/calibration_floors.jsonl; run: bash scripts/perf.sh $tier floors" >&2
		exit 1
	fi
	echo "Measuring $name tier=$tier device=${KAPPA_PERF_DEVICE_DIR:-$target/kappa-perf-device} datasets=$datasets criterion=${CRITERION_HOME:-$target/criterion}"
	KAPPA_PERF_TIER="$tier" cargo bench -p kappa-perf --bench "$name" -- "${criterion_args[@]}"
	echo "Dataset: $datasets/calibration_$name.jsonl"
done
