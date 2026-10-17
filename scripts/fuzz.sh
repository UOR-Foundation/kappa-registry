#!/usr/bin/env bash
# Coverage-guided fuzzing of the decoders that take peer-supplied bytes, in
# the flake's `fuzz` shell (nightly toolchain, cargo-fuzz), under
# AddressSanitizer. Each target runs for a bounded time; a target that
# finds a failing input exits non-zero, the remaining targets still run,
# and the exit status is the first failure's. Corpora persist under
# crates/kappa-succinct/fuzz/corpus/<target> and failing inputs under
# crates/kappa-succinct/fuzz/artifacts/<target>.
set -euo pipefail
usage() {
	echo "Usage: bash scripts/fuzz.sh [all|<target>] [seconds per target]"
	echo "Default: all 300. Targets are the fuzz crate's binaries (cargo fuzz list)."
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
target="${1:-all}"
seconds="${2:-300}"
[[ "$seconds" =~ ^[1-9][0-9]*$ ]] || {
	echo "Invalid seconds: $seconds (expected a positive integer)" >&2
	exit 2
}
root="$(git rev-parse --show-toplevel)"
fuzz_dir="$root/crates/kappa-succinct/fuzz"
in_fuzz_shell() {
	nix develop "$root#fuzz" --command "$@"
}
listing="$(in_fuzz_shell cargo fuzz list --fuzz-dir "$fuzz_dir")"
mapfile -t available <<<"$listing"
if [[ "$target" == all ]]; then
	targets=("${available[@]}")
else
	found=0
	for name in "${available[@]}"; do
		[[ "$name" == "$target" ]] && found=1
	done
	((found == 1)) || {
		echo "Unknown fuzz target: $target (valid: all ${available[*]})" >&2
		exit 2
	}
	targets=("$target")
fi
status=0
for name in "${targets[@]}"; do
	echo "== fuzz $name for ${seconds}s"
	code=0
	in_fuzz_shell cargo fuzz run --fuzz-dir "$fuzz_dir" "$name" -- -max_total_time="$seconds" || code=$?
	echo "== fuzz $name: exit $code"
	if ((code != 0 && status == 0)); then
		status=$code
	fi
done
exit "$status"
