#!/usr/bin/env bash
# Run a command with its complete output preserved. Standard output and
# standard error go to the terminal and, unfiltered, to
# tmp/logs/<name>-<UTC timestamp>.log; tmp/logs/<name>.log links to the
# newest run. The log records the command, working directory, start time
# and exit status, and the command's exit status is returned unchanged.
set -euo pipefail
usage() {
	echo "Usage: bash scripts/logged.sh <name> <command> [args...]"
	echo "<name> is [a-z0-9][a-z0-9_-]*; logs are written under tmp/logs/."
}
if [[ $# -ge 1 && ("$1" == "-h" || "$1" == "--help") ]]; then
	usage
	exit 0
fi
[[ $# -ge 2 ]] || {
	usage >&2
	exit 2
}
name="$1"
shift
[[ "$name" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || {
	echo "Invalid log name: $name (expected [a-z0-9][a-z0-9_-]*)" >&2
	exit 2
}
root="$(git rev-parse --show-toplevel)"
dir="$root/tmp/logs"
mkdir -p "$dir"
log="$dir/$name-$(date -u +%Y%m%dT%H%M%SZ).log"
ln -sfn "$(basename "$log")" "$dir/$name.log"
printf '# command: %s\n# cwd: %s\n# started: %s\n' "$*" "$PWD" "$(date -u +%FT%TZ)" >"$log"
status=0
"$@" 2>&1 | tee -a "$log" || status=$?
printf '# finished: %s\n# exit: %s\n' "$(date -u +%FT%TZ)" "$status" >>"$log"
echo "Log: $log" >&2
exit "$status"
