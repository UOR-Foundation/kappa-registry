#!/usr/bin/env bash
set -euo pipefail

# Git end-to-end test: push, clone, fetch against a live kappa-server.
# Usage: ./scripts/git-e2e.sh
# Requires: git, curl, cargo build completed

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="$PROJECT_ROOT/target/debug/kappa-server"

if [ ! -f "$BINARY" ]; then
  echo "Building kappa-server..."
  cargo build -p kappa-server
fi

TMP=$(mktemp -d)
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')

KAPPA_LISTEN_ADDR="127.0.0.1:$PORT" \
KAPPA_STORE_ROOT="$TMP/store" \
KAPPA_RATELIMIT_READ_PERIOD_MS=0 \
KAPPA_RATELIMIT_WRITE_PERIOD_MS=0 \
KAPPA_RATELIMIT_ADMIN_PERIOD_MS=0 \
RUST_LOG=warn \
  "$BINARY" &
SERVER_PID=$!
trap "kill $SERVER_PID 2>/dev/null || true; rm -rf $TMP" EXIT

for i in $(seq 1 50); do
  if curl -sf "http://127.0.0.1:$PORT/_status" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

BASE="http://127.0.0.1:$PORT"

echo "=== git push ==="
GITDIR="$TMP/src"
mkdir -p "$GITDIR"
cd "$GITDIR"
git init -q
git checkout -b main
echo "hello from kappa-registry" > hello.txt
mkdir -p src
echo 'fn main() { println!("hello"); }' > src/main.rs
git add .
GIT_AUTHOR_NAME=Test GIT_AUTHOR_EMAIL=test@test.com \
GIT_COMMITTER_NAME=Test GIT_COMMITTER_EMAIL=test@test.com \
  git commit -q -m "initial commit"
GIT_TERMINAL_PROMPT=0 git remote add origin "$BASE/myrepo.git"
GIT_TERMINAL_PROMPT=0 git push -u origin main 2>&1
echo "push exit: $?"

echo ""
echo "=== git clone ==="
GIT_TERMINAL_PROMPT=0 git clone "$BASE/myrepo.git" "$TMP/cloned" 2>&1
echo "clone exit: $?"

echo ""
echo "=== verify cloned content ==="
diff "$GITDIR/hello.txt" "$TMP/cloned/hello.txt"
diff "$GITDIR/src/main.rs" "$TMP/cloned/src/main.rs"
echo "files match"

echo ""
echo "=== git log in clone ==="
cd "$TMP/cloned"
git log --oneline

echo ""
echo "=== second commit + fetch ==="
cd "$GITDIR"
echo "second line" >> hello.txt
git add hello.txt
GIT_AUTHOR_NAME=Test GIT_AUTHOR_EMAIL=test@test.com \
GIT_COMMITTER_NAME=Test GIT_COMMITTER_EMAIL=test@test.com \
  git commit -q -m "second commit"
GIT_TERMINAL_PROMPT=0 git push 2>&1
echo "second push exit: $?"

cd "$TMP/cloned"
GIT_TERMINAL_PROMPT=0 git fetch origin 2>&1
GIT_TERMINAL_PROMPT=0 git merge origin/main --no-edit 2>&1
echo "fetch+merge exit: $?"

diff "$GITDIR/hello.txt" "$TMP/cloned/hello.txt"
echo "files match after fetch"

echo ""
echo "=== git log after fetch ==="
git log --oneline

echo ""
echo "SUCCESS: git push + clone + fetch roundtrip complete"
