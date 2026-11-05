#!/bin/sh
# © 2026 aiaiaiai · aiaiaiai.org
# SPDX-License-Identifier: Apache-2.0
# Smoke the temporary landing page. It must not serve identity routes.
set -eu

cd "$(dirname "$0")/.."
if command -v python3 >/dev/null 2>&1; then
  PYTHON=python3
else
  PYTHON=python
fi
"$PYTHON" -B -c 'import ast, pathlib; ast.parse(pathlib.Path("server.py").read_text())'
"$PYTHON" -B server.py &
server_pid=$!
trap 'kill "$server_pid" 2>/dev/null || true' EXIT

ready=0
i=0
while [ "$i" -lt 30 ]; do
  if curl -fsS http://127.0.0.1:1927/healthz >/dev/null 2>&1; then
    ready=1
    break
  fi
  i=$((i + 1))
  sleep 1
done
[ "$ready" -eq 1 ]

test "$(curl -fsS http://127.0.0.1:1927/healthz)" = ok
curl -fsS http://127.0.0.1:1927/ | grep -q 'Identity, in progress'
curl -fsS http://127.0.0.1:1927/static/auth.css | grep -q 'ecosystem-auth-panel'
test "$(curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:1927/nope)" = 404
test "$(curl -sS --path-as-is -o /dev/null -w '%{http_code}' http://127.0.0.1:1927/static/../server.py)" = 404
test "$(curl -sS -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:1927/)" = 501
