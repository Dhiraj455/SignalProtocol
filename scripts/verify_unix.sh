#!/usr/bin/env bash
# Automated verification — macOS, Linux, and Git Bash on Windows (WSL/Git Bash).
# From repo root: chmod +x scripts/verify_unix.sh && ./scripts/verify_unix.sh
#
# Usage:
#   ./scripts/verify_unix.sh           # backend API smoke tests + frontend lint/test/build
#   ./scripts/verify_unix.sh --no-api # frontend only (skip starting uvicorn on :3001)

set -euo pipefail

NO_API=false
for arg in "$@"; do
  if [[ "$arg" == "--no-api" ]]; then
    NO_API=true
  fi
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BACKEND="$ROOT/backend"
FRONTEND="$ROOT/frontend"
BASE_URL="${BASE_URL:-http://127.0.0.1:3001}"

echo "=== Project root: $ROOT"

echo "=== Backend: Python venv + dependencies"
cd "$BACKEND"
if [[ ! -d .venv ]]; then
  bootstrap_py=""
  for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c "pass" >/dev/null 2>&1; then
      bootstrap_py="$candidate"
      break
    fi
  done
  if [[ -z "$bootstrap_py" ]]; then
    echo "ERROR: Could not create .venv — need working python or python3 on PATH (not the Store stub)." >&2
    exit 1
  fi
  "$bootstrap_py" -m venv .venv
fi
activate_venv() {
  local v=".venv/bin/activate"
  if [[ -f "$v" ]]; then
    # Unix / macOS / WSL/Linux venv
    # shellcheck disable=SC1091
    source "$v"
  elif [[ -f .venv/Scripts/activate ]]; then
    # Windows-style venv (Python on Windows creates Scripts/, not bin/)
    # shellcheck disable=SC1091
    source ".venv/Scripts/activate"
  else
    echo "ERROR: No venv activate script found. Expected .venv/bin/activate or .venv/Scripts/activate" >&2
    echo "Try: cd backend && python -m venv .venv   (or delete backend/.venv and re-run)" >&2
    exit 1
  fi
}
activate_venv
# Use the venv interpreter for pip — avoids Windows error:
# "To modify pip, please run ... python.exe -m pip install ..."
py_for_venv() {
  if [[ -f .venv/Scripts/python.exe ]]; then echo ".venv/Scripts/python.exe"
  elif [[ -f .venv/bin/python ]]; then echo ".venv/bin/python"
  elif command -v python >/dev/null 2>&1; then echo "python"
  else echo "python3"; fi
}
PY="$(py_for_venv)"

b64_rand32() {
  "$PY" -c "import secrets, base64; print(base64.standard_b64encode(secrets.token_bytes(32)).decode())"
}

json_register_payload() {
  local user="$1"
  local ik="$2"
  local idhk="$3"
  local spk="$4"
  local sig="$5"
  local opk="$6"
  "$PY" -c "
import json, sys
u, ik, idhk, spk, sig, opk = sys.argv[1:]
print(json.dumps({
  'username': u,
  'identityKey': ik,
  'identityDhKey': idhk,
  'signedPreKey': {'publicKey': spk, 'signature': sig},
  'oneTimePrekeys': [{'id': 1, 'publicKey': opk}],
}))
" "$user" "$ik" "$idhk" "$spk" "$sig" "$opk"
}

"$PY" -m pip install -q -r requirements.txt

API_PID=""
cleanup() {
  if [[ -n "$API_PID" ]] && kill -0 "$API_PID" 2>/dev/null; then
    echo "=== Stopping API (pid $API_PID)"
    kill "$API_PID" 2>/dev/null || true
    wait "$API_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

if [[ "$NO_API" == "false" ]]; then
  echo "=== Backend: starting uvicorn on $BASE_URL"
  uvicorn main:app --host 127.0.0.1 --port 3001 &
  API_PID=$!

  echo -n "Waiting for /health"
  for _ in $(seq 1 40); do
    if curl -sf "$BASE_URL/health" >/dev/null 2>&1; then
      echo " — ok"
      break
    fi
    echo -n "."
    sleep 0.25
  done
  if ! curl -sf "$BASE_URL/health" >/dev/null 2>&1; then
    echo ""
    echo "ERROR: API did not become ready. Is port 3001 free? Try: $0 --no-api" >&2
    exit 1
  fi

  SUFFIX="$(date +%s)"
  ALICE="verify_alice_${SUFFIX}"
  BOB="verify_bob_${SUFFIX}"

  ik_a="$(b64_rand32)"; idh_a="$(b64_rand32)"; spk_a="$(b64_rand32)"; sig_a="$(b64_rand32)"
  opk_a="$(b64_rand32)"
  ik_b="$(b64_rand32)"; idh_b="$(b64_rand32)"; spk_b="$(b64_rand32)"; sig_b="$(b64_rand32)"
  opk_b="$(b64_rand32)"

  echo "=== API: register $ALICE and $BOB"
  curl -sf -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d "$(json_register_payload "$ALICE" "$ik_a" "$idh_a" "$spk_a" "$sig_a" "$opk_a")" | "$PY" -m json.tool
  curl -sf -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d "$(json_register_payload "$BOB" "$ik_b" "$idh_b" "$spk_b" "$sig_b" "$opk_b")" | "$PY" -m json.tool

  echo "=== API: GET bundle / $ALICE"
  curl -sf "$BASE_URL/bundle/${ALICE}" | "$PY" -m json.tool | head -n 20

  echo "=== API: POST reserve bundle / $BOB (consumes one OPK if present)"
  curl -sf -X POST "$BASE_URL/bundle/${BOB}/reserve" | "$PY" -m json.tool | head -n 20

  echo "=== API: POST send (opaque ciphertext blob)"
  MSG_ID="$(
    curl -sf -X POST "$BASE_URL/send" \
      -H "Content-Type: application/json" \
      -d "{
        \"from\": \"${ALICE}\",
        \"to\": \"${BOB}\",
        \"message\": {
          \"header\": { \"dhPub\": \"\", \"n\": 1, \"pn\": 0 },
          \"ciphertext\": \"dGVzdC1jaXBoZXJ0ZXh0LWRlbW8=\"
        }
      }" | "$PY" -c "import sys, json; print(json.load(sys.stdin)['id'])"
  )"
  echo "send id: $MSG_ID"

  echo "=== API: GET conversation"
  curl -sf "$BASE_URL/conversation?me=${ALICE}&peer=${BOB}" | "$PY" -m json.tool | head -n 30

  echo "=== API: GET chats for $ALICE"
  curl -sf "$BASE_URL/chats?username=${ALICE}" | "$PY" -m json.tool

  cleanup
  API_PID=""
else
  echo "=== Skipping API tests (--no-api)"
fi

echo "=== Frontend: npm install + lint + test + build"
cd "$FRONTEND"
if [[ ! -f package-lock.json ]]; then
  npm install
else
  npm ci
fi
npm run lint
npm run test
npm run build

echo ""
echo "=== All verification steps completed successfully."
