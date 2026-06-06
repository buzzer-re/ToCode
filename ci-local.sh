#!/usr/bin/env bash
# Local CI simulation. Mirrors .github/workflows/ci.yml.
# Usage: ./ci-local.sh [--fix]
set -euo pipefail

FIX=false
if [[ "${1:-}" == "--fix" ]]; then
  FIX=true
fi

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

PASS=0
FAIL=0
RESULTS=()

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
RESET='\033[0m'

ok() {
  PASS=$((PASS + 1))
  RESULTS+=("${GREEN}PASS${RESET} $1")
}

fail() {
  FAIL=$((FAIL + 1))
  RESULTS+=("${RED}FAIL${RESET} $1: $2")
}

warn() {
  RESULTS+=("${YELLOW}WARN${RESET} $1")
}

info() {
  echo -e "${YELLOW}> $1${RESET}"
}

find_uv() {
  if command -v uv >/dev/null 2>&1; then
    command -v uv
    return 0
  fi
  if [[ -n "${USERPROFILE:-}" ]] && command -v cygpath >/dev/null 2>&1; then
    local candidate
    candidate="$(cygpath -u "$USERPROFILE")/.local/bin/uv.exe"
    if [[ -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  fi
  if command -v powershell.exe >/dev/null 2>&1 && command -v cygpath >/dev/null 2>&1; then
    local win_candidate
    win_candidate="$(powershell.exe -NoProfile -Command "(Get-Command uv -ErrorAction SilentlyContinue).Source" 2>/dev/null | tr -d '\r')"
    if [[ -n "$win_candidate" ]]; then
      local candidate
      candidate="$(cygpath -u "$win_candidate")"
      if [[ -x "$candidate" ]]; then
        printf '%s\n' "$candidate"
        return 0
      fi
    fi
  fi
  if [[ -x "$HOME/.local/bin/uv" ]]; then
    printf '%s\n' "$HOME/.local/bin/uv"
    return 0
  fi
  if [[ -x "$HOME/.local/bin/uv.exe" ]]; then
    printf '%s\n' "$HOME/.local/bin/uv.exe"
    return 0
  fi
  local mounted_candidate
  for mounted_candidate in /mnt/c/Users/*/.local/bin/uv.exe /c/Users/*/.local/bin/uv.exe; do
    if [[ -x "$mounted_candidate" ]]; then
      printf '%s\n' "$mounted_candidate"
      return 0
    fi
  done
  return 1
}

find_python() {
  if command -v python3 >/dev/null 2>&1; then
    command -v python3
    return 0
  fi
  if command -v python >/dev/null 2>&1; then
    command -v python
    return 0
  fi
  return 1
}

UV_BIN="$(find_uv || true)"
PYTHON_BIN="$(find_python || true)"

run_tool() {
  if [[ -n "$UV_BIN" ]]; then
    "$UV_BIN" run --locked "$@"
  else
    "$PYTHON_BIN" "$@"
  fi
}

run_with() {
  local package="$1"
  shift
  if [[ -n "$UV_BIN" ]]; then
    "$UV_BIN" run --locked --with "$package" "$@"
  else
    while [[ "${1:-}" == "--with" ]]; do
      shift 2
    done
    if [[ "${1:-}" == "python" ]]; then
      shift
      "$PYTHON_BIN" "$@"
    else
      "$@"
    fi
  fi
}

info "Checking CI tools"
if [[ -z "$UV_BIN" ]]; then
  warn "uv not found; using current Python environment for tools"
fi
if [[ -z "$UV_BIN" && -z "$PYTHON_BIN" ]]; then
  fail "tool bootstrap" "neither uv nor Python is available"
  echo "No usable Python toolchain found"
  exit 1
fi
if [[ -z "$UV_BIN" ]]; then
  info "Bootstrapping Python CI tools with pip"
  "$PYTHON_BIN" -m pip install --user --quiet \
    ruff==0.15.13 \
    mypy==2.1.0 \
    tomli==2.4.1 \
    types-tqdm==4.67.3.20260518 \
    pytest==8.4.2 || {
    fail "tool bootstrap" "pip install failed"
    echo "Could not install CI tools"
    exit 1
  }
fi

info "[1/5] Ruff format"
if "$FIX"; then
  if run_with ruff==0.15.13 python -m ruff format src tests; then
    ok "ruff format"
  else
    fail "ruff format" "see output above"
  fi
else
  if run_with ruff==0.15.13 python -m ruff format --check src tests; then
    ok "ruff format"
  else
    fail "ruff format" "run ./ci-local.sh --fix"
  fi
fi

info "[2/5] Ruff lint"
if "$FIX"; then
  if run_with ruff==0.15.13 python -m ruff check src tests --fix; then
    ok "ruff lint"
  else
    fail "ruff lint" "see output above"
  fi
else
  if run_with ruff==0.15.13 python -m ruff check src tests; then
    ok "ruff lint"
  else
    fail "ruff lint" "see output above"
  fi
fi

info "[3/5] Mypy"
if run_with mypy==2.1.0 --with tomli==2.4.1 --with types-tqdm==4.67.3.20260518 --with pytest==8.4.2 python -m mypy \
  src tests --pretty; then
  ok "mypy"
else
  fail "mypy" "see output above"
fi

info "[4/5] Pytest"
if [[ -n "$UV_BIN" ]]; then
  TEST_CMD=(--extra dev pytest -q)
else
  TEST_CMD=(-m pytest -q)
fi
if run_tool "${TEST_CMD[@]}"; then
  ok "pytest"
else
  fail "pytest" "see output above"
fi

info "[5/5] Compile Python"
if [[ -n "$PYTHON_BIN" ]]; then
  COMPILE_CMD=("$PYTHON_BIN" -m compileall src tests)
else
  COMPILE_CMD=("$UV_BIN" run python -m compileall src tests)
fi
if "${COMPILE_CMD[@]}"; then
  ok "compileall"
else
  fail "compileall" "see output above"
fi

echo ""
echo -e "${BOLD}CI Results${RESET}"
for result in "${RESULTS[@]}"; do
  echo -e "  $result"
done

if [[ $FAIL -gt 0 ]]; then
  echo -e "${RED}${BOLD}FAILED${RESET} - $FAIL check(s) failed, $PASS passed"
  exit 1
fi

echo -e "${GREEN}${BOLD}ALL REQUIRED CHECKS PASSED${RESET} - $PASS checks"
