#!/usr/bin/env bash
set -euo pipefail

repo_url="${TOCODE_REPO_URL:-https://github.com/buzzer-re/ToCode.git}"
install_dir="${TOCODE_INSTALL_DIR:-$HOME/ToCode}"
branch="${TOCODE_BRANCH:-main}"
with_dev=false

usage() {
  cat <<'EOF'
Install ToCode on Linux or macOS.

Usage:
  ./install.sh [options]

Options:
  --dir PATH       Clone or update ToCode at PATH. Default: $HOME/ToCode
  --repo URL       Git repository URL. Default: https://github.com/buzzer-re/ToCode.git
  --branch NAME    Branch to install. Default: main
  --dev            Also install development extras in the local checkout
  -h, --help       Show this help
EOF
}

info() {
  printf '==> %s\n' "$1"
}

die() {
  printf 'install.sh: %s\n' "$1" >&2
  exit 1
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

while [ "$#" -gt 0 ]; do
  case "$1" in
    --dir)
      [ "$#" -ge 2 ] || die "--dir requires a path"
      install_dir="$2"
      shift 2
      ;;
    --repo)
      [ "$#" -ge 2 ] || die "--repo requires a URL"
      repo_url="$2"
      shift 2
      ;;
    --branch)
      [ "$#" -ge 2 ] || die "--branch requires a name"
      branch="$2"
      shift 2
      ;;
    --dev)
      with_dev=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

command -v git >/dev/null 2>&1 || die "git is required but was not found on PATH"

if [ -d "$install_dir/.git" ]; then
  info "Updating ToCode at $install_dir"
  git -C "$install_dir" fetch origin "$branch"
  git -C "$install_dir" checkout "$branch"
  git -C "$install_dir" pull --ff-only origin "$branch"
elif [ -e "$install_dir" ]; then
  die "$install_dir already exists and is not a Git checkout"
else
  info "Cloning ToCode into $install_dir"
  git clone --branch "$branch" "$repo_url" "$install_dir"
fi

if command -v uv >/dev/null 2>&1; then
  info "Syncing local project environment with uv"
  if [ "$with_dev" = true ]; then
    uv --directory "$install_dir" sync --extra dev
  else
    uv --directory "$install_dir" sync
  fi

  info "Installing the tocode command with uv"
  uv tool install --force --editable "$install_dir"

  if ! command -v tocode >/dev/null 2>&1; then
    tool_bin="$(uv tool dir --bin 2>/dev/null || true)"
    if [ -n "$tool_bin" ]; then
      export PATH="$tool_bin:$PATH"
    fi
  fi
else
  python_bin="$(find_python || true)"
  [ -n "$python_bin" ] || die "Python 3.10 or newer is required when uv is not installed"

  "$python_bin" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' \
    || die "Python 3.10 or newer is required"

  info "Installing the tocode command with pip"
  if [ "$with_dev" = true ]; then
    "$python_bin" -m pip install --user --editable "${install_dir}[dev]"
  else
    "$python_bin" -m pip install --user --editable "$install_dir"
  fi

  user_bin="$("$python_bin" -c 'import os, site; print(os.path.join(site.USER_BASE, "bin"))')"
  export PATH="$user_bin:$PATH"
fi

command -v tocode >/dev/null 2>&1 || die "tocode was installed, but its bin directory is not on PATH"
tocode --help >/dev/null

info "ToCode is installed"
printf 'Run: tocode <binary> -o <output_dir>\n'
