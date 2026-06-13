#!/usr/bin/env bash
set -euo pipefail

repo_url="${TOCODE_REPO_URL:-https://github.com/buzzer-re/ToCode.git}"
branch="${TOCODE_BRANCH:-main}"
with_dev=false
tocode_bin_dir=""

script_dir="$(cd "$(dirname "$0")" && pwd)"
if [ -n "${TOCODE_INSTALL_DIR:-}" ]; then
  install_dir="$TOCODE_INSTALL_DIR"
elif [ -d "$script_dir/.git" ] && [ -f "$script_dir/pyproject.toml" ]; then
  install_dir="$script_dir"
else
  install_dir="$HOME/ToCode"
fi

usage() {
  cat <<'EOF'
Install ToCode on Linux or macOS.

Usage:
  ./install.sh [options]

Options:
  --dir PATH       Clone or update ToCode at PATH. Default: this checkout when run from one, otherwise $HOME/ToCode
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
  printf '\nToCode was not installed: %s\n' "$1" >&2
  shift
  for hint in "$@"; do
    printf '    %s\n' "$hint" >&2
  done
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

path_contains() {
  case ":$PATH:" in
    *":$1:"*) return 0 ;;
    *) return 1 ;;
  esac
}

shell_rc_file() {
  shell_name="$(basename "${SHELL:-}")"
  case "$shell_name" in
    zsh) printf '%s\n' "$HOME/.zshrc" ;;
    bash) printf '%s\n' "$HOME/.bashrc" ;;
    ksh) printf '%s\n' "$HOME/.kshrc" ;;
    *) printf '%s\n' "$HOME/.profile" ;;
  esac
}

ensure_path() {
  bin_dir="$1"
  [ -n "$bin_dir" ] || return 0
  mkdir -p "$bin_dir"

  missing_from_path=false
  if ! path_contains "$bin_dir"; then
    missing_from_path=true
    export PATH="$bin_dir:$PATH"
  fi

  if [ "$missing_from_path" = false ]; then
    return 0
  fi

  rc_file="$(shell_rc_file)"
  marker="# ToCode installer: add user Python/uv tools to PATH"
  path_line="export PATH=\"$bin_dir:\$PATH\""

  touch "$rc_file"
  if ! grep -Fqs "$path_line" "$rc_file"; then
    {
      printf '\n%s\n' "$marker"
      printf '%s\n' "$path_line"
    } >>"$rc_file"
    info "Added $bin_dir to $rc_file"
    info "Open a new shell session, or run: source $rc_file"
  fi
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

command -v git >/dev/null 2>&1 || die "git was not found on PATH" \
  "Install it with your package manager (for example: apt install git, brew install git), then run this installer again."

if [ -d "$install_dir/.git" ]; then
  if [ "$install_dir" = "$script_dir" ]; then
    info "Installing ToCode from this checkout at $install_dir"
  else
    info "Updating ToCode at $install_dir"
    git -C "$install_dir" fetch origin "$branch"
    git -C "$install_dir" checkout "$branch"
    git -C "$install_dir" pull --ff-only origin "$branch"
  fi
elif [ -e "$install_dir" ]; then
  die "$install_dir already exists and is not a ToCode Git checkout" \
    "Move or delete it, or pick another location with: ./install.sh --dir PATH"
else
  info "Cloning ToCode into $install_dir"
  git clone --branch "$branch" "$repo_url" "$install_dir"
fi

if command -v uv >/dev/null 2>&1; then
  info "Syncing local project environment with uv"
  if [ "$with_dev" = true ]; then
    uv --directory "$install_dir" sync --locked --extra dev
  else
    uv --directory "$install_dir" sync --locked
  fi

  info "Installing the tocode command with uv"
  uv tool install --force --editable "$install_dir"

  tocode_bin_dir="$(uv tool dir --bin 2>/dev/null || true)"
  if ! command -v tocode >/dev/null 2>&1; then
    ensure_path "$tocode_bin_dir"
  fi
else
  python_bin="$(find_python || true)"
  [ -n "$python_bin" ] || die "neither uv nor Python 3.10+ was found on PATH" \
    "Install uv from https://docs.astral.sh/uv/getting-started/installation/ (recommended)," \
    "or install Python 3.10 or newer, then run this installer again."

  "$python_bin" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' \
    || die "$python_bin is older than Python 3.10" \
      "Install uv from https://docs.astral.sh/uv/getting-started/installation/ (recommended)," \
      "or install Python 3.10 or newer, then run this installer again."

  info "Installing the tocode command with pip"
  if [ "$with_dev" = true ]; then
    "$python_bin" -m pip install --user --editable "${install_dir}[dev]"
  else
    "$python_bin" -m pip install --user --editable "$install_dir"
  fi

  tocode_bin_dir="$("$python_bin" -c 'import sysconfig; print(sysconfig.get_path("scripts", sysconfig.get_preferred_scheme("user")))' 2>/dev/null \
    || "$python_bin" -c 'import os, site; print(os.path.join(site.USER_BASE, "bin"))')"
  ensure_path "$tocode_bin_dir"
fi

if command -v tocode >/dev/null 2>&1; then
  tocode --help >/dev/null \
    || die "tocode is installed but 'tocode --help' failed" \
      "Check the output above, or run this installer again."
  info "ToCode is installed"
  printf 'Run: tocode <binary> -o <output_dir>\n'
elif [ -n "$tocode_bin_dir" ] && [ -x "$tocode_bin_dir/tocode" ]; then
  info "ToCode is installed"
  printf 'The tocode command lives in %s, which is not visible in this shell yet.\n' "$tocode_bin_dir"
  printf 'Open a new shell session (or run: source %s), then run: tocode <binary> -o <output_dir>\n' "$(shell_rc_file)"
else
  if [ -n "$tocode_bin_dir" ]; then
    die "the install finished, but the tocode command could not be located" \
      "Expected it in $tocode_bin_dir - check that directory and add it to your PATH if it is there."
  fi
  die "the install finished, but the tocode command could not be located" \
    "Add the directory containing the tocode command to your PATH manually."
fi
