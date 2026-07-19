#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
cd "${repo_root}"

if [[ -z "${UV_CACHE_DIR:-}" || ! -w "${UV_CACHE_DIR}" ]]; then
  export UV_CACHE_DIR="${repo_root}/.uv-cache"
fi
if [[ -z "${PIP_CACHE_DIR:-}" || ! -w "${PIP_CACHE_DIR}" ]]; then
  export PIP_CACHE_DIR="${repo_root}/.pip-cache"
fi
export UV_NO_PROGRESS="${UV_NO_PROGRESS:-1}"

run_step() {
  printf '\n==> %s\n' "$*"
  "$@"
}

note_unconfigured() {
  printf '\n==> %s\n' "$1"
  printf 'No %s configuration is present in pyproject.toml or repository tooling; no blocking %s check is defined.\n' "$2" "$2"
}

printf 'Running local CI quality gate from %s\n' "${repo_root}"

run_step uv lock --check
run_step uv sync --locked

note_unconfigured "format" "formatting"
note_unconfigured "lint" "lint"
note_unconfigured "type" "type"

build_dir="$(mktemp -d "${TMPDIR:-/tmp}/django-mfa-toolkit-build.XXXXXX")"
trap 'rm -rf "${build_dir}"' EXIT
run_step uv build --out-dir "${build_dir}"

run_step uv run pytest
run_step uv run pip-audit
