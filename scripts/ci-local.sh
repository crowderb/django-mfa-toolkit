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

printf 'Running local CI quality gate from %s\n' "${repo_root}"

run_step uv lock --check
run_step uv sync --locked

run_step uv run ruff format --check django_mfa_toolkit tests
run_step uv run ruff check django_mfa_toolkit tests
run_step uv run mypy

build_dir="$(mktemp -d "${TMPDIR:-/tmp}/django-mfa-toolkit-build.XXXXXX")"
trap 'rm -rf "${build_dir}"' EXIT
run_step uv build --out-dir "${build_dir}"

run_step uv run pytest
run_step uv run pip-audit
