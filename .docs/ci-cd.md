# CI/CD

Continuous integration runs on GitHub Actions. The workflow is defined in
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml).

## When it runs

- On every pull request.
- On every push to `main`.

Superseded runs on the same ref are cancelled automatically.

## Jobs

### `test`

Installs [`uv`](https://docs.astral.sh/uv/), verifies the lockfile is in sync
(`uv lock --check`), syncs the locked environment, and runs the test suite
(`uv run python -m pytest -q`). It runs against Python 3.11 and 3.12, matching
the versions advertised in `pyproject.toml` classifiers.

### `audit` — dependency CVE scan (pip-audit)

Syncs the locked environment and runs
[`pip-audit`](https://pypi.org/project/pip-audit/) over it:

```bash
uv run python -m pip_audit
```

`pip-audit` is declared in the `dev` dependency group in `pyproject.toml`.

**Command convention:** this repository uses PEP 735 `[dependency-groups]`
rather than `[project.optional-dependencies]` extras, so the dev group
(including `pip-audit`) is synced by default. The invocation is
`uv run python -m pip_audit` — **not** `uv run --extra dev ...`, which would
fail because there is no `dev` extra to select. The audit therefore covers the
full locked environment (runtime + dev dependencies).

## Policy: the audit is a hard gate

The `audit` job **fails the build** when any locked dependency has a known CVE.
A pull request cannot be merged with a red audit job.

Rationale (trade-off): this is a security-primitives library whose runtime
dependencies (`cryptography`, `pyotp`) are inherited by every downstream
consumer. Blocking on a known-vulnerable dependency is the stronger posture and
is consistent with the project's secure-by-construction stance. The cost is that
a newly published advisory in any locked dependency — including a dev/test-only
one such as Django or pytest — turns CI red until the lock is refreshed, even
when the advisory does not affect shipped code.

### Remediation when the audit fails

1. **Preferred — upgrade the dependency.** Bump the affected package in the lock
   and confirm the audit is clean:

   ```bash
   uv lock --upgrade-package <name>
   uv run python -m pip_audit
   ```

   Commit the updated `uv.lock`.

2. **When no fix is available yet** — after reviewing the advisory and
   confirming it does not affect this library's shipped code paths, ignore the
   specific advisory with a justification, and open a follow-up to remove the
   ignore once a fix ships:

   ```bash
   uv run python -m pip_audit --ignore-vuln <ADVISORY-ID>
   ```

   Record the advisory ID and the reason (in the workflow step or a tracked
   item). Do not broaden the ignore beyond the specific advisory.

Never silence the audit by removing the step or converting it to alert-only
without an explicit, documented decision.
