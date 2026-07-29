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

## Database topology audit: shared CI PostgreSQL

The `django-mfa-toolkit-23` audit against the
`solutions-architecture/shared-ci-postgres` pattern found that this project
does not currently require PostgreSQL. The full local gate in
[`scripts/ci-local.sh`](../scripts/ci-local.sh) runs `uv lock --check`, locked
dependency sync, package build, `uv run pytest`, and `uv run pip-audit`; it
does not start or probe a database service. The hosted GitHub Actions workflow
uses the same SQLite-backed Django test settings and likewise defines no
PostgreSQL service.

The test topology is deliberately in-process SQLite:
`tests/settings.py` configures `django.db.backends.sqlite3` with
`NAME = ":memory:"`. Consequently:

- Host, port, database, user, and password are not configurable because no
  PostgreSQL connection is used, and there are no hard-coded PostgreSQL
  assumptions to remove.
- There is no physical test database name to make unique; Django creates and
  tears down the in-memory database within each test process. Concurrent CI
  jobs are isolated by their separate processes.
- No PostgreSQL role privileges, extensions, or cleanup job are required.
  Killed runs cannot leak PostgreSQL databases because none are created.
- Hosted CI intentionally matches the local topology rather than using a
  PostgreSQL service container.

This is an explicit exception to the shared-process/ephemeral-database
pattern, not a shared mutable database. SQLite is sufficient for the current
package tests, while PostgreSQL-specific behavior is outside this repository's
audited CI contract. If future tests need PostgreSQL semantics, revisit this
decision first: add a PostgreSQL-backed test configuration with environment-
configurable connection fields, generate a safe unique per-run test database,
require only the CI role privileges needed by Django (normally `CREATEDB`),
and pair teardown with periodic orphan cleanup. Until then, the required
alternative is to keep the existing in-memory SQLite setup and its current
local/hosted CI gates.
