# Pre-commit secret scanner

A Git pre-commit hook and CI check using Yelp's `detect-secrets` 1.5.0 to block hardcoded credentials. A small custom scanner remains as a separate CLI exercise with baseline and staged-index support. Neither scanner proves that a repository contains no secrets.

## Architecture

- `.pre-commit-hooks.yaml` exposes `secret-scan`, backed by the installed `detect-secrets-hook` executable. `pyproject.toml` packages the project and declares the scanner dependency so installation works in a consumer repository.
- `.pre-commit-config.yaml` checks this repository with the same detector. Its reviewed baseline is `.detect-secrets.baseline`. Intentional detector fixtures in `tests/` and `examples/dirty.env` are excluded from the repository self-scan; integration tests explicitly prove a dirty consumer file is blocked.
- `scan.py`, `baseline.py`, and `cli.py` provide the separate custom regex/entropy scanner. It has its own `.secrets-baseline.json` format, which is not compatible with detect-secrets baselines.
- `cli.py --staged` reads NUL-delimited staged paths and their bytes from Git's index, including renamed files. Unstaged changes cannot replace the contents being checked.

## Prerequisites

Python 3.12+, Git, and pip. Install validation tools with:

```bash
pip install -r requirements-test.txt
```

## Install in another repository

Copy `examples/pre-commit-config-sample.yaml` to `.pre-commit-config.yaml` and replace `REPLACE_WITH_REVIEWED_COMMIT_SHA` with the reviewed commit SHA for this repository. No release tag is published yet.

```bash
pip install pre-commit detect-secrets==1.5.0
detect-secrets scan > .detect-secrets.baseline
# Review every baseline finding before accepting it.
detect-secrets audit .detect-secrets.baseline
pre-commit install
pre-commit run --all-files
```

Commit the reviewed baseline and configuration. The pre-commit framework installs the packaged hook in an isolated environment and checks staged files during `git commit`. It temporarily stashes unstaged changes, including for partially staged files. A new unbaselined secret blocks the commit. Inspect and remove the credential rather than bypassing the hook.

For CI, install the validation requirements and run `pre-commit run --all-files` after checkout. CI also checks packaging and actual hook installation through the integration tests. `--staged` is not a substitute for scanning a checked-out PR in CI: checkout normally has an empty index diff.

## Custom CLI examples

```bash
python cli.py examples/clean.env
python cli.py examples/dirty.env
python cli.py --staged
python cli.py --staged --update-baseline
python cli.py --staged --entropy-threshold 4.6
```

The dirty example uses published AWS example credentials and a deliberately invalid generic credential. It exits 1 without a baseline. The clean example uses environment-variable references and exits 0. `--update-baseline` explicitly accepts the findings into the custom baseline; review them first. Git read errors exit 2.

The custom scanner checks AWS key shapes, private-key headers, generic credential assignments, Slack token shapes, and high-entropy quoted strings. `# secret-scan: allow` suppresses a custom-scanner line; detect-secrets instead uses `# pragma: allowlist secret` or its own reviewed baseline.

## Security considerations

- Scanning needs no cloud credentials. Hook installation downloads Python packages; the integration tests install into temporary environments. detect-secrets can verify supported tokens over the network; use its `--no-verify` option for offline-only scanning.
- Never add live credentials as fixtures. Provider-shaped examples can trigger push protection even when invented. Historical commits must also be cleaned before publication when that happens.
- The custom report masks most of the matching line; it is not suitable for confidential logs because it retains a prefix and suffix. detect-secrets reports the detector and location.
- Baselines and allow comments suppress findings. Review them as security-sensitive changes. Binary files are outside the custom scanner's coverage.
- Repository self-scan exclusions are limited to intentional fixtures. Consumer configurations should not copy those exclusions indiscriminately.

## Idempotency

Both scanners give the same decision for unchanged input and configuration. Custom baseline keys use path, rule, and line hash; moving a line within a file does not invalidate it. Repeating `--update-baseline` for unchanged files writes the same content.

## Validation

```bash
ruff check .
ruff format --check .
python -m unittest discover -s tests
pre-commit run --all-files
python cli.py scan.py baseline.py cli.py --baseline .secrets-baseline.json
```

The suite covers detector and baseline behavior, error exit codes, index versus worktree contents, filenames with spaces, and staged renames. It installs the packaged hook into a temporary consumer repository, accepts a clean real commit, and rejects a partially staged secret while restoring the clean unstaged contents. No live cloud resource or real credential is used.

## Known limitations

This is a heuristic guard, not a credential inventory or a replacement for revocation and server-side scanning. The custom scanner is a teaching implementation; the published hook uses detect-secrets. Tests cover local Git delivery, not organization-wide enforcement or every detector/provider.
