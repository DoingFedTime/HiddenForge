# CI

HiddenForge's CI runs on **Forgejo Actions** on `sambent.dev`; nothing runs on
GitHub. The workflow does fetch two pinned actions from github.com
(`actions/checkout`, `hadolint-action`), `upload-artifact` from code.forgejo.org,
and its scanner images from Docker Hub.
The workflow runs on a self-hosted runner, which is where the build and the
tests happen.

## The workflow

`.forgejo/workflows/ci.yml` (Forgejo drives CI from `.forgejo/workflows/`):

| Job | What it does |
|---|---|
| `lint` | hadolint (threshold `warning`), `ruff`, `py_compile` incl. the extensionless CLI, and `mypy` over sources *and* tests |
| `unit` | host unit + property tests with the coverage floor enforced; `manifest.json` is checked against the code (not just parsed); `scripts/mutation_spotcheck.py` |
| `mutation` | a full `mutmut run` over `entrypoint.py`, `healthcheck.py` and `vanity.py`, then `scripts/mutation_gate.py`: every mutant that survives must be explained in the gate's allowlist or the job fails. The gate also re-runs each mutant mutmut recorded as a `timeout` on its own, because that label is a wall-clock bound rather than a verdict and has been measured hiding live survivors; a mutant that really hangs must be named in `DOCUMENTED_HANGS`. Tag/schedule only -- the run takes twenty minutes and more, of which the timeout re-grade is the slow half. See `review/MUTATION-2026-09-18.md` |
| `build-and-test` | `docker build`, the in-container torrc test, the CLI contract checks, a vanity smoke test, and the live acceptance suite (`HIDDENFORGE_E2E=1`) |
| `security` | trivy (image + fs), semgrep (security-audit + dockerfile), gitleaks over every commit and the working tree; runs on a daily schedule so an advisory published after the last commit is still caught. Accepted findings live in `.trivyignore`/`.gitleaks.toml` |
| `reproducibility` | builds the same tree twice under the documented flags, for `linux/amd64` only, and fails if the OCI index digests differ (the two-platform release digest is reproduced by hand before signing) |
| `pin-freshness` | `scripts/check_pins.py` against the Alpine index: fails if a pinned apk version has disappeared, reports (does not auto-bump) a newer one. Schedule/dispatch only |

All jobs use `runs-on: docker`, mapped to **host mode** on
the runner, so job steps execute directly on that machine and have `docker`, `git` and
`python3` available.

Publishing the image and signing its digest are **not** in the workflow. They
are deliberate local steps on the maintainer's machine:

- build the release from a clean checkout of the tag with the reproducible
  recipe in `signatures/README.md`, scan it, and push the same digest to
  `sambent.dev` and Docker Hub
- sign the index digest: ML-DSA-65, and SSH-FIDO2 on a hardware key

The hardware signature needs the physical key, so it can never run in CI.

### A tag is the release gate

Pushing a `v*` tag runs every job except `pin-freshness` (schedule and dispatch only), including the live acceptance suite
in `build-and-test`. **Do not publish an image until that run is green on
the tagged commit** -- a tag whose CI never ran, or failed, must not become an
image. The `reproducibility` and `security` jobs run on a tag too, so the released
bits are reproducible and scanned at the moment they are tagged. `mutation` runs
on a tag for the same reason: a regression that the test suite would not have
caught must not be discovered after the image is published.

## Running the same checks by hand

Every CI job is a thin wrapper over commands that work locally, so a red run can
be reproduced without the runner:

```bash
.venv/bin/ruff check . scripts/hiddenforge   # plain `.` skips the extensionless CLI
MYPY=.venv/bin/mypy sh scripts/typecheck.sh
.venv/bin/python -m pytest -q --cov=entrypoint --cov-report=term
docker build --build-arg SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" \
  -t sambent.dev/sam/hiddenforge:latest .
# --entrypoint python3 is REQUIRED and is not decoration. The image's ENTRYPOINT
# is `python3 /usr/local/bin/entrypoint.py`, so without it these arguments are
# appended to the supervisor's argv: the container starts a real Tor service,
# bootstraps, and runs forever. The smoke test never executes and the command
# never returns. (This line used to omit it; running it verbatim is how that was
# found.)
docker run --rm --entrypoint python3 sambent.dev/sam/hiddenforge:latest \
  /usr/local/bin/tests/test_torrc.py
HIDDENFORGE_E2E=1 .venv/bin/python -m pytest tests/test_e2e_live.py -v
```

## Running the workflow locally (and why you should)

A workflow that has never been executed is not a workflow. Every job here was
first run for real with `forgejo-runner exec`, in host mode, and that is how the
following got found and fixed, none of which any amount of reading had surfaced:

- `lint` failed: its tool venv had `ruff` + `mypy` but not `pytest`/`hypothesis`,
  which `scripts/typecheck.sh` needs because it checks `tests/` too.
- `lint` failed to fetch `hadolint/hadolint-action`: it does not exist on
  `code.forgejo.org`, and short action names resolve against the instance's
  `DEFAULT_ACTIONS_URL`; the step now uses the fully-qualified GitHub URL.
- `security` failed on semgrep: `scripts/check_pins.py` fed `--branch`/`--arch`
  into `urllib`; both are now bounded and the call carries a `# nosemgrep`.
- `build-and-test`'s torrc smoke test was a folded YAML plain scalar, so its
  backslash-continuation mangled the script path and the step could never pass.

```
# If a runner daemon is running on this machine, stop it first: it holds the
# cache DB (actcache/bolt.db).
forgejo-runner exec -i -self-hosted -W .forgejo/workflows/ci.yml -j lint  -E push
forgejo-runner exec -i -self-hosted -W .forgejo/workflows/ci.yml -j unit  -E push
forgejo-runner exec -i -self-hosted -W .forgejo/workflows/ci.yml -j security -E push
forgejo-runner exec -i -self-hosted -W .forgejo/workflows/ci.yml -j reproducibility -E push
forgejo-runner exec -i -self-hosted -W .forgejo/workflows/ci.yml -j build-and-test -E push
forgejo-runner exec -i -self-hosted -W .forgejo/workflows/ci.yml -j pin-freshness -E schedule
forgejo-runner exec -i -self-hosted -W .forgejo/workflows/ci.yml -j mutation -E schedule
```

**Known local limitation.** The `security` job's final "Upload security reports"
step uses `forgejo/upload-artifact`, which needs `ACTIONS_RUNTIME_TOKEN`; `exec`
does not provide it, so that one step fails locally. It is the last step and the
only one, and it is expected to pass on the instance. Do not mistake it for a
workflow defect.

`-E push` selects the push event; `pin-freshness` is gated to
`schedule`/`workflow_dispatch`, so run it with `-E schedule`.
