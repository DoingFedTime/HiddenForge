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
| `lint` | hadolint (threshold `warning`); `cargo fmt --check` and `cargo clippy --all-targets -D warnings` for the runtime; the wizard is rebuilt from its sources and must match (`wizard/build.py --check`); `ruff`, `py_compile` incl. the extensionless CLI, `mypy` over sources *and* tests, `tests/test_version_consistency.py`, and `docker compose config -q` on both shipped compose files |
| `unit` | host unit + property tests with the coverage floor enforced; `cargo test`; the differential tests that hold the Rust runtime to the 2.x reference (torrc, `setup`, the guard monitors' decisions) and the wizard to `setup`; `manifest.json` is checked against the code; `scripts/mutation_spotcheck.py` |
| `mutation (tags and nightly)` | a full `mutmut run` over the 2.x Python reference (`entrypoint.py`, `healthcheck.py`, `vanity.py`), then `scripts/mutation_gate.py`: every mutant that survives must be explained in the gate's allowlist or the job fails. The gate also re-runs each mutant mutmut recorded as a `timeout` on its own, because that label is a wall-clock bound rather than a verdict; a mutant that really hangs must be named in `DOCUMENTED_HANGS`. Tag/schedule only. See `review/MUTATION-2026-09-18.md` |
| `build-and-test` | verifies the build inputs, builds the image offline from them, checks the generated torrc is accepted by the image's Tor, checks the 2.x compatibility forms (and that `sh -c id` and `python3 -c` are refused), the CLI contract, a vanity smoke test, and the live acceptance suite (`HIDDENFORGE_E2E=1`) |
| `security` | trivy and grype over the image at every severity, fixed or not (either finding anything fails the job); trivy fs (secrets, misconfiguration), semgrep (security-audit + dockerfile), gitleaks over every commit and the working tree. Runs daily too, so an advisory published after the last commit is still caught |
| `reproducibility` | clones the commit twice, once under umask 007 and once under 022, and builds each with `--no-cache` for `linux/amd64`; fails if the OCI index digests differ. The two-platform release digest is reproduced by hand before signing |
| `inputs-integrity (nightly)` | `scripts/build_inputs.py verify` over the archived inputs (lock, signatures, checksums), and a warning when Tor has published a newer stable than the one the build pins. Schedule/dispatch only |

Every job has a `timeout-minutes` so a hung step cannot hold the single runner: lint 20, unit 30, mutation 60, build-and-test 30, security 30, reproducibility 30, inputs-integrity 20. `mutation` and `inputs-integrity` do not run on an ordinary push, so a green push run does not include them.

**The inputs.** The build needs the input archive, which is not in the
repository (it is tens of megabytes of packages). The runner reads its path from
the `HIDDENFORGE_INPUTS` repository variable. Fetch it once with
`scripts/build_inputs.py fetch <url> <dir>`; every job that builds verifies it
first.

All jobs use `runs-on: docker`, mapped to **host mode** on
the runner, so job steps execute directly on that machine and have `docker`, `git` and
`python3` available.

Publishing the image and signing its digest are **not** in the workflow. They
are deliberate local steps on the maintainer's machine:

- build the release from a clean checkout of the tag with the reproducible
  recipe in `signatures/README.md`, scan it, and push the same digest to
  `sambent.dev` and Docker Hub
- publish the input archive (`scripts/build_inputs.py pack`) beside the release
- sign the index digest: ML-DSA-65, and SSH-FIDO2 on a hardware key when it is
  available

The hardware signature needs the physical key, so it can never run in CI.

### A tag is the release gate

Pushing a `v*` tag runs every job except `inputs-integrity` (schedule and dispatch only), including the live acceptance suite
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
( cd hiddenforge-rs && cargo fmt --check && cargo clippy --release --locked --all-targets -- -D warnings \
    && cargo test --release --locked && cargo build --release --locked )
.venv/bin/python -m pytest -q tests/rust tests/test_wizard_diff.py
python3 scripts/build_inputs.py verify ./inputs
docker build --build-context inputs=./inputs \
  --build-arg SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" \
  -t sambent.dev/sam/hiddenforge:latest .
docker run --rm -e MYAPP_TOR_SERVICE_HOSTS=80:10.0.0.2:8080 \
  --entrypoint /usr/local/bin/hiddenforge sambent.dev/sam/hiddenforge:latest torrc-preview
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
# Pass the inputs with --var HIDDENFORGE_INPUTS=<dir> on each exec line.
forgejo-runner exec -i -self-hosted -W .forgejo/workflows/ci.yml -j lint  -E push
forgejo-runner exec -i -self-hosted -W .forgejo/workflows/ci.yml -j unit  -E push
forgejo-runner exec -i -self-hosted -W .forgejo/workflows/ci.yml -j security -E push
forgejo-runner exec -i -self-hosted -W .forgejo/workflows/ci.yml -j reproducibility -E push
forgejo-runner exec -i -self-hosted -W .forgejo/workflows/ci.yml -j build-and-test -E push
forgejo-runner exec -i -self-hosted -W .forgejo/workflows/ci.yml -j inputs-integrity -E schedule
forgejo-runner exec -i -self-hosted -W .forgejo/workflows/ci.yml -j mutation -E schedule
```

**Known local limitation.** The `security` job's final "Upload security reports"
step uses `forgejo/upload-artifact`, which needs `ACTIONS_RUNTIME_TOKEN`; `exec`
does not provide it, so that one step fails locally. It is the last step and the
only one, and it is expected to pass on the instance. Do not mistake it for a
workflow defect.

`-E push` selects the push event; `inputs-integrity` is gated to
`schedule`/`workflow_dispatch`, so run it with `-E schedule`.
