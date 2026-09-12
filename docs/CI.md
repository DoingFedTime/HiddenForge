# CI

HiddenForge's CI runs on **Forgejo Actions** on `sambent.dev`. GitHub is not in
the loop.
The workflow runs on a self-hosted runner, which is where the build and the
tests happen.

## The workflow

`.forgejo/workflows/ci.yml` (Forgejo drives CI from `.forgejo/workflows/`):

| Job | What it does |
|---|---|
| `lint` | hadolint (threshold `warning`), `ruff`, `py_compile` incl. the extensionless CLI |
| `unit` | host unit + property tests with the coverage floor enforced; `manifest.json` parses |
| `build-and-test` | `docker build`, the in-container torrc test, the CLI contract checks, a vanity smoke test, and the live acceptance suite (`HIDDENFORGE_E2E=1`) |

All jobs use `runs-on: docker` / `ubuntu-latest`, both mapped to **host mode** on
the runner, so job steps execute directly on that machine and have `docker`, `git` and
`python3` available.

Publishing the image to `sambent.dev` and signing the digest are **not** in the
workflow. They are deliberate local steps:

- build, scan, make the SBOM and push the image
- sign the pushed digest (ML-DSA-65, and SSH-FIDO2 on a hardware key)

Signing needs the physical key, so it can never run in CI.

### A tag is the release gate

Pushing a `v*` tag runs the whole workflow, including the live acceptance suite
in `build-and-test`. **Do not publish an image until that run is green on
the tagged commit** -- a tag whose CI never ran, or failed, must not become an
image. The `reproducibility` and `security` jobs run on a tag too, so the released
bits are reproducible and scanned at the moment they are tagged.

## Running the same checks by hand

Every CI job is a thin wrapper over commands that work locally, so a red run can
be reproduced without the runner:

```bash
.venv/bin/ruff check .
.venv/bin/python -m pytest -q --cov=entrypoint --cov-report=term
docker build --build-arg SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" \
  -t sambent.dev/sam/hiddenforge:latest .
docker run --rm sambent.dev/sam/hiddenforge:latest python3 /usr/local/bin/tests/test_torrc.py
HIDDENFORGE_E2E=1 .venv/bin/python -m pytest tests/test_e2e_live.py -v
```
