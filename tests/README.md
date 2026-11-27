# Tests

`make test` (or `./tests/run.sh`) runs the policy suite. It runs `conftest`
through a pinned container (`docker.io/openpolicyagent/conftest`), so it needs
only podman or docker, no local conftest install. Set `CONFTEST_BIN=conftest` to
use a local binary instead, or `CONFTEST_IMAGE` to pin a different image.

## What runs

- **Rego unit tests** (`conftest verify`): per-rule positive and negative cases
  for every assessment requirement, in
  `opa/change-management/policy/*_test.rego`. Includes tests that each package
  ignores the other AR's evidence.
  `*_test.rego` files are excluded from the published bundle.
- **Fixtures** (`conftest test`): the real policies run over realistic
  evidence, `fixtures/<AR>/pass.json` (must pass) and `fail.json` (must be
  denied). These also document the shape produced by `evidence/<AR>.sh`.
- **Findings report** (`test_build_findings.py`, `test_findings_rules.py`,
  `test_render_findings_html.py`): the builder is a pure function over pre-computed policy
  results, tested on synthetic data, plus one integration test that runs the real policies
  over the fail fixtures when `conftest` is installed (skipped with a message otherwise).
  The rules catalog must match the Rego exactly: a `deny` without `with_rule("<id>", ...)`,
  an id missing from `config/findings/rules.yaml`, an unused id, or a rule without a fix hint
  fails the build.
- **Python unit tests** (`tests/python/`), including that the entrypoint fails a
  run when an AR has no evidence. The trail viewer is tested on synthetic data
  only: `tests/python/trace_fakes.py` builds a fake repository (two domains, a KSI
  framework, an 800-53 framework and a third certification, fake repos and users)
  and `tests/fixtures/trace.sample.json` is its output with hostile `<script>`
  text injected. A test fails if the sample drifts from what `build_trace.py`
  produces, and another builds the real repo's trace to prove every link resolves.

## Not covered

- End-to-end pipeline (evidence collectors to `complyctl scan`). Low priority:
  failures there are loud. Can be added to `run.sh` later.
