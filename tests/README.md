# Tests

`make test` (or `./tests/run.sh`) runs the policy suite. It runs `conftest`
through a pinned container (`docker.io/openpolicyagent/conftest`), so it needs
only podman or docker, no local conftest install. Set `CONFTEST_BIN=conftest` to
use a local binary instead, or `CONFTEST_IMAGE` to pin a different image.

## What runs

- **Rego unit tests** (`conftest verify`): per-rule positive and negative cases
  for `RSC.CMT.CTRL01.AR02`, in
  `opa/change-management/policy/github_default_branch_merge_review_test.rego`.
  `*_test.rego` files are excluded from the published bundle.
- **AR02 fixtures** (`conftest test`): the real policy run over realistic
  evidence, `fixtures/RSC.CMT.CTRL01.AR02/pass.json` (must pass) and `fail.json`
  (must be denied). These also document the shape produced by
  `evidence/RSC.CMT.CTRL01.AR02.sh`.

## Stubbed

- **AR01 (ampel):** evaluated by ampel's builtin `github/branch-rules` spec
  against the live repo, so there is no authored policy of ours to unit-test.
  `fixtures/RSC.CMT.CTRL01.AR01/{pass,fail}.json` are staged as sample
  branch-protection snapshots; wiring a fixture-based ampel check is a TODO.

## Not covered

- End-to-end pipeline (evidence collectors to `complyctl scan`). Low priority:
  failures there are loud. Can be added to `run.sh` later.
