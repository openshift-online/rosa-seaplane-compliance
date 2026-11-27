# Adding a KSI

A playbook for an engineer who is new to compliance and has only this repo. Read the
README glossary first ("Terms you'll meet"). The list of what is left to build is
[ksi-backlog.md](ksi-backlog.md).

## What "done" means

`make coverage` gives each in-phase KSI a state:

| State | Meaning |
| :-- | :-- |
| Not started | No AR is mapped to it. |
| In progress | At least one AR is mapped, but not yet Covered. |
| Covered | At least 2 **implemented** automated methods, reaching every in-scope target. |
| SDR-ready | Covered, every related control decided, and the explanations written and reviewed. |

A **method** is an AR that counts as implemented when all four hold: it is mapped to the KSI,
its policy plan is automated, its Rego package exists, and `tests/fixtures/<AR>/` has both
`pass.json` and `fail.json`. Use **two methods of different kinds**: *intent* (is it
configured?) and *behavioral* (did it hold in practice?). Coverage never depends on pass or
fail: a failing check is a finding, not a gap in your work.

The three finished KSIs are your worked examples:

| KSI | Intent method | Behavioral method | Targets |
| :-- | :-- | :-- | :-- |
| `KSI-CMT-VTD` | `RSC.CMT.CTRL01.AR01` merge gate | `RSC.CMT.CTRL01.AR02` approvals | GitHub repos |
| `KSI-IAM-SNU` | `RSC.IAM.CTRL01.AR01` credential report | `RSC.IAM.CTRL01.AR02` CloudTrail per-key lookup | AWS accounts |
| `KSI-CMT-LMC` | `RSC.CMT.CTRL02.AR01` audit logging, backed by Prowler | `RSC.CMT.CTRL01.AR02` (shared) | AWS accounts and repos |

`KSI-CMT-VTD` has a third, post-merge method in progress; do not copy from it until it lands.

## 0. Before you start

Do the README's one-time setup. For AWS targets you also need a valid Kerberos ticket
(`kinit`) and the sibling checkouts `rosa-seaplane` and `rosa-seaplane-internal`
(`docs/credentials.md`). Work on one branch; stage files by name.

## 1. Understand the KSI

```bash
jq '.KSI.IAM.indicators["KSI-IAM-SNU"]' mappings/vendor/fedramp/fedramp-consolidated-rules.json   # statement, related controls
make coverage KSI=KSI-IAM-SNU                                                                     # state, open controls, next steps
```

- The **statement** is the outcome you must prove. Design measures for *it*; the related
  800-53 controls are a completeness checklist, not the requirement.
- Related controls look like `cm-3.2`. The mapping files write them `CM-03 (02)`;
  `scripts/fedramp_data.py` normalizes between the two.
- **Prowler's candidate list** for each KSI is a starting point only. It lives in the pinned
  Prowler install: `jq -r '.requirements[]|select(.id=="KSI-MLA-ALA")|.checks.aws[]' <prowler-venv>/lib/python3.12/site-packages/prowler/compliance/fedramp_20x_ksi_2026.json`.
  It maps checks to KSIs loosely (see "The Prowler rule").
- Check `mappings/fedramp-20x/ksi-scope.yaml`: the KSI must be in the `automatable` or `hybrid`
  bucket. A hybrid KSI needs human judgment; automate only its machine-checkable part.

## 2. Choose the methods, and use existing tools first

Prefer, in this order: a check Prowler already has and that measures exactly what you need;
a thin collector over a cloud API or the GitHub API; custom code last. Write down, per
method, *what fact it measures* and *why that proves the KSI's outcome*.

### The Prowler rule

Prowler's PASS/FAIL may be the verdict for the facts its checks measure; we do not
re-implement it. The one rule: **before relying on a check for a requirement, read what it
measures against what the requirement needs**, and record why each check is in or out. Do the
reading *before* running anything, and never add or drop a check because it passed or failed.

```bash
$RSC_PROWLER aws --list-checks --service iam --no-banner          # what exists
<prowler-venv>/lib/python3.12/site-packages/prowler/providers/aws/services/<svc>/<check>/<check>.metadata.json   # what it says it measures
```

Read the check's Python too: it can judge more than its title says. Two real examples:

- `KSI-CMT-LMC`: Prowler maps 16 AWS checks. [config/prowler/checks.yaml](../config/prowler/checks.yaml)
  keeps **3** and records why the other **13** are out: nine alarms on specific change types
  (the KSI names none, so requiring them imposes a benchmark), S3 data events (data operations,
  not changes to the environment), the configuration recorder (a different capability), and
  `cloudtrail_cloudwatch_logging_enabled`, which judges every trail visible in the account
  including organization trails the account does not own.
- `KSI-IAM-SNU`: the credential checks Prowler offers (key age, unused keys, two active keys)
  all **passed** for an account that had a user with an active, recently used long-term key.
  They ask different questions from "is there a standing long-term key?". So the identity
  checks use our own small collectors instead, and Prowler is not used there.

`config/prowler/checks.yaml` is the tracked record. Prowler is **pinned** (`prowler-version`);
the collector refuses any other version, because a release can change what a check measures.
Upgrade on purpose: read the changed checks, then change that number, the README and the tests
together.

## 3. Write the neutral control, AR and policy plan

Catalogs and policies are certification-neutral (`CLAUDE.md`): no "FedRAMP", "KSI" or "NIST"
wording in `gemara/` or `opa/`. Certification vocabulary lives only in `mappings/`.

| File | What to add | Example |
| :-- | :-- | :-- |
| `gemara/<domain>/controls.yaml` | control `RSC.<FAM>.CTRLnn` and its ARs `...ARnn`: one testable condition each, with `applicability` (`github_repositories` or `aws_accounts`) | [gemara/identity-access/controls.yaml](../gemara/identity-access/controls.yaml) |
| `gemara/<domain>/policy.yaml` | an assessment plan `RSC.<FAM>.POL01.APnn` per AR: `Intent` or `Behavioral`, `Automated`, `frequency: daily`, executor `opa` | [gemara/identity-access/policy.yaml](../gemara/identity-access/policy.yaml) |

State honestly in the AR text what it cannot see (for example, "a credential deleted inside
the window is outside what it can see"). A new domain also needs both of its files listed under
`gemara.sources` in [complypack.yaml](../complypack.yaml) (complypack has no glob support;
`tests/python/test_render_config.py` fails if one is missing) and a `schemas:` entry for each
new platform schema (section 5). `.complytime/complytime.yaml` is generated from the domains (`make config`),
so it needs no edit.

Check the catalog reads well: `complypack requirements --catalog RSC.IAM.CTRL --config complypack.yaml --format text`.

## 4. Write the collector

One executable per AR in `evidence/`, named by its AR id, sourcing `evidence/lib/collect.sh`
(GitHub repos: `collect_repo`; any other target: `collect_target` plus `rsc_list_targets`, with
`evidence/lib/aws.sh` for AWS accounts). The contract, enforced by `rsc_collect_all`:

- **One evidence file per target** in `evidence/output/<AR>/<target>.json`, plus
  `manifest.json` (per target `collected` or `error`, with the first line of the error).
  The manifest deliberately has **no** `assessment_requirement` key: the Rego judges every JSON
  file in the directory and must not treat the manifest as evidence.
- **A failing target never stops the others and is never a pass.** It is recorded as `error`
  and shows up as missing scope (`targets 6/7`). The collector itself fails only if *no* target
  was collected, and the scan is refused for an AR with no evidence at all.
- **Never fail silently.** `collect_*` runs where `set -e` is ignored, so guard every command
  with `|| return 1`. Capture an exit status on the same line (`out="$(cmd)" && ...; rc=$?`):
  `rc=$?` after an `if` always reads 0.
- **Retry only transient server errors** (HTTP 5xx), through `rsc_retry`; never retry a 403 or
  404. Pace calls to the API's limit and treat "throttled out" as an error.
- **Read-only, least privilege.** AWS collectors call `rsc_aws_reexec "$0"` first (it re-runs
  the collector inside the temporary AWS config from `scripts/aws_access.py`) and use only the
  `rsc-<account>-ro` profile. If a read is denied, add the action to
  [config/aws/compliance-readonly-role.yaml](../config/aws/compliance-readonly-role.yaml) with a
  `needed-by` line, then re-apply with `make aws-role ACTION=apply YES=1` (an admin step; ask
  first) and `make aws-role ACTION=verify`.
- Put parsing in a small Python helper in `evidence/lib/` that reads stdin and prints one JSON
  document (see `iam_credential_report.py`, `iam_key_usage.py`, `prowler_findings.py`), so unit
  tests need neither the cloud nor a shell.

Examples: [evidence/RSC.IAM.CTRL01.AR01.sh](../evidence/RSC.IAM.CTRL01.AR01.sh) (AWS API),
[evidence/RSC.CMT.CTRL02.AR01.sh](../evidence/RSC.CMT.CTRL02.AR01.sh) (Prowler),
[evidence/RSC.CMT.CTRL01.AR02.sh](../evidence/RSC.CMT.CTRL01.AR02.sh) (GitHub GraphQL, paging).

### Event or state: declare it in `config/history/ar-basis.yaml`

Every automated method is exactly one of two kinds, and the daily history and backfill depend on it:

- **`event`**: it judges items timestamped inside a day (merged PRs, key-use events, pipeline runs).
  The collector takes **one UTC day** and can be rerun for a missed day (a backfill).
  Source `rsc_day_window || exit 1` after `collect.sh`: it sets `DAY_DATE`, `DAY_START`, `DAY_END`
  from `RSC_DATE` (default yesterday), refusing today, the future and anything over 90 days old. Collect
  exactly the items in the half-open `[DAY_START, DAY_END)` (an item at `DAY_END` belongs to the next
  day: mind sources whose end time is inclusive), and write `covers_date` and
  `window: {start, end}` at the top level of every evidence file (the record builder refuses evidence
  that does not say it covers the record's day). A day with nothing in it is a **complete, empty
  collection and must pass**: never add a rule such as "no items found". The safeguard against a
  silent gap is completeness: the target was reached, every page down to the day was read, nothing was
  capped; anything else is an error or `collection.complete: false`, never a pass. Judge facts that
  change after the day (approvals, configuration) as of collection time, and say so in
  `evidence/known-gaps.yaml`.
- **`state`**: it judges the present (configuration, which keys exist, health). It ignores the date,
  records `generated_at`, and a backfill records it as `not_collected` for a past day.

An event method that also has rules reading the present (for example "the head is deployed") lists
them as `state_rules`; a backfill ignores them. The AR has no entry? The record builder refuses to
build a record until it does.

## 5. Normalize the evidence

The evidence is what the Rego reads, so shape it for the *question*, in source-neutral names
(`principal_type`, `credential_type`, `active`) so another source can produce the same shape.

- Required fields: `assessment_requirement`, a logical target name (`regional`, `owner/repo`), and,
  for non-trivial collections, `collection: {complete: true|false, ...}` so a partial read can
  never pass.
- **Keep out:** account IDs, ARNs, full key ids, emails, source IPs, user agents, raw event
  dumps, commit messages. Use logical names and counts; keep only the fields the policy needs.
- Write the shape as a CUE schema, `schemas/<platform>.cue`, and list it under `schemas:` in
  `complypack.yaml` like the existing ones. `tests/run.sh` validates every fixture against it
  (with `complypack validate-policy` and `test-policy`; that step is skipped, with a notice, if
  `complypack` is not installed, so install it).

## 6. Write the Rego

One package per AR in `opa/<domain>/policy/`, listed in that directory's
`complytime-mapping.json` (package id to AR id). The opa provider runs **every package on every
file** under the evidence directory, so:

```rego
# platform: principal-credentials
# schema: schemas/principal-credentials.cue
package rosa_seaplane.identity_access.long_term_credentials
import rego.v1
applies if input.assessment_requirement == "RSC.IAM.CTRL01.AR01"
with_rule(id, text) := sprintf("%s [rule: %s]", [text, id])
```

Guard every rule on `applies`. `tests/run.sh` reads these lines with `sed`, so keep the format
exactly: the `# platform:` name must equal the schema file's name (`schemas/<platform>.cue`),
and the `applies` line must end with the quoted AR id (no trailing comment). `make trace`
also fails if the `# schema:` header does not point at an existing file.

- **Empty or incomplete evidence must fail**, and zero items is valid only when the collection
  says it is complete. A missing evidence file produces no denial, which is why the entrypoint
  refuses to scan an AR with none.
- Every `deny` message is a plain string ending in `[rule: <id>]`. Add the id to
  [config/findings/rules.yaml](../config/findings/rules.yaml): `ar`, `kind` (`violation` or
  `incomplete-evidence`), `title`, a human-written `fix`, an `example` message the pattern
  must match, and an optional `subject` regex. `tests/python/test_findings_rules.py` fails on
  an id that is used but not catalogued, catalogued but unused, or lacking a fix hint.
- If the Rego reads one tool's vocabulary (Prowler check ids), name the file and package for it
  (`prowler_account_change_logging.rego`) so the coupling is explicit.
- Write `<name>_test.rego` unit tests (positive, negative, and "ignores other ARs' evidence"),
  and `tests/fixtures/<AR>/pass.json` and `fail.json` (synthetic; build fake IDs at run time).
  The test runner needs both fixtures for every AR directory.

## 7. Write the mappings

`mappings/<domain>-to-ksi.mapping.yaml` and `<domain>-to-nist.mapping.yaml`, one mapping entry
per AR with `source` (the AR), `targets` (`KSI-...` or `"AC-02"`), a `strength`, and a
`rationale`. **The rationale text feeds the SDR**: write it as an explanation to an assessor
of why this measurement demonstrates the KSI. Map to an 800-53 control only where the AR
genuinely evidences it (we deliberately did not map `AU-10` to a check that does not show
non-repudiation). See [mappings/identity-access-to-ksi.mapping.yaml](../mappings/identity-access-to-ksi.mapping.yaml).

## 8. The KSI record, in the same PR

`mappings/fedramp-20x/ksi/<KSI>.yaml` holds what cannot be derived: `target-types`, and the
three explanations (`measures`, `automation-verification`, `validation`). Create it in the same
PR as the checks. A model may draft it, but a person must review it, because assessors check
that what is written matches what runs.

- Drafted text starts with `[Proposed, pending review]`; until a person edits it and removes
  the marker, coverage counts the narrative as **not written** (and the marker is visible in
  the SDR text, because the SDR carries the record's words).
- Say what is *not* measured (for example non-AWS identities). If the KSI is only partly
  covered, the SDR status stays `Partially Implemented`.
- **Control decisions** (`inherited` or `not-applicable`) need a `rationale`, and a second
  person approves any exception. Leave `control-decisions: {}` rather than guess. A related
  control is "addressed" automatically when one of the KSI's ARs maps to it.
- The automation exemption (`config/automation.yaml`) is an example of an approval recorded by
  a second person: `approved-by` stays empty until they add themselves in a PR.

## 9. Record the limits

Add each AR to [evidence/known-gaps.yaml](../evidence/known-gaps.yaml): what its check cannot
see, in **generic structural wording only** (the repo is public: never a repo, account,
principal or PR name, never the current state of a system). A passing result means "no problem
found within these limits". `tests/python/test_findings_rules.py` fails if an AR has none.

## 10. Verify

```bash
make test && make validate     # Rego, fixtures vs schemas, Python tests, account-ID guard; cue vet of catalogs and mappings
make publish-policy publish-complypack   # republish after any control, policy or Rego change
make run-local                 # collect and scan (RSC_ENV=integration by default)
make coverage KSI=KSI-XXX-YYY  # 2 methods? targets all reached? open controls?
make findings                  # what the checks found, what is incomplete, gaps and limits
make why AR=RSC.XXX.CTRLnn.ARnn   # per-target denials for one AR
make sdr-view                  # open output/sdr/index.html: the AR page, the Findings tab
```

Also: no 12-digit number or account ARN anywhere tracked (`tests/python/test_no_account_ids.py`),
no real findings in tracked files, and the README's tables updated only where something
changed. The real run may *fail*: that is data, not a defect. Do not make it pass.

## Mistakes we already made, so you do not

- **The overall status rollup is not "required checks passed".** It includes items that are not
  required and never resolve on a merged PR (a pending merge-bot status, queued or skipped
  third-party checks). AR02 used to judge that rollup, which made most of its findings noise; it
  now judges only the checks branch protection requires, per PR, on the last commit.
- **A GitHub review decision is not how this team approves.** Approval is Prow: `lgtm` and
  `approved` labels set by `/lgtm` and `/approve` commands, which also appear in review bodies,
  and a command made after the merge does nothing. Read how the team actually works.
- **A check that did not run must never read as a pass.** Prowler emits nothing for a service it
  cannot list, and can return MANUAL; an absent finding, an incomplete collection and an
  unreached target are each their own outcome.
- **Provider passes can contradict the KSI** (the IAM example above): read the check.
- **`conftest` runs every package on every file.** Guard every rule on `applies`, and keep
  `assessment_requirement` out of `manifest.json`.
- **`rc=$?` after an `if` reads 0**, and `set -e` is ignored inside functions called from `if`.
- **GitHub pages by `updatedAt`**, not merge time: stop paging when a page's oldest `updatedAt`
  is before the start of the day, not when one merge date is.
- **CloudTrail's `--end-time` is inclusive**: drop an event at exactly the end of the day, or it is
  counted in two days.
- **An empty day must pass**, so a "no items found" rule is a bug for an event check (it failed every
  quiet day); check that the collection was complete instead.
- **Fine-grained GitHub tokens have no "Checks" permission**; reading check state on a private
  repo needs "Commit statuses" read.
- **Fake account IDs must be built at run time** (`"1" * 12`): a 12-digit literal fails the
  guard test.
- **IAM rejects some characters in tags** (parentheses, semicolons) only after the call;
  `scripts/aws_readonly_role.py` now validates them first.
- **`curl --aws-sigv4` mis-signs query strings with spaces or commas** when you use
  `--data-urlencode`: percent-encode the query yourself and put it in the URL.
- **Your Kerberos ticket expires overnight**; AWS collectors then fail with "Kerberos
  authentication failed". Run `kinit` again.
- **Do not weaken a failing check.** If a check looks wrong, fix what it measures and explain
  why in the PR; real findings stay visible.
