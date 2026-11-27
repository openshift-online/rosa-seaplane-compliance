# Credentials

Every credential this project uses should be scoped to exactly what the
thing consuming it does — not a personal admin token, not a shared
all-access secret. This doc is where to look before running evidence
collection, a scan, or a push to the evidence locker, and where to add a
section when a new evidence source shows up.

## GitHub (`GITHUB_TOKEN`)

Used by:
- `evidence/RSC.CMT.CTRL01.AR01.sh` — `gh api repos/{repo}/branches/{branch}/protection`
- `evidence/RSC.CMT.CTRL01.AR02.sh` — a GraphQL query over merged PRs

Both run once per repository in `config/scope.yaml`, so the token must reach
every one of them, including the private `rosa-seaplane-internal`. A repository
the token cannot read does not stop the run: it is recorded as an `error` in
that AR's `manifest.json` and shows up as missing scope in `make coverage`.

Don't reuse your personal `gh auth token` for this — it carries whatever
scopes your day-to-day admin session has. Create a token scoped to just this
job instead.

**Fine-grained PAT (preferred):**

1. GitHub → **Settings → Developer settings → Personal access tokens →
   Fine-grained tokens → Generate new token**
2. **Token name:** something identifiable, e.g. `rosa-seaplane-compliance-evidence`
3. **Resource owner:** `openshift-online` (the org that owns `rosa-seaplane`)
4. **Expiration:** short-lived (e.g. 90 days) — this is a bot-style
   credential, rotate it rather than making it permanent
5. **Repository access:** "Only select repositories" → every repository in
   `config/scope.yaml`
6. **Permissions → Repository permissions:**
   - Administration: **Read-only** (branch-protection reads are gated
     behind admin-read, not plain repo read)
   - Pull requests: **Read-only**
   - Commit statuses: **Read-only** (AR02 reads each merged PR's status checks,
     `statusCheckRollup` and its contexts; public repositories allow it anonymously, but a
     private one such as `rosa-seaplane-internal` fails with "Resource not
     accessible by personal access token" without it). There is no separate
     "Checks" permission for fine-grained tokens; it exists only for GitHub
     Apps, so in a private repository only commit statuses (which is what Prow's
     `ci/prow/*` checks are) can be judged; a required check that is not a commit
     status is reported as incomplete evidence. If the error persists with Commit statuses granted, the token needs
     a classic `repo` scope or a GitHub App instead.
   - Metadata: Read-only (auto-included, can't be unchecked)
   - Leave everything else "No access"
7. Generate, copy the token (`github_pat_...`)

If the org restricts or blocks fine-grained PATs, fall back to a **classic
PAT** with just the `repo` scope (classic tokens can't scope to a single
repo or to read-only admin, so `repo` is the minimum that still works for
branch-protection reads).

**Wiring it in:** set it in `.envrc` (already `.gitignore`d):

```bash
export GITHUB_TOKEN=github_pat_xxxxxxxx
```

then `direnv allow`. `gh api` prefers `GITHUB_TOKEN`/`GH_TOKEN` over its own
stored keyring credential automatically, so nothing else needs to change —
not even your own `gh auth login` session.

## S3 evidence locker (`RSC_S3_BUCKET`, AWS credentials)

Used by `scripts/push-evidence.sh` (`make push-evidence`) to upload
`evidence/output/` and `.complytime/scan/` to the shared evidence locker.

Needs standard AWS credentials (env vars, a profile, or an assumed role —
whatever `aws` CLI already resolves) with write access to the target
bucket, plus:

```bash
export RSC_S3_BUCKET=<bucket-name>
# export RSC_S3_PREFIX=<prefix>          # optional, defaults to rosa-seaplane-compliance
```

**Local development** (no real AWS account needed) — run a disposable
S3-compatible endpoint and point `push-evidence.sh` at it:

```bash
podman run -d --name local-s3 -p 9090:9090 docker.io/adobe/s3mock:latest
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1
aws --endpoint-url http://localhost:9090 s3 mb s3://rosa-seaplane-evidence
export RSC_S3_BUCKET=rosa-seaplane-evidence RSC_S3_ENDPOINT_URL=http://localhost:9090
```

These `test`/`test` values aren't real secrets — they're s3mock's
no-op local credentials, fine to keep in a shell history or a local
`.envrc`. Never do this against real AWS.

## AWS accounts (`RSC_ENV`)

Local runs evaluate one environment, `integration` by default. Switch with
`make run-local RSC_ENV=stage`: the checks and scope are identical, only the AWS
accounts differ.

**Access works the way the platform's own dev scripts do** (`rosa-seaplane`
`scripts/dev/int-env.sh`, `stage-env.sh`), and never reads or writes your
`~/.aws/config`:

- The account IDs come from the platform's account snapshot,
  `../rosa-seaplane-internal/infra/accounts/<int|stage>/terragrunt-accounts.json`
  (clone `rosa-seaplane-internal` as a sibling, or set `RSC_ACCOUNTS_FILE`).
- `scripts/aws_access.py` writes a **temporary** AWS config from it, logs in with the
  same SAML helper (`../rosa-seaplane/scripts/dev/cached_saml_credentials_process.py`,
  run through `uv`; set `RSC_SEAPLANE_REPO` if your checkout lives elsewhere), and
  deletes the config afterwards. It needs the same Kerberos login those scripts need.
- `config/environments/<env>.yaml` lists only the logical accounts (`central`,
  `regional`, `management-mc01`, ...) and where each one's ID sits in the snapshot.
  **Account IDs are never committed**; a test fails if one appears in any tracked file.

Profiles in the temporary config: `rsc-admin` (SAML login into the control account),
`rsc-<account>-admin` (admin role in a child account) and `rsc-<account>-ro` (the
compliance read-only role). The checks use only the `-ro` profiles.

**The read-only role.** `config/aws/compliance-readonly-role.yaml` defines it and
records every permission with the check that needs it. Until it lives in the
platform's Terraform, `make aws-role` manages it (admin is needed only for that):

```bash
make aws-role ACTION=plan                # default: show what would change, writes nothing
make aws-role ACTION=apply YES=1         # create or update it in every account of RSC_ENV
make aws-role ACTION=verify              # reads work through the -ro profile, writes are denied
make aws-role ACTION=delete YES=1
# optional: ACCOUNT=regional (default: all)
```

`make env` shows the selected environment and whether each account resolves from the
snapshot. Never use an admin profile for the checks themselves.

**AWS collectors** (`evidence/*.sh` using `evidence/lib/aws.sh`) re-run themselves inside
that temporary config, so `make run-local` needs nothing extra beyond the access above,
and they use only the `rsc-<account>-ro` profiles. The container image does not support
them yet (no SAML login, no sibling checkouts there).

## OCI registry — not evidence collection, but part of the pipeline

`make publish-policy` / `make publish-complypack` push the Gemara policy and
the OPA/Rego complypack to `REGISTRY` (`Makefile`). **This defaults to a local-only
registry, not a public one** — nothing is published anywhere public unless
you explicitly repoint `REGISTRY` at one and authenticate to it yourself
(e.g. `podman login your-registry.example.com`). Publishing to a public
registry is a deliberate, manual action, not something to automate casually.

**Local registry** (the default — start it once, then `make publish-policy`
and `make publish-complypack` work as-is):

```bash
podman run -d --name local-oci-registry -p 5050:5000 docker.io/library/registry:2
```

`REGISTRY`'s `http://` prefix is how both publish scripts and
`.complytime/complytime.yaml` opt into plain-HTTP for this local registry —
`scripts/publish-policy-bundle.sh`/`publish-complypack.sh` strip it and pass
`--plain-http` to `oras`/`complypack`; complyctl
itself detects the same prefix on `policies[].url`
(`internal/registry/client.go`'s `NewClient`) and strips it before building
the actual OCI reference. There's no `plain-http: true` field on a
`policies[]` entry — that key belongs to complypack.yaml's schema, not
complyctl's.

The Rego ships as a complypack, which complyctl itself fetches (with the same
`http://` handling), so the stock `opa-provider` needs no registry access and
no patch.

**Pointing at a real registry later:** change `REGISTRY`/`IMAGE_REGISTRY` in
`Makefile` (drop the `http://` prefix for a real TLS registry); `make config`
re-renders `.complytime/complytime.yaml` from it. Then run `make publish-policy`
/ `make publish-complypack` from an authenticated session.

## Adding a new evidence source

When a new `evidence/*.sh` collector needs a credential:

1. Scope it as narrowly as the source allows — read-only, limited to the
   specific repo/resource/API the collector actually touches, short-lived
   if the source supports expiry.
2. Name its env var `RSC_<SOURCE>_<THING>` (matching the `RSC_*` convention
   already used by `RSC_REPO`, `RSC_S3_BUCKET`, etc.).
3. Add a section here: what it's used by, exactly how to mint the minimal
   version of it, and how to wire it into `.envrc`.
4. If local development without the real credential is possible (a mock
   server, a sandbox account), document that too — see the S3 and OCI
   registry sections above for the pattern.
