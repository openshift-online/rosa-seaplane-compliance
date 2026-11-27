# TODO: point at a real registry when this project has one; update it here
# (`make config` renders .complytime/complytime.yaml from it). Defaults to a local-only registry
# (see docs/credentials.md) so `make publish-policy`/`make publish-complypack`
# work out of the box without touching anything public. REGISTRY carries an
# "http://" prefix (stripped by the publish scripts, which pass --plain-http/
# --tls=false when they see it); IMAGE_REGISTRY has no scheme since image
# tags don't take one.
REGISTRY             ?= http://localhost:5050/rosa-seaplane-compliance
IMAGE_REGISTRY        ?= localhost:5050/rosa-seaplane-compliance
POLICY_VERSION       ?= v0.1.0
COMPLYPACK_VERSION   ?= v0.1.0
IMAGE                ?= $(IMAGE_REGISTRY)/complyctl-runner:latest

# Environment evaluated by local runs: config/environments/<name>.yaml
# (integration or stage). Switching it only changes which AWS profiles are used.
RSC_ENV              ?= integration
export RSC_ENV

# Prefer a local .venv (python3 -m venv .venv && .venv/bin/pip install -r requirements.txt).
PYTHON               ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)

# Gemara CUE schema version to validate against; only affects `make validate`,
# not complyctl itself. Pulled from the CUE Central Registry.
GEMARA_SCHEMA_VERSION ?= v1.6.0

.PHONY: daily record history-init history-summary findings aws-role why env config validate test publish-policy publish-complypack build-image run-local run-image doctor coverage push-evidence sdr sdr-view trace

## Explain why an AR failed: per-evidence-file denials and unreached targets.
## Usage: make why AR=RSC.CMT.CTRL01.AR02
why:
	./scripts/why.sh $(or $(AR),$(error set AR=<assessment requirement id>))

## Manage the compliance read-only AWS role in every account of RSC_ENV.
## ACTION=plan|apply|verify|delete (default plan), YES=1 to write, ACCOUNT=<name> to limit.
aws-role:
	$(PYTHON) scripts/aws_readonly_role.py $(or $(ACTION),plan) --env $(RSC_ENV) $(if $(ACCOUNT),--account $(ACCOUNT)) $(if $(YES),--yes)

## Show the selected environment and which AWS profile variables are set.
env:
	$(PYTHON) scripts/environment.py $(RSC_ENV)

## Render .complytime/complytime.yaml from the gemara/*/ domains (gitignored).
config:
	$(PYTHON) scripts/render_complytime_config.py --registry $(REGISTRY) \
	  --policy-version $(POLICY_VERSION) --complypack-version $(COMPLYPACK_VERSION)

## Validate every domain's Gemara YAML and every mapping against the upstream
## CUE schema (needs `cue` CLI).
validate:
	@set -e; for d in gemara/*/; do \
	  echo "cue vet $$d"; \
	  cue vet -c -d '#ControlCatalog' github.com/gemaraproj/gemara@$(GEMARA_SCHEMA_VERSION) $${d}controls.yaml; \
	  cue vet -c -d '#Policy' github.com/gemaraproj/gemara@$(GEMARA_SCHEMA_VERSION) $${d}policy.yaml; \
	done; \
	for m in mappings/*.mapping.yaml; do \
	  echo "cue vet $$m"; \
	  cue vet -c -d '#MappingDocument' github.com/gemaraproj/gemara@$(GEMARA_SCHEMA_VERSION) $$m; \
	done
	@echo "All Gemara YAML files are schema-valid."

## Run the policy test suite (Rego unit tests + pass/fail fixtures).
test:
	PYTHON=$(PYTHON) ./tests/run.sh

## Publish each domain's control catalog + policy as one OCI artifact.
publish-policy:
	@set -e; for d in gemara/*/; do d=$$(basename $$d); \
	  ./scripts/publish-policy-bundle.sh $$d $(REGISTRY)/policies/$$d:$(POLICY_VERSION); \
	done

## Publish all domains' Rego (+ merged complytime-mapping.json) as one complypack.
publish-complypack:
	./scripts/publish-complypack.sh $(REGISTRY)/complypacks/rosa-seaplane:$(COMPLYPACK_VERSION)

## Build the ECS-ready container image (requires podman or docker).
build-image: config
	podman build -t $(IMAGE) -f containers/complyctl/Containerfile .

## Run evidence -> scan using locally installed complyctl + providers. The event collectors cover one
## UTC day: RSC_DATE (or DATE) = YYYY-MM-DD, default yesterday (the only day this accepts; earlier days
## are backfills: `make daily DATE=...`). The state collectors judge the present.
run-local: config
	RSC_EVIDENCE_DIR="$$(pwd)/evidence/output" RSC_REPO_ROOT="$$(pwd)" GITHUB_TOKEN=$${GITHUB_TOKEN:?set GITHUB_TOKEN} \
	  $(if $(or $(RSC_DATE),$(DATE)),RSC_DATE=$(or $(RSC_DATE),$(DATE))) \
	  $(PYTHON) containers/complyctl/entrypoint.py

## Run the same loop inside the built container image.
run-image:
	podman run --rm -e GITHUB_TOKEN=$${GITHUB_TOKEN:?set GITHUB_TOKEN} $(IMAGE)

## Quick provider/prereq health check (local complyctl install).
doctor:
	complyctl doctor --format text

## KSI coverage rollup over `complypack coverage`. KSI=<id> for a drill-down.
## Also writes output/coverage.json.
coverage:
	$(PYTHON) scripts/coverage.py $(if $(KSI),--ksi $(KSI))

## Push this run's evidence/output/ and .complytime/scan/ (the L5 EvaluationLog)
## to the shared evidence locker. Requires RSC_S3_BUCKET; see scripts/push-evidence.sh.
push-evidence:
	./scripts/push-evidence.sh

## Generate the FedRAMP Security Decision Record from coverage + the latest scan.
## Writes output/sdr/sdr.json (gitignored: it describes real findings).
sdr: coverage
	$(PYTHON) scripts/generate_sdr.py

## Build output/trace.json: ARs joined to the requirements they evidence, their
## implementation links, scope and latest result. Fails if a link does not resolve.
trace: coverage
	$(PYTHON) scripts/build_trace.py

## Findings, gaps and limits in one deterministic report (no AI, no network): output/findings.json
## and output/findings.md. Evaluates the policies over the evidence of the last `make run-local`.
findings: coverage
	$(PYTHON) scripts/build_findings.py

## Render the SDR, coverage, AR trail and findings as one offline HTML page: output/sdr/index.html.
## The findings need evidence from a run; without it the page is built without that tab.
sdr-view: sdr trace
	@$(PYTHON) scripts/build_findings.py || echo "NOTE: no Findings tab (run make run-local, then make findings)"
	$(PYTHON) scripts/render_sdr_html.py

## Create the history store's version marker (idempotent). RSC_S3_BUCKET set => the evidence
## locker (S3, RSC_S3_PREFIX, RSC_S3_ENDPOINT_URL); otherwise the local folder RSC_HISTORY_DIR
## or .history/ (gitignored). The history holds real findings: it never lives in this repo.
history-init:
	$(PYTHON) scripts/history.py init

## Append this run's record (a result per KSI per method, about one UTC day) to the history.
## Build it right after `make run-local`, `make findings` and `make trace` (`make daily` does).
## DATE=YYYY-MM-DD names the covered day, default yesterday: yesterday is a normal run, an earlier day a
## backfill (its state methods are not_collected). Today, the future and days over 90 days ago are refused.
## Refuses to run when the outputs are missing or older than the evidence, the evidence is over a day old,
## or the evidence of an event method was collected for another day.
record:
	$(PYTHON) scripts/build_record.py $(if $(DATE),--date $(DATE))

## Summaries of the stored series (30 days, the available year, missing days, gap alarms):
## output/history/summary.json and summary.md, and output/sdr/ksi-metrics.json (daily series).
history-summary:
	$(PYTHON) scripts/history_summary.py

## Everything one daily run does; this is what a scheduler would run (none exists yet). Needs
## `make history-init` once. First it backfills every day of the last RSC_BACKFILL_DAYS (default 5, at
## least 3) before yesterday that has no record (event collectors only, oldest first, into
## output/backfill/<day>/), then runs yesterday in full. DATE=<day> runs only that day (yesterday: the
## normal run; earlier: a backfill). A failed backfill is reported and does not stop the normal run;
## the exit code is non-zero if anything failed. Run it at or after 02:00 UTC (RSC_SETTLE_MINUTES).
daily:
	$(PYTHON) scripts/daily.py $(if $(DATE),--date $(DATE))
