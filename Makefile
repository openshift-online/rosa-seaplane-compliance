# TODO: update here and in .complytime/complytime.yaml when this namespace changes.
REGISTRY            ?= quay.io/jmelis/rosa-seaplane-compliance
POLICY_VERSION       ?= v0.1.0
OPA_BUNDLE_VERSION   ?= v0.1.0
IMAGE                ?= $(REGISTRY)/complyctl-runner:latest

# Gemara CUE schema version to validate against; only affects `make validate`,
# not complyctl itself. Pulled from the CUE Central Registry.
GEMARA_SCHEMA_VERSION ?= v1.6.0

.PHONY: validate publish-policy publish-opa-bundle build-image run-local run-image doctor coverage coverage-ksi coverage-nist rtm-ksi rtm-nist

## Validate Gemara YAML against the upstream CUE schema (needs `cue` CLI).
validate:
	cue vet -c -d '#ControlCatalog' github.com/gemaraproj/gemara@$(GEMARA_SCHEMA_VERSION) gemara/change-management/controls.yaml
	cue vet -c -d '#Policy' github.com/gemaraproj/gemara@$(GEMARA_SCHEMA_VERSION) gemara/change-management/policy.yaml
	cue vet -c -d '#MappingDocument' github.com/gemaraproj/gemara@$(GEMARA_SCHEMA_VERSION) mappings/change-management-to-ksi.mapping.yaml
	cue vet -c -d '#MappingDocument' github.com/gemaraproj/gemara@$(GEMARA_SCHEMA_VERSION) mappings/change-management-to-nist.mapping.yaml
	@echo "All Gemara YAML files are schema-valid."

## Publish the Gemara control catalog + policy as one OCI artifact.
publish-policy:
	./scripts/publish-policy-bundle.sh $(REGISTRY)/policies/change-management:$(POLICY_VERSION)

## Publish all domains' Rego (+ merged complytime-mapping.json) as one project bundle.
publish-opa-bundle:
	./scripts/publish-opa-bundle.sh $(REGISTRY)/opa-bundles/rosa-seaplane:$(OPA_BUNDLE_VERSION)

## Build the ECS-ready container image (requires podman or docker).
build-image:
	podman build -t $(IMAGE) -f containers/complyctl/Containerfile .

## Run evidence -> scan using locally installed complyctl + providers.
run-local:
	RSC_EVIDENCE_DIR="$$(pwd)/evidence/output" GITHUB_TOKEN=$${GITHUB_TOKEN:?set GITHUB_TOKEN} \
	  python3 containers/complyctl/entrypoint.py

## Run the same loop inside the built container image.
run-image:
	podman run --rm -e GITHUB_TOKEN=$${GITHUB_TOKEN:?set GITHUB_TOKEN} $(IMAGE)

## Quick provider/prereq health check (local complyctl install).
doctor:
	complyctl doctor --format text

## Report KSI coverage: which required KSIs our ARs cover.
coverage-ksi:
	python3 scripts/coverage.py \
	  --baseline mappings/fedramp-class-c.ksi.baseline.yaml \
	  --mapping mappings/change-management-to-ksi.mapping.yaml

## Report 800-53 coverage: which required controls our ARs cover.
coverage-nist:
	python3 scripts/coverage.py \
	  --baseline mappings/fedramp-class-c.nist-800-53.baseline.yaml \
	  --mapping mappings/change-management-to-nist.mapping.yaml

## Both coverage views (KSI and 800-53).
coverage: coverage-ksi coverage-nist

## Generate the FedRAMP KSI Requirements Traceability Matrix (CSV, for the auditor).
rtm-ksi:
	python3 scripts/generate_rtm.py \
	  --mapping mappings/change-management-to-ksi.mapping.yaml \
	  --policy gemara/change-management/policy.yaml \
	  --out rtm/change-management-to-ksi.csv

## Generate the NIST 800-53 Requirements Traceability Matrix (CSV, supporting crosswalk).
rtm-nist:
	python3 scripts/generate_rtm.py \
	  --mapping mappings/change-management-to-nist.mapping.yaml \
	  --policy gemara/change-management/policy.yaml \
	  --out rtm/change-management-to-nist.csv
