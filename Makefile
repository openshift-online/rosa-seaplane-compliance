# TODO: update here and in complytime.yaml when this namespace changes.
REGISTRY            ?= quay.io/jmelis/rosa-seaplane-compliance
POLICY_VERSION       ?= v0.1.0
OPA_BUNDLE_VERSION   ?= v0.1.0
IMAGE                ?= $(REGISTRY)/complyctl-runner:latest

# Tracks gemaraproj/gemara's main (no stable release tag exists); only
# affects `make validate`, not complyctl itself.
GEMARA_SCHEMA_DIR    ?= .cache/gemara-schema

.PHONY: validate publish-policy publish-opa-bundle build-image run-local run-image doctor scan report rtm-ksi rtm-nist

## Validate Gemara YAML against the upstream CUE schema (needs `cue` CLI).
validate:
	@test -d $(GEMARA_SCHEMA_DIR)/.git || git clone --depth 1 \
	  https://github.com/gemaraproj/gemara.git $(GEMARA_SCHEMA_DIR)
	@root="$$(pwd)"; cd $(GEMARA_SCHEMA_DIR) && \
	  cue vet -d '#ControlCatalog' "$$root/gemara/change-management/controls.yaml" . && \
	  cue vet -d '#Policy' "$$root/gemara/change-management/policy.yaml" . && \
	  cue vet -d '#MappingDocument' "$$root/mappings/change-management-to-ksi.mapping.yaml" . && \
	  cue vet -d '#MappingDocument' "$$root/mappings/change-management-to-nist.mapping.yaml" .
	@echo "All Gemara YAML files are schema-valid."

## Publish the Gemara control catalog + policy as one OCI artifact.
publish-policy:
	./scripts/publish-policy-bundle.sh $(REGISTRY)/policies/change-management:$(POLICY_VERSION)

## Publish the Rego bundle (+ complytime-mapping.json) for the opa provider.
publish-opa-bundle:
	./scripts/publish-opa-bundle.sh $(REGISTRY)/opa-bundles/change-management:$(OPA_BUNDLE_VERSION)

## Build the ECS-ready container image (requires podman or docker).
build-image:
	podman build -t $(IMAGE) -f containers/complyctl/Containerfile .

## Run evidence -> scan -> report using locally installed complyctl + providers.
run-local:
	RSC_EVIDENCE_DIR="$$(pwd)/evidence/output" GITHUB_TOKEN=$${GITHUB_TOKEN:?set GITHUB_TOKEN} \
	  ./containers/complyctl/entrypoint.sh

## Run the same loop inside the built container image.
run-image:
	podman run --rm -e GITHUB_TOKEN=$${GITHUB_TOKEN:?set GITHUB_TOKEN} $(IMAGE)

## Quick provider/prereq health check (local complyctl install).
doctor:
	complyctl doctor --format text

## Re-run just the report against whatever EvaluationLog already exists.
report:
	python3 scripts/report.py \
	  --mapping mappings/change-management-to-ksi.mapping.yaml \
	  --mapping mappings/change-management-to-nist.mapping.yaml

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
