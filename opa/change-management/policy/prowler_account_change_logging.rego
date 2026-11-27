# RSC.CMT.CTRL02.AR01: in every in-scope account, an audit log records the
# modifications made to the cloud environment in each region checked, and an alert
# exists for the logging itself being stopped or altered. Input: the JSON from
# evidence/RSC.CMT.CTRL02.AR01.sh. Package name must match the "id" in
# complytime-mapping.json.
#
# Named for Prowler because it reads Prowler's check IDs and statuses; the choice of
# checks, and why each is in or out, is recorded in config/prowler/checks.yaml
# (tests/python/test_prowler_checks.py keeps this list and that file in step).
# Prowler's PASS/FAIL is the verdict for the facts each check measures; this policy
# adds only what Prowler cannot say about itself: that every check actually ran.
#
# A check that left no result must never read as a pass. Two of the checks emit
# nothing at all when CloudTrail cannot be listed, and the alarm check can report
# MANUAL when it could not list what it needed, so absence and any status other than
# PASS or FAIL are denied.
#
# The opa provider evaluates every mapped package against every file in the target's
# input_path, so each rule is guarded on the evidence's own assessment_requirement.
# Missing evidence therefore produces no denials; containers/complyctl/entrypoint.py
# fails the run when an AR has no evidence.
# platform: prowler-findings
# schema: schemas/prowler-findings.cue
package rosa_seaplane.change_management.prowler_account_change_logging

import rego.v1

applies if input.assessment_requirement == "RSC.CMT.CTRL02.AR01"

# Every denial carries a stable rule id as a trailing "[rule: <id>]", so reports can
# group and explain findings. The message stays a plain string (complyctl records it
# as is); config/findings/rules.yaml holds the title and fix hint for each id.
with_rule(id, text) := sprintf("%s [rule: %s]", [text, id])

required_checks := {
	"cloudtrail_multi_region_enabled",
	"cloudtrail_multi_region_enabled_logging_management_events",
	"cloudwatch_log_metric_filter_and_alarm_for_cloudtrail_configuration_changes_enabled",
}

# These two report once per region audited, so each region checked needs its own result.
per_region_checks := {
	"cloudtrail_multi_region_enabled",
	"cloudtrail_multi_region_enabled_logging_management_events",
}

results(check) := [f | some f in input.findings; f.check_id == check]

deny contains msg if {
	applies
	not input.collection.complete == true
	msg := with_rule("change-logging.collection-incomplete", sprintf("%s: the Prowler collection was incomplete, so nothing can be concluded", [input.target]))
}

# A required check with no result at all.
deny contains msg if {
	applies
	some check in required_checks
	count(results(check)) == 0
	msg := with_rule("change-logging.check-no-result", sprintf("%s: %s left no result, so it cannot be treated as passed", [input.target, check]))
}

# A per-region check missing a result for a region that was checked.
deny contains msg if {
	applies
	some check in per_region_checks
	count(results(check)) > 0
	some region in input.collection.regions
	count([f | some f in results(check); f.region == region]) == 0
	msg := with_rule("change-logging.check-no-region-result", sprintf("%s: %s left no result for region %s, so it cannot be treated as passed there", [input.target, check, region]))
}

deny contains msg if {
	applies
	some f in input.findings
	f.check_id in required_checks
	f.status == "FAIL"
	msg := with_rule("change-logging.check-failed", sprintf("%s: %s failed in %s for %s: %s", [input.target, f.check_id, f.region, f.resource_name, f.detail]))
}

deny contains msg if {
	applies
	some f in input.findings
	f.check_id in required_checks
	not f.status in {"PASS", "FAIL"}
	msg := with_rule("change-logging.check-not-assessed", sprintf("%s: %s could not be assessed in %s (status %s): %s", [input.target, f.check_id, f.region, f.status, f.detail]))
}
