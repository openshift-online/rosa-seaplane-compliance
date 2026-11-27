# Unit tests for RSC.CMT.CTRL02.AR01. Run with `conftest verify` (or `make test`).
# Not shipped in the complypack: scripts/publish-complypack.sh skips *_test.rego.

package rosa_seaplane.change_management.prowler_account_change_logging

import rego.v1

mr := "cloudtrail_multi_region_enabled"

me := "cloudtrail_multi_region_enabled_logging_management_events"

al := "cloudwatch_log_metric_filter_and_alarm_for_cloudtrail_configuration_changes_enabled"

finding(check, status) := {
	"check_id": check,
	"status": status,
	"region": "us-east-1",
	"resource_type": "AwsCloudTrailTrail",
	"resource_name": "example-trail",
	"detail": "example detail",
}

good_findings := [finding(mr, "PASS"), finding(me, "PASS"), finding(al, "PASS")]

evidence(findings) := {
	"assessment_requirement": "RSC.CMT.CTRL02.AR01",
	"target": "regional",
	"collection": {"complete": true, "regions": ["us-east-1"]},
	"findings": findings,
}

without(check) := [f | some f in good_findings; f.check_id != check]

test_all_required_checks_passing_is_a_pass if {
	count(deny) == 0 with input as evidence(good_findings)
}

test_a_fail_is_denied_naming_target_check_and_resource if {
	violations := deny with input as evidence([finding(mr, "FAIL"), finding(me, "PASS"), finding(al, "PASS")])
	some msg in violations
	contains(msg, "regional")
	contains(msg, mr)
	contains(msg, "example-trail")
	contains(msg, "failed")
}

test_each_required_check_with_no_result_is_denied if {
	every check in required_checks {
		violations := deny with input as evidence(without(check))
		some msg in violations
		contains(msg, check)
		contains(msg, "left no result")
	}
}

test_no_findings_at_all_is_denied_for_every_check if {
	violations := deny with input as evidence([])
	count(violations) == 3
}

test_manual_is_not_a_pass if {
	violations := deny with input as evidence([finding(mr, "PASS"), finding(me, "PASS"), finding(al, "MANUAL")])
	some msg in violations
	contains(msg, "could not be assessed")
	contains(msg, "MANUAL")
}

test_an_unknown_status_is_not_a_pass if {
	violations := deny with input as evidence([finding(mr, "PASS"), finding(me, "MUTED"), finding(al, "PASS")])
	some msg in violations
	contains(msg, "could not be assessed")
}

test_a_region_checked_without_a_result_is_denied if {
	i := object.union(evidence(good_findings), {"collection": {"complete": true, "regions": ["us-east-1", "us-west-2"]}})
	violations := deny with input as i
	some msg in violations
	contains(msg, "us-west-2")
	contains(msg, "left no result for region")
}

test_the_account_wide_alarm_check_needs_no_per_region_result if {
	i := object.union(evidence(good_findings), {"collection": {"complete": true, "regions": ["us-east-1", "us-west-2"]}})
	extra := [f | some f in good_findings; f.check_id in per_region_checks]
	both := array.concat(extra, [finding(al, "PASS")])
	west := [object.union(f, {"region": "us-west-2"}) | some f in extra]
	count(deny) == 0 with input as object.union(i, {"findings": array.concat(both, west)})
}

test_incomplete_collection_is_denied_even_with_passing_findings if {
	i := object.union(evidence(good_findings), {"collection": {"complete": false, "regions": ["us-east-1"]}})
	violations := deny with input as i
	some msg in violations
	contains(msg, "incomplete")
}

test_missing_collection_block_is_denied if {
	i := {"assessment_requirement": "RSC.CMT.CTRL02.AR01", "target": "regional", "findings": good_findings}
	violations := deny with input as i
	some msg in violations
	contains(msg, "incomplete")
}

test_a_failing_check_we_did_not_require_is_not_this_requirements_business if {
	other := finding("some_other_check", "FAIL")
	count(deny) == 0 with input as evidence(array.concat(good_findings, [other]))
}

test_ignores_other_ars_evidence if {
	count(deny) == 0 with input as {
		"assessment_requirement": "RSC.CMT.CTRL01.AR01",
		"target": "regional",
		"findings": [],
	}
}

test_ignores_evidence_with_no_ar if {
	count(deny) == 0 with input as {"findings": []}
}
