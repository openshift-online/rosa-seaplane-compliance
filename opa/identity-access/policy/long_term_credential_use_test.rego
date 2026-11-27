# Unit tests for RSC.IAM.CTRL01.AR02. Run with `conftest verify` (or `make test`).
# Not shipped in the complypack: scripts/publish-complypack.sh skips *_test.rego.

package rosa_seaplane.identity_access.long_term_credential_use

import rego.v1

key(overrides) := object.union({
	"principal_type": "iam-user", "principal": "svc", "key_suffix": "AB12", "active": true,
	"last_used": null, "last_used_in_window": false, "last_used_region": null,
	"last_used_region_checked": true, "cross_checked": true, "events_found": 0, "events_truncated": false,
}, overrides)

event(principal, credential) := {
	"time": "2026-01-01T00:00:00Z", "event_name": "AssumeRole", "event_source": "sts.amazonaws.com",
	"principal_type": "iam-user", "principal": principal, "credential_type": credential, "region": "us-east-1",
}

clean := {
	"assessment_requirement": "RSC.IAM.CTRL01.AR02",
	"target": "regional",
	"target_type": "aws-account",
	"covers_date": "2026-11-26",
	"window": {"start": "2026-11-26T00:00:00Z", "end": "2026-11-27T00:00:00Z"},
	"collection": {
		"complete": true, "source": "cloudtrail-event-history+iam-last-used",
		"regions": ["us-east-1"], "keys_checked": 1, "lookup_errors": 0, "limitations": [],
	},
	"keys": [key({})],
	"events": [],
}

test_no_events_from_a_complete_consistent_collection_passes if {
	count(deny) == 0 with input as clean
}

test_no_keys_at_all_is_valid_when_complete if {
	count(deny) == 0 with input as object.union(clean, {"keys": [], "events": []})
}

test_incomplete_collection_is_denied_and_never_a_pass if {
	i := object.union(clean, {"collection": object.union(clean.collection, {"complete": false, "lookup_errors": 2})})
	violations := deny with input as i
	some msg in violations
	contains(msg, "not fully searched")
	contains(msg, "2 lookup error")
}

test_missing_collection_block_is_denied if {
	violations := deny with input as {"assessment_requirement": "RSC.IAM.CTRL01.AR02", "target": "regional", "keys": [], "events": []}
	some msg in violations
	contains(msg, "not fully searched")
}

test_long_term_event_is_denied_and_names_the_principal if {
	i := object.union(clean, {
		"keys": [key({"events_found": 3})],
		"events": [event("svc", "long-term"), event("svc", "long-term")],
	})
	violations := deny with input as i
	count(violations) == 1
	some msg in violations
	contains(msg, "regional")
	contains(msg, "svc")
	contains(msg, "long-term credential")
	contains(msg, "3 event(s)")
	not contains(msg, "at least")
}

test_truncated_count_is_reported_as_a_lower_bound if {
	i := object.union(clean, {"keys": [key({"events_found": 50, "events_truncated": true})], "events": [event("svc", "long-term")]})
	violations := deny with input as i
	some msg in violations
	contains(msg, "at least 50 event(s)")
}

test_one_denial_per_principal if {
	i := object.union(clean, {
		"keys": [key({"events_found": 1}), key({"key_suffix": "ZZ99", "events_found": 2}), key({"principal": "other", "events_found": 1})],
		"events": [event("svc", "long-term"), event("svc", "long-term"), event("other", "long-term")],
	})
	count(deny) with input as i == 2
}

test_temporary_and_session_events_are_not_findings if {
	i := object.union(clean, {"events": [event("some-role", "temporary"), event("root", "none")]})
	count(deny) == 0 with input as i
}

test_key_used_in_window_with_no_events_is_suspect_not_a_pass if {
	i := object.union(clean, {"keys": [key({"last_used": "2026-01-01T00:00:00Z", "last_used_in_window": true, "last_used_region": "us-east-1"})]})
	violations := deny with input as i
	count(violations) == 1
	some msg in violations
	contains(msg, "audit log shows no events")
	contains(msg, "...AB12")
}

test_key_used_before_the_window_with_no_events_passes if {
	i := object.union(clean, {"keys": [key({"last_used": "2025-01-01T00:00:00Z", "last_used_in_window": false})]})
	count(deny) == 0 with input as i
}

test_key_never_used_passes if {
	count(deny) == 0 with input as clean
}

test_key_used_in_a_region_that_was_not_searched_is_denied if {
	i := object.union(clean, {"keys": [key({
		"last_used": "2026-01-01T00:00:00Z", "last_used_in_window": true, "last_used_region": "eu-west-1",
		"last_used_region_checked": false, "events_found": 2,
	})], "events": [event("svc", "long-term")]})
	violations := deny with input as i
	some msg in violations
	contains(msg, "eu-west-1")
	contains(msg, "not searched")
}

test_a_key_whose_last_used_could_not_be_read_is_not_cross_check_denied if {
	# The incomplete collection (errors) is what denies it; the key itself is not accused.
	i := object.union(clean, {"keys": [key({"cross_checked": false, "last_used_in_window": true})]})
	count(deny) == 0 with input as i
}

test_ignores_other_ars_evidence if {
	count(deny) == 0 with input as {"assessment_requirement": "RSC.IAM.CTRL01.AR01", "target": "regional", "principals": []}
}

test_ignores_evidence_with_no_ar if {
	count(deny) == 0 with input as {"keys": [], "events": []}
}
