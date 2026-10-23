# Unit tests for RSC.CMT.CTRL01.AR02. Run with `conftest verify` (or `make test`).
# Not shipped in the opa bundle: scripts/publish-opa-bundle.sh skips *_test.rego.

package rosa_seaplane.change_management.github_default_branch_merge_review

import rego.v1

compliant_pr := {
	"number": 201,
	"author": "alice",
	"merged_by": "bob",
	"review_decision": "APPROVED",
	"status_check_state": "SUCCESS",
}

test_compliant_merges_pass if {
	count(deny) == 0 with input as {"base_ref": "main", "pull_requests": [compliant_pr]}
}

test_unapproved_review_is_denied if {
	violations := deny with input as {
		"base_ref": "main",
		"pull_requests": [object.union(compliant_pr, {"review_decision": "REVIEW_REQUIRED"})],
	}
	some msg in violations
	contains(msg, "without an approved review")
}

test_self_merge_is_denied if {
	violations := deny with input as {
		"base_ref": "main",
		"pull_requests": [object.union(compliant_pr, {"merged_by": "alice"})],
	}
	some msg in violations
	contains(msg, "by its own author")
}

test_failing_checks_is_denied if {
	violations := deny with input as {
		"base_ref": "main",
		"pull_requests": [object.union(compliant_pr, {"status_check_state": "FAILURE"})],
	}
	some msg in violations
	contains(msg, "non-passing status checks")
}

test_empty_window_is_denied if {
	violations := deny with input as {"base_ref": "main", "pull_requests": []}
	some msg in violations
	contains(msg, "no merged pull requests found")
}
