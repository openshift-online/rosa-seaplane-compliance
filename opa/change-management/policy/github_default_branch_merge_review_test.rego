# Unit tests for RSC.CMT.CTRL01.AR02. Run with `conftest verify` (or `make test`).
# Not shipped in the complypack: scripts/publish-complypack.sh skips *_test.rego.

package rosa_seaplane.change_management.github_default_branch_merge_review

import rego.v1

compliant_pr := {
	"number": 201,
	"author": "alice",
	"merged_by": "bob",
	"author_is_bot": false,
	"automated_change": {
		"author_allowlisted": false, "gate_defined": false, "gate_labels_present": true,
		"merged_by_merge_automation": true, "all_commits_by_author": true,
	},
	"approved_by": ["bob"],
	"approval_sources": ["github-review"],
	"history_truncated": false,
	"required_checks": [{"context": "ci/build", "result": "success"}],
	"checks_complete": true,
	"status_check_state": "SUCCESS",
}

base := {
	"assessment_requirement": "RSC.CMT.CTRL01.AR02",
	"covers_date": "2026-09-06",
	"window": {"start": "2026-09-06T00:00:00Z", "end": "2026-09-07T00:00:00Z"},
	"repository": "openshift-online/example",
	"base_ref": "main",
}

test_github_approval_passes if {
	count(deny) == 0 with input as object.union(base, {"pull_requests": [compliant_pr]})
}

test_prow_approval_passes if {
	pr := object.union(compliant_pr, {"approved_by": ["dave"], "approval_sources": ["prow"], "merged_by": "openshift-merge-bot"})
	count(deny) == 0 with input as object.union(base, {"pull_requests": [pr]})
}

test_no_approval_is_denied if {
	pr := object.union(compliant_pr, {"approved_by": [], "approval_sources": []})
	violations := deny with input as object.union(base, {"pull_requests": [pr]})
	some msg in violations
	contains(msg, "without a non-author approval")
}

test_self_approval_is_denied if {
	pr := object.union(compliant_pr, {"approved_by": ["alice"], "approval_sources": ["prow"]})
	violations := deny with input as object.union(base, {"pull_requests": [pr]})
	some msg in violations
	contains(msg, "without a non-author approval")
}

test_self_approval_among_others_still_needs_a_non_author if {
	pr := object.union(compliant_pr, {"approved_by": ["alice", "bob"]})
	count(deny) == 0 with input as object.union(base, {"pull_requests": [pr]})
}

test_truncated_history_is_noted if {
	pr := object.union(compliant_pr, {"approved_by": [], "history_truncated": true})
	violations := deny with input as object.union(base, {"pull_requests": [pr]})
	some msg in violations
	contains(msg, "history was truncated")
}

test_bot_authored_without_approver_is_denied_and_says_so if {
	pr := object.union(compliant_pr, {"author": "dep-bot", "author_is_bot": true, "approved_by": [], "approval_sources": []})
	violations := deny with input as object.union(base, {"pull_requests": [pr]})
	some msg in violations
	contains(msg, "author is a bot")
}

test_self_merge_is_denied if {
	violations := deny with input as {
		"assessment_requirement": "RSC.CMT.CTRL01.AR02",
		"repository": "openshift-online/example",
		"base_ref": "main",
		"pull_requests": [object.union(compliant_pr, {"merged_by": "alice"})],
	}
	some msg in violations
	contains(msg, "by its own author")
}

test_required_check_not_passing_is_denied_naming_the_check_and_result if {
	every result in {"failure", "pending", "neutral", "missing"} {
		pr := object.union(compliant_pr, {"required_checks": [{"context": "ci/build", "result": result}]})
		violations := deny with input as object.union(base, {"pull_requests": [pr]})
		some msg in violations
		contains(msg, "required check ci/build not passing")
		contains(msg, result)
		contains(msg, "merge-review.required-check-not-passing")
	}
}

test_only_the_failing_required_check_is_named if {
	pr := object.union(compliant_pr, {"required_checks": [
		{"context": "ci/build", "result": "success"},
		{"context": "ci/lint", "result": "failure"},
	]})
	violations := deny with input as object.union(base, {"pull_requests": [pr]})
	count(violations) == 1
	some msg in violations
	contains(msg, "ci/lint")
}

test_the_overall_rollup_is_not_judged if {
	# A pending or failing OVERALL state with every required check passing is not a denial.
	pr := object.union(compliant_pr, {"status_check_state": "PENDING"})
	count(deny) == 0 with input as object.union(base, {"pull_requests": [pr]})
	pr2 := object.union(compliant_pr, {"status_check_state": "FAILURE"})
	count(deny) == 0 with input as object.union(base, {"pull_requests": [pr2]})
}

test_no_required_checks_means_no_status_check_denial if {
	pr := object.union(compliant_pr, {"required_checks": []})
	count(deny) == 0 with input as object.union(base, {"pull_requests": [pr]})
}

test_unknown_is_neither_a_violation_nor_a_pass if {
	# Check runs unreadable and the required context not among the statuses: we cannot tell.
	pr := object.union(compliant_pr, {"required_checks": [{"context": "ci/build", "result": "unknown"}]})
	violations := deny with input as object.union(base, {"pull_requests": [pr]})
	count({m | some m in violations; contains(m, "merge-review.required-check-not-passing")}) == 0
	some msg in violations
	contains(msg, "merge-review.checks-incomplete")
}

test_incomplete_checks_are_reported_never_passed if {
	pr := object.union(compliant_pr, {"checks_complete": false})
	violations := deny with input as object.union(base, {"pull_requests": [pr]})
	some msg in violations
	contains(msg, "could not all be read")
	contains(msg, "merge-review.checks-incomplete")
}

test_evidence_without_the_completeness_flag_is_not_a_pass if {
	pr := object.remove(compliant_pr, ["checks_complete"])
	violations := deny with input as object.union(base, {"pull_requests": [pr]})
	some msg in violations
	contains(msg, "could not all be read")
}

test_a_day_without_merges_passes if {
	count(deny) == 0 with input as {"assessment_requirement": "RSC.CMT.CTRL01.AR02", "repository": "openshift-online/example", "base_ref": "main", "covers_date": "2026-09-06", "window": {"start": "2026-09-06T00:00:00Z", "end": "2026-09-07T00:00:00Z"}, "pull_requests": []}
}

test_ignores_other_ars_evidence if {
	count(deny) == 0 with input as {
		"assessment_requirement": "RSC.CMT.CTRL01.AR01",
		"repository": "openshift-online/example",
		"branch": "main",
		"protection": {},
	}
}

test_deny_message_names_repo if {
	pr := object.union(compliant_pr, {"approved_by": [], "approval_sources": []})
	violations := deny with input as object.union(base, {"pull_requests": [pr]})
	some msg in violations
	contains(msg, "openshift-online/example")
}

# Automation exemption: a bot change with no human approver.
automated_pr := object.union(compliant_pr, {
	"author": "dep-bot", "author_is_bot": true, "approved_by": [], "approval_sources": [],
	"merged_by": "merge-bot",
	"automated_change": {
		"author_allowlisted": true, "gate_defined": true, "gate_labels_present": true,
		"merged_by_merge_automation": true, "all_commits_by_author": true,
	},
})

test_automation_exemption_passes_when_every_fact_holds if {
	count(deny) == 0 with input as object.union(base, {"pull_requests": [automated_pr]})
}

test_each_unmet_fact_denies_and_is_named if {
	# author_allowlisted is covered by its own test: without it the message is the generic one.
	every fact in automation_facts - {"author_allowlisted"} {
		pr := object.union(automated_pr, {"automated_change": object.union(automated_pr.automated_change, {fact: false})})
		violations := deny with input as object.union(base, {"pull_requests": [pr]})
		some msg in violations
		contains(msg, "automation exemption not met")
		contains(msg, fact)
	}
}

test_exemption_never_applies_to_a_non_allowlisted_bot if {
	pr := object.union(automated_pr, {"automated_change": object.union(automated_pr.automated_change, {"author_allowlisted": false})})
	violations := deny with input as object.union(base, {"pull_requests": [pr]})
	some msg in violations
	contains(msg, "without a non-author approval")
}

test_exemption_does_not_waive_a_failing_required_check if {
	pr := object.union(automated_pr, {"required_checks": [{"context": "ci/build", "result": "failure"}]})
	violations := deny with input as object.union(base, {"pull_requests": [pr]})
	some msg in violations
	contains(msg, "required check ci/build not passing")
}

test_exemption_does_not_waive_self_merge if {
	pr := object.union(automated_pr, {"merged_by": "dep-bot"})
	violations := deny with input as object.union(base, {"pull_requests": [pr]})
	some msg in violations
	contains(msg, "by its own author")
}

test_a_human_approver_still_passes_without_the_exemption if {
	pr := object.union(compliant_pr, {"approved_by": ["bob"]})
	count(deny) == 0 with input as object.union(base, {"pull_requests": [pr]})
}
