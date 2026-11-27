# Unit tests for RSC.CMT.CTRL03.AR01. Run with `conftest verify` (or `make test`).
# Not shipped in the complypack: scripts/publish-complypack.sh skips *_test.rego.

package rosa_seaplane.change_management.deployment_applied

import rego.v1

# Time is relative to the collection's own timestamp: NOW is 12:00; the lag is 120 minutes.
head_sha := "1111111111111111111111111111111111111111"

old_sha := "2222222222222222222222222222222222222222"

execution(commit, status, started) := {
	"commit": commit,
	"status": status,
	"trigger": "webhook",
	"started": started,
	"finished": started,
	"applied": applied_for(status),
	"applied_sha": applied_sha_for(status, commit),
}

applied_for("succeeded") := true

applied_for(s) := null if s != "succeeded"

applied_sha_for("succeeded", commit) := commit

applied_sha_for(s, _) := null if s != "succeeded"

healthy := {
	"assessment_requirement": "RSC.CMT.CTRL03.AR01",
	"target": "example-pipeline",
	"branch": "main",
	"covers_date": "2026-11-24",
	"window": {"start": "2026-11-24T00:00:00Z", "end": "2026-11-25T00:00:00Z"},
	"collection": {
		"complete": true,
		"allowed_lag_minutes": 120,
		"generated_at": "2026-11-24T12:00:00Z",
		"problems": [],
	},
	"head": {
		"sha": head_sha,
		"committed_at": "2026-11-24T09:00:00Z",
		"deployed": true,
		"deployed_by": "applied-itself",
		"deployed_by_execution_status": "succeeded",
	},
	"latest_execution": execution(head_sha, "succeeded", "2026-11-24T09:01:00Z"),
	"executions": [execution(head_sha, "succeeded", "2026-11-24T09:01:00Z"), execution(old_sha, "succeeded", "2026-11-23T09:01:00Z")],
	"merged_commits": [
		{"sha": old_sha, "merged_at": "2026-11-23T09:00:00Z", "deployed": true, "deployed_by": "applied-itself", "deployed_by_execution_status": "succeeded"},
		{"sha": head_sha, "merged_at": "2026-11-24T09:00:00Z", "deployed": true, "deployed_by": "applied-itself", "deployed_by_execution_status": "succeeded"},
	],
}

with_changes(changes) := object.union(healthy, {"merged_commits": changes})

test_a_complete_healthy_history_passes if {
	count(deny) == 0 with input as healthy
}

test_zero_merges_with_a_healthy_head_passes if {
	count(deny) == 0 with input as with_changes([])
}

test_incomplete_collection_is_denied_on_its_own_and_nothing_else_is_concluded if {
	i := object.union(healthy, {
		"collection": {"complete": false, "allowed_lag_minutes": 120, "generated_at": "2026-11-24T12:00:00Z", "problems": ["the execution history is longer than 30 pages"]},
		"head": {"sha": head_sha, "committed_at": "2026-11-24T09:00:00Z", "deployed": false, "deployed_by": "none", "deployed_by_execution_status": "none"},
	})
	violations := deny with input as i
	count(violations) == 1
	some msg in violations
	contains(msg, "could not be fully read")
	contains(msg, "30 pages")
	contains(msg, "[rule: deployment.collection-incomplete]")
}

test_missing_collection_block_still_denies if {
	violations := deny with input as {"assessment_requirement": "RSC.CMT.CTRL03.AR01"}
	count(violations) == 1
	some msg in violations
	contains(msg, "[rule: deployment.collection-incomplete]")
	contains(msg, "no reason recorded")
}

test_a_merged_change_never_deployed_and_older_than_the_lag_is_denied if {
	change := {"sha": old_sha, "merged_at": "2026-11-23T09:00:00Z", "deployed": false, "deployed_by": "none", "deployed_by_execution_status": "failed"}
	violations := deny with input as with_changes([change])
	some msg in violations
	contains(msg, "[rule: deployment.change-not-deployed]")
	contains(msg, "2222222")
	contains(msg, "latest attempt: failed")
}

test_a_change_still_inside_the_lag_is_not_denied_yet if {
	change := {"sha": old_sha, "merged_at": "2026-11-24T11:00:00Z", "deployed": false, "deployed_by": "none", "deployed_by_execution_status": "in-progress"}
	count(deny) == 0 with input as with_changes([change])
}

test_the_lag_boundary_is_exclusive if {
	at := {"sha": old_sha, "merged_at": "2026-11-24T10:00:00Z", "deployed": false, "deployed_by": "none", "deployed_by_execution_status": "none"}
	just_over := {"sha": old_sha, "merged_at": "2026-11-24T09:59:59Z", "deployed": false, "deployed_by": "none", "deployed_by_execution_status": "none"}
	count(deny) == 0 with input as with_changes([at])
	count(deny) == 1 with input as with_changes([just_over])
}

test_a_change_deployed_by_a_later_run_that_contains_it_passes if {
	change := {"sha": old_sha, "merged_at": "2026-11-23T09:00:00Z", "deployed": true, "deployed_by": "contained-in-later", "deployed_by_execution_status": "succeeded"}
	count(deny) == 0 with input as with_changes([change])
}

test_the_head_is_reported_once_by_its_own_rule if {
	i := object.union(with_changes([{"sha": head_sha, "merged_at": "2026-11-24T09:00:00Z", "deployed": false, "deployed_by": "none", "deployed_by_execution_status": "failed"}]), {
		"head": {"sha": head_sha, "committed_at": "2026-11-24T09:00:00Z", "deployed": false, "deployed_by": "none", "deployed_by_execution_status": "failed"},
		"latest_execution": execution(head_sha, "succeeded", "2026-11-24T09:01:00Z"),
	})
	violations := deny with input as i
	count(violations) == 1
	some msg in violations
	contains(msg, "[rule: deployment.head-not-deployed]")
	contains(msg, "1111111")
}

test_a_head_inside_the_lag_is_not_denied_yet if {
	i := object.union(healthy, {"head": {"sha": head_sha, "committed_at": "2026-11-24T11:30:00Z", "deployed": false, "deployed_by": "none", "deployed_by_execution_status": "in-progress"}})
	count(deny) == 0 with input as i
}

test_a_failed_latest_run_never_recovered_is_denied if {
	failed := object.union(execution(head_sha, "failed", "2026-11-24T09:30:00Z"), {"recovered": false})
	i := object.union(healthy, {"latest_execution": failed, "executions": [failed]})
	violations := deny with input as i
	some msg in violations
	contains(msg, "[rule: deployment.latest-execution-failed]")
	contains(msg, "failed")
}

test_a_failed_run_that_was_recovered_is_not_a_violation if {
	failed := object.union(execution(head_sha, "failed", "2026-11-24T09:30:00Z"), {"recovered": true})
	i := object.union(healthy, {"latest_execution": failed, "executions": [failed, execution(head_sha, "succeeded", "2026-11-24T09:01:00Z")]})
	count(deny) == 0 with input as i
}

test_a_recent_failure_inside_the_lag_is_not_denied_yet if {
	failed := object.union(execution(head_sha, "failed", "2026-11-24T11:30:00Z"), {"recovered": false})
	i := object.union(healthy, {"latest_execution": failed, "executions": [failed]})
	count(deny) == 0 with input as i
}

test_a_stopped_run_not_recovered_is_denied if {
	stopped := object.union(execution(head_sha, "stopped", "2026-11-24T09:30:00Z"), {"recovered": null})
	i := object.union(healthy, {"latest_execution": stopped, "executions": [stopped]})
	violations := deny with input as i
	some msg in violations
	contains(msg, "[rule: deployment.latest-execution-failed]")
}

test_a_run_stuck_in_progress_past_the_lag_is_denied if {
	stuck := execution(head_sha, "in-progress", "2026-11-24T09:30:00Z")
	i := object.union(healthy, {"latest_execution": stuck, "executions": [stuck]})
	violations := deny with input as i
	some msg in violations
	contains(msg, "[rule: deployment.latest-execution-stuck]")
	contains(msg, "still in-progress")
}

test_a_superseded_latest_run_is_not_a_failure if {
	superseded := execution(head_sha, "superseded", "2026-11-24T09:30:00Z")
	i := object.union(healthy, {"latest_execution": superseded, "executions": [superseded, execution(head_sha, "succeeded", "2026-11-24T09:01:00Z")]})
	count(deny) == 0 with input as i
}

test_no_executions_in_the_window_has_no_latest_run_to_judge if {
	i := object.union(healthy, {"latest_execution": null, "executions": []})
	count(deny) == 0 with input as i
}

test_a_succeeded_run_whose_record_says_not_applied_is_a_contradiction if {
	e := object.union(execution(head_sha, "succeeded", "2026-11-24T09:01:00Z"), {"applied": false})
	violations := deny with input as object.union(healthy, {"executions": [e]})
	some msg in violations
	contains(msg, "[rule: deployment.record-contradicts-status]")
}

test_a_succeeded_run_whose_record_names_another_commit_is_a_contradiction if {
	e := object.union(execution(head_sha, "succeeded", "2026-11-24T09:01:00Z"), {"applied_sha": old_sha})
	violations := deny with input as object.union(healthy, {"executions": [e]})
	some msg in violations
	contains(msg, "[rule: deployment.record-contradicts-status]")
}

test_a_failed_run_that_claims_to_be_applied_is_a_contradiction if {
	e := object.union(execution(head_sha, "failed", "2026-11-24T09:30:00Z"), {"applied": true, "recovered": true})
	violations := deny with input as object.union(healthy, {"executions": [e]})
	some msg in violations
	contains(msg, "[rule: deployment.record-contradicts-status]")
}

test_a_succeeded_run_with_no_record_at_all_is_not_a_contradiction if {
	e := object.union(execution(head_sha, "succeeded", "2026-11-24T09:01:00Z"), {"applied": null, "applied_sha": null})
	count(deny) == 0 with input as object.union(healthy, {"executions": [e]})
}

test_a_contradicting_run_after_the_day_is_left_to_that_day if {
	e := object.union(execution(head_sha, "succeeded", "2026-11-25T09:01:00Z"), {"applied": false})
	count(deny) == 0 with input as object.union(healthy, {"executions": [e]})
}

test_a_day_with_no_merges_passes if {
	count(deny) == 0 with input as object.union(healthy, {"merged_commits": []})
}

test_evidence_without_a_window_is_judged_whole if {
	e := object.union(execution(head_sha, "succeeded", "2026-11-25T09:01:00Z"), {"applied": false})
	violations := deny with input as object.union(object.remove(healthy, ["window"]), {"executions": [e]})
	some msg in violations
	contains(msg, "[rule: deployment.record-contradicts-status]")
}

test_ignores_other_ars_evidence if {
	count(deny) == 0 with input as {"assessment_requirement": "RSC.CMT.CTRL02.AR01", "findings": []}
}
