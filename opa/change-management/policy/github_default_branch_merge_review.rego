# RSC.CMT.CTRL01.AR02: every merge to the default branch must carry a
# non-author approval and pass required checks. Input: the flattened JSON
# from evidence/RSC.CMT.CTRL01.AR02.sh. Package name must match the "id"
# in complytime-mapping.json. Does NOT detect admin-bypass merges, see
# README "Known gaps".

package rosa_seaplane.change_management.github_default_branch_merge_review

deny[msg] {
	pr := input.pull_requests[_]
	pr.review_decision != "APPROVED"
	msg := sprintf(
		"PR #%d (%s) merged to %s without an approved review (review_decision=%s)",
		[pr.number, pr.author, input.base_ref, pr.review_decision],
	)
}

deny[msg] {
	pr := input.pull_requests[_]
	pr.author == pr.merged_by
	msg := sprintf(
		"PR #%d merged to %s by its own author (%s): no non-author approval is possible",
		[pr.number, input.base_ref, pr.author],
	)
}

deny[msg] {
	pr := input.pull_requests[_]
	pr.status_check_state != "SUCCESS"
	msg := sprintf(
		"PR #%d merged to %s with non-passing status checks (status_check_state=%s)",
		[pr.number, input.base_ref, pr.status_check_state],
	)
}

# Empty pull_requests would otherwise vacuously "pass" every rule above.
deny[msg] {
	count(input.pull_requests) == 0
	msg := sprintf(
		"no merged pull requests found against %s in the evaluation window, cannot demonstrate the control; verify evidence/RSC.CMT.CTRL01.AR02.sh ran successfully and GITHUB_TOKEN has read access",
		[input.base_ref],
	)
}
