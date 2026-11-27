# RSC.CMT.CTRL01.AR02: every merge to the default branch must carry a
# non-author approval and pass required checks. Input: the flattened JSON
# from evidence/RSC.CMT.CTRL01.AR02.sh. Package name must match the "id"
# in complytime-mapping.json. Does NOT detect admin-bypass merges, see
# README "Known gaps".
#
# The opa provider evaluates every mapped package against every file in the
# target's input_path, so each rule is guarded on the evidence's own
# assessment_requirement (see github_default_branch_protection.rego).
#
# The evidence covers ONE UTC day. A day with no merge has an empty pull_requests list,
# and that is a pass: nothing happened that needed review. What stops a silent gap from
# passing is the collection itself (the repository must be reached, the pages read down
# to the day, nothing capped); a collection that fails writes no evidence, so the AR is
# reported as an error, never as a pass.

# platform: github-pr-merge-review
# schema: schemas/github-pr-merge-review.cue
package rosa_seaplane.change_management.github_default_branch_merge_review

import rego.v1

applies if input.assessment_requirement == "RSC.CMT.CTRL01.AR02"

# Every denial carries a stable rule id as a trailing "[rule: <id>]", so reports can
# group and explain findings. The message stays a plain string (complyctl records it
# as is); config/findings/rules.yaml holds the title and fix hint for each id.
with_rule(id, text) := sprintf("%s [rule: %s]", [text, id])

# Approval is normalized by the collector (GitHub reviews and Prow commands both
# end up in approved_by), so this rule does not care how the team approves. The
# author is filtered again here: an author's own approval never counts.
approvers(pr) := {a | some a in pr.approved_by; a != pr.author}

# A change by an allowlisted automation identity counts as approved by automation
# only when every fact holds (see config/automation.yaml): the repo's merge bot
# has a dedicated approval-requiring rule for that author, the approval labels are
# present, the merge bot merged it, and every commit is the author's own and
# signed. Failing required checks are still denied by their own rule below.
automation_facts := {"author_allowlisted", "gate_defined", "gate_labels_present", "merged_by_merge_automation", "all_commits_by_author"}

automation_exempt(pr) if {
	every fact in automation_facts {
		pr.automated_change[fact] == true
	}
}

unmet_automation_facts(pr) := sort([f | some f in automation_facts; not pr.automated_change[f] == true])

deny contains msg if {
	applies
	some pr in input.pull_requests
	count(approvers(pr)) == 0
	not automation_exempt(pr)
	msg := with_rule("merge-review.no-approval", sprintf(
		"%s: PR #%d (%s) merged to %s without a non-author approval%s",
		[input.repository, pr.number, pr.author, input.base_ref, truncation_note(pr)],
	))
}

truncation_note(pr) := " (comment history was truncated, so an approval may be missing from the evidence)" if {
	pr.history_truncated == true
} else := sprintf(" (automation exemption not met, missing: %s)", [concat(", ", unmet_automation_facts(pr))]) if {
	pr.automated_change.author_allowlisted == true
} else := " (the author is a bot, so any approval labels were applied by the bot itself)" if {
	pr.author_is_bot == true
} else := ""

deny contains msg if {
	applies
	some pr in input.pull_requests
	pr.author == pr.merged_by
	msg := with_rule("merge-review.self-merge", sprintf(
		"%s: PR #%d merged to %s by its own author (%s), bypassing the merge gate",
		[input.repository, pr.number, input.base_ref, pr.author],
	))
}

# Only the checks the branch protection REQUIRES are judged, on the PR's last
# commit. The collector normalizes each required context to success, failure,
# pending, neutral (a check run that concluded neutral or skipped), missing (it
# never reported) or unknown (the repository's check runs are not readable and the
# context is not among the readable statuses, so we cannot tell). Only `success`
# passes: GitHub itself lets neutral and skipped satisfy a required check, but then
# the check asserted nothing, so it is reported. `unknown` is never a violation and
# never a pass: it makes the PR incomplete evidence, below.
# A repository with no required checks configured yields no denial here: that is
# reported by the merge-gate requirement (RSC.CMT.CTRL01.AR01).
deny contains msg if {
	applies
	some pr in input.pull_requests
	some check in pr.required_checks
	check.result != "success"
	check.result != "unknown"
	msg := with_rule("merge-review.required-check-not-passing", sprintf(
		"%s: PR #%d merged to %s with required check %s not passing (%s)",
		[input.repository, pr.number, input.base_ref, check.context, check.result],
	))
}

# If the contexts of a PR's last commit could not all be read, a required check may
# be missing from the evidence, so the PR cannot be judged. An absent flag (evidence
# from an older collector) is treated the same way, never as a pass.
checks_unjudged(pr) if not pr.checks_complete == true

checks_unjudged(pr) if {
	some check in pr.required_checks
	check.result == "unknown"
}

deny contains msg if {
	applies
	some pr in input.pull_requests
	checks_unjudged(pr)
	msg := with_rule("merge-review.checks-incomplete", sprintf(
		"%s: PR #%d merged to %s: the status checks on its last commit could not all be read (more contexts than the collector reads, or check runs are not readable for this repository with the current token), so the required checks cannot be judged",
		[input.repository, pr.number, input.base_ref],
	))
}
