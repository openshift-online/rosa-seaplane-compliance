// Shape of the evidence RSC.CMT.CTRL01.AR02 is evaluated against: recent
// merges to a GitHub repository's default branch, as fetched by
// evidence/*.sh. Matches tests/fixtures/RSC.CMT.CTRL01.AR02/{pass,fail}.json.
//
// Numbers use `number` rather than `int`: complypack's JSON test-data loader
// decodes all numbers as float64, so CUE's strict `int` kind rejects them even
// for whole-valued integers (e.g. 30 becomes a CUE float literal, not an int literal).
//
// The evidence covers ONE UTC day: the pull requests merged in the half-open
// window [start, end). An empty list for a complete collection is a pass.
assessment_requirement: string
generated_at:           string
repository:             string
base_ref:               string
// The UTC day the evidence covers (YYYY-MM-DD) and its half-open window, ISO times.
covers_date: string
window: {
	start: string
	end:   string
}
// False when the branch has no protection at all; then no check is required.
branch_protected: bool
// The status check contexts the branch protection requires (current configuration).
required_contexts: [...string]
// False when the repository's check runs cannot be read with the collector's token
// (a private repository and a fine-grained token): only commit statuses are judged.
check_runs_readable: bool
pull_requests: [...{
	number:             number
	merged_at:          string
	author:             string
	merged_by:          string
	// True when the author is a bot account. A bot that labels its own PR has no
	// human approver; the policy decides what that means.
	author_is_bot:      bool
	// Facts for the documented automation exemption (config/automation.yaml). The
	// collector reports them; the policy decides.
	automated_change: {
		author_allowlisted:         bool
		gate_defined:               bool
		gate_labels_present:        bool
		merged_by_merge_automation: bool
		all_commits_by_author:      bool
	}
	// Normalized by the collector from GitHub reviews and Prow /lgtm history:
	// accounts other than the (non-bot) author that approved the change.
	approved_by:        [...string]
	approval_sources:   [..."github-review" | "prow"]
	// True when the comment/review history had more than one page, so an
	// approval could be missing from the evidence.
	history_truncated:  bool
	// What each REQUIRED context did on the PR's last commit. Only `success` passes.
	// neutral = a check run that concluded neutral or skipped; missing = the context
	// never reported; unknown = check runs are unreadable and the context is not among
	// the readable statuses. The overall rollup is not judged.
	required_checks: [...{
		context: string
		result:  "success" | "failure" | "pending" | "neutral" | "missing" | "unknown"
	}]
	// False when the PR's status contexts could not all be read (more than the
	// collector's paging bound), so a required check may be missing from the evidence.
	checks_complete: bool
	// The overall rollup of the last commit. For debugging only: it includes
	// contexts that are not required and is never judged.
	status_check_state: string
}]
