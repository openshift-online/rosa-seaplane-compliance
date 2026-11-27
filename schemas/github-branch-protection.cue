// Shape of the evidence RSC.CMT.CTRL01.AR01 is evaluated against: a GitHub
// repository's branch-protection config, as fetched by evidence/*.sh.
// Matches tests/fixtures/RSC.CMT.CTRL01.AR01/{pass,fail}.json.
//
// required_approving_review_count uses `number` rather than `int`: complypack's
// JSON test-data loader decodes all numbers as float64, so CUE's strict `int`
// kind rejects them even for whole-valued integers.
assessment_requirement: string
generated_at:           string
repository:             string
branch:                 string
// How approval before merge is required, normalized by the collector from GitHub
// required reviews or the merge bot's (Prow Tide) configuration.
approval_gate: {
	mechanism:          "github-required-reviews" | "prow-tide" | "none"
	requires_approval:  bool
	// GitHub itself stops a merge that skips the gate; otherwise it can be bypassed.
	enforced_on_github: bool
	queries_without_approval?: [...string]
}
// false when GitHub reports the branch as not protected at all; then
// `protection` is empty.
protected: bool
protection: {
	// GitHub omits keys that are not configured, and all of them when the branch
	// is unprotected.
	required_pull_request_reviews?: {
		required_approving_review_count: number
		dismiss_stale_reviews?:          bool
		require_code_owner_reviews?:     bool
	}
	required_status_checks?: null | {
		strict:    bool
		contexts: [...string]
	}
	enforce_admins?: {
		enabled: bool
	}
	allow_force_pushes?: {
		enabled: bool
	}
	allow_deletions?: {
		enabled: bool
	}
	required_linear_history?: {
		enabled: bool
	}
}
