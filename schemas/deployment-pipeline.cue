// Shape of the evidence RSC.CMT.CTRL03.AR01 is evaluated against: how the changes merged
// to a repository's default branch reached an environment through its automated
// deployment pipeline, for one pipeline, as collected by evidence/RSC.CMT.CTRL03.AR01.sh
// and evidence/lib/deployment_pipeline.py. Matches tests/fixtures/RSC.CMT.CTRL03.AR01/.
//
// Statuses are normalized by the collector so the policy needs no knowledge of the
// pipeline product: succeeded | failed | in-progress | stopped | superseded | unknown.
//
// Numbers use `number` rather than `int`: complypack's JSON test-data loader decodes all
// numbers as float64, so CUE's strict `int` rejects whole-valued integers.
//
// Never recorded: commit messages, author names or e-mail addresses, account IDs or ARNs.
assessment_requirement: string
generated_at:           string
// Logical name of the pipeline, never an ID.
target:      string
target_type: string
repository:  string
branch:      string
// The UTC day the evidence covers (YYYY-MM-DD) and its half-open window, ISO times.
covers_date: string
window: {
	start: string
	end:   string
}
collection: {
	// False when the window was not fully covered (history that does not reach back, a
	// page cap, an applied record or a comparison that failed). An incomplete
	// collection must never pass.
	complete:             bool
	source:               string
	allowed_lag_minutes:  number
	regions:              [...string]
	executions_read:      number
	changes_checked:      number
	comparisons:          number
	problems:             [...string]
	limitations:          [...string]
	generated_at:         string
}
// The head of the branch and whether it is deployed (applied by a succeeded run, or
// contained in a commit one applied).
head: {
	sha:                          string
	committed_at:                 string
	deployed:                     bool
	deployed_by:                  "applied-itself" | "contained-in-later" | "none" | "unknown"
	deployed_by_execution_status: string
}
// The newest execution, or null if there is none in the window.
latest_execution: null | #Execution
// Executions in the window, newest first (a bounded list).
executions: [...#Execution]
// One entry per pull request merged into the branch in the window, oldest first.
merged_commits: [...{
	sha:                          string
	merged_at:                    string
	deployed:                     bool
	deployed_by:                  "applied-itself" | "contained-in-later" | "none" | "unknown"
	// Status of the run that settled it (succeeded) or of the earliest run that tried
	// after the merge; "none" when no run started after it.
	deployed_by_execution_status: string
}]

#Execution: {
	// The commit the execution built; null if the source revision was not a commit.
	commit:  null | string
	status:  "succeeded" | "failed" | "in-progress" | "stopped" | "superseded" | "unknown"
	trigger: "webhook" | "manual" | "other"
	started: string
	finished: null | string
	// The Apply step's exported record; null when absent.
	applied:     null | bool
	applied_sha: null | string
	// For a failed or stopped run: whether a later success deployed its commit (or one
	// containing it); null when that could not be established.
	recovered?: null | bool
}
