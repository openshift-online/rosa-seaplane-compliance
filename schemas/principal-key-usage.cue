// Shape of the evidence RSC.IAM.CTRL01.AR02 is evaluated against: whether any
// principal authenticated with a long-term credential on one UTC day, in one target
// (an AWS account today), as collected by evidence/RSC.IAM.CTRL01.AR02.sh and
// evidence/lib/iam_key_usage.py. Matches tests/fixtures/RSC.IAM.CTRL01.AR02/.
//
// Numbers use `number` rather than `int`: complypack's JSON test-data loader decodes
// all numbers as float64, so CUE's strict `int` rejects whole-valued integers.
//
// Never recorded: source IPs, user agents, request parameters, or a full key id (only
// its last four characters).
assessment_requirement: string
generated_at:           string
// Logical name of the target (e.g. "regional"), never an account ID.
target:      string
target_type: string
// The UTC day the evidence covers (YYYY-MM-DD) and its half-open window, ISO times.
covers_date: string
window: {
	start: string
	end:   string
}
collection: {
	// False when any lookup failed or was throttled out, so the window was not fully
	// searched. An incomplete collection must never pass.
	complete:     bool
	source:       string
	// The regions that were searched.
	regions:       [...string]
	keys_checked:  number
	lookup_errors: number
	// What this method cannot see, stated so that "no events" is not over-read.
	limitations:  [...string]
	generated_at: string
}
// One entry per long-term key that exists (and the root user, if it has any key).
keys: [...{
	principal_type: string
	principal:      string
	key_suffix:     null | string
	active:         bool
	// IAM's own record of the key's last use, for the cross-check.
	last_used:                null | string
	last_used_in_window:      bool
	last_used_region:         null | string
	last_used_region_checked: bool
	// False when IAM's last-used record could not be read or does not exist (root).
	cross_checked: bool
	// Events seen for this key (a lower bound: collection stops at the first page
	// with events), and whether more exist than were kept.
	events_found:     number
	events_truncated: bool
}]
// A bounded, trimmed sample of the events (newest first).
events: [...{
	time:            string
	event_name:      string
	event_source:    string
	principal_type:  string
	principal:       string
	credential_type: "long-term" | "temporary" | "none"
	region:          string
}]
