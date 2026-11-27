// Shape of the evidence RSC.CMT.CTRL03.AR02 is evaluated against: the state of the
// applications deployed to one cluster, as the deployment tool reports it through the
// platform's metrics, as collected by evidence/RSC.CMT.CTRL03.AR02.sh and
// evidence/lib/argocd_health.py. Matches tests/fixtures/RSC.CMT.CTRL03.AR02/.
//
// States are normalized by the collector so the policy needs no knowledge of the
// deployment tool: sync_state is synced | out-of-sync | unknown, health_state is
// healthy | progressing | degraded | missing | suspended | unknown.
//
// Numbers use `number` rather than `int`: complypack's JSON test-data loader decodes all
// numbers as float64, so CUE's strict `int` rejects whole-valued integers.
//
// Never recorded: account IDs, the metrics API's ID or URL, ARNs, the deployment tool's
// cluster URL.
assessment_requirement: string
generated_at:           string
// Logical name of the cluster (the metrics' cluster label), never an ID.
target:      string
target_type: string
collection: {
	// False when the metrics cannot be trusted: a query failed, the newest sample is older
	// than the freshness limit, the cluster reported nothing, or the metrics have gaps in
	// the window. An incomplete collection must never pass.
	complete:                    bool
	source:                      string
	window_minutes:              number
	step_seconds:                number
	steps:                       number
	freshness_seconds:           number
	newest_sample_age_seconds:   null | number
	window_coverage:             number
	applications_gone_in_window: number
	problems:                    [...string]
	limitations:                 [...string]
	generated_at:                string
}
// One entry per application the cluster currently reports.
applications: [...{
	name:         string
	project:      string
	sync_state:   "synced" | "out-of-sync" | "unknown"
	health_state: "healthy" | "progressing" | "degraded" | "missing" | "suspended" | "unknown"
	// The share of the window's steps at which the application was seen.
	observed_fraction: number
	// Seen at too few steps to be judged (new, renamed, or the metrics have gaps).
	partially_observed: bool
	// Never healthy and in sync at any step of the window, and bad at one or more.
	unhealthy_for_window: bool
	// Progressing at every step of the window: it never settled.
	stuck_progressing_for_window: bool
}]
