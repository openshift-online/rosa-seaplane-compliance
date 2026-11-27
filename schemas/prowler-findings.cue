// Shape of the evidence RSC.CMT.CTRL02.AR01 is evaluated against: the results of the
// Prowler checks listed in config/prowler/checks.yaml for one target (an AWS account
// today), as normalized by evidence/lib/prowler_findings.py. Matches
// tests/fixtures/RSC.CMT.CTRL02.AR01/. Only the fields the policy needs are kept:
// never the raw Prowler output, account IDs, ARNs or compliance blobs.
assessment_requirement: string
generated_at:           string
// Logical name of the target (e.g. "regional"), never an account ID.
target:      string
target_type: string
collection: {
	// False when Prowler did not finish, or its output could not be read. An
	// incomplete collection must never pass.
	complete: bool
	source:   string
	// The Prowler version that produced the findings (the collector refuses any
	// version other than the pinned one).
	prowler_version: string
	// The checks the collector asked Prowler to run, and the regions it asked for.
	required_checks: [...string]
	regions: [...string]
	generated_at: string
}
findings: [...{
	check_id: string
	// PASS and FAIL are verdicts. Anything else (Prowler's MANUAL, for example, when
	// it could not list what it needed) means "could not be assessed".
	status:        string
	region:        string
	resource_type: string
	resource_name: string
	// Prowler's own explanation, with any 12-digit number masked.
	detail: string
}]
