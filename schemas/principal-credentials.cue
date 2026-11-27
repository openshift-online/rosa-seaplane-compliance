// Shape of the evidence RSC.IAM.CTRL01.AR01 is evaluated against: the credentials
// each principal holds in one target (an AWS account today), as collected by
// evidence/RSC.IAM.CTRL01.AR01.sh. Matches tests/fixtures/RSC.IAM.CTRL01.AR01/.
//
// Only machine credentials are recorded (access keys, tokens). Passwords and MFA
// belong to people and are out of scope for this control.
assessment_requirement: string
generated_at:           string
// Logical name of the target (e.g. "regional"), never an account ID.
target:      string
target_type: string
collection: {
	// False when the inventory could not be read in full. An incomplete collection
	// must never pass. Zero principals with complete: true is valid.
	complete:     bool
	source:       string
	generated_at: string
}
principals: [...{
	principal_type: string
	name:           string
	credentials: [...{
		credential_type: string
		long_term:       bool
		active:          bool
	}]
}]
