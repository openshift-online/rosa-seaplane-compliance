# RSC.IAM.CTRL01.AR01: no non-human principal in an in-scope target may hold an
# active long-term credential. Input: the JSON from
# evidence/RSC.IAM.CTRL01.AR01.sh. Package name must match the "id" in
# complytime-mapping.json.
#
# Source-neutral: it reads normalized credentials (credential_type, long_term,
# active), so a collector for another source (GitHub tokens, cluster service
# accounts) only has to produce the same shape. The collector cannot always tell
# people from services, so every principal holding an active long-term credential
# is reported; people are expected to sign in through federation, not static keys.
#
# The opa provider evaluates every mapped package against every file in the
# target's input_path, so each rule is guarded on the evidence's own
# assessment_requirement. Missing evidence therefore produces no denials;
# containers/complyctl/entrypoint.py fails the run when an AR has no evidence.
# platform: principal-credentials
# schema: schemas/principal-credentials.cue
package rosa_seaplane.identity_access.long_term_credentials

import rego.v1

applies if input.assessment_requirement == "RSC.IAM.CTRL01.AR01"

# Every denial carries a stable rule id as a trailing "[rule: <id>]", so reports can
# group and explain findings. The message stays a plain string (complyctl records it
# as is); config/findings/rules.yaml holds the title and fix hint for each id.
with_rule(id, text) := sprintf("%s [rule: %s]", [text, id])

# Zero principals is valid; an unread or partly read inventory is not.
deny contains msg if {
	applies
	not input.collection.complete == true
	msg := with_rule("credentials.inventory-incomplete", sprintf("%s: the credential inventory was incomplete, so nothing can be concluded", [input.target]))
}

# One denial per principal and credential type, with how many are active (identical
# messages would collapse in a set, hiding a second key).
deny contains msg if {
	applies
	some principal in input.principals
	some credential in principal.credentials
	credential.long_term == true
	credential.active == true
	n := count([c |
		some c in principal.credentials
		c.long_term == true
		c.active == true
		c.credential_type == credential.credential_type
	])
	msg := with_rule("credentials.long-term-active", sprintf(
		"%s: %s %s holds %d active long-term credential(s) (%s)",
		[input.target, principal.principal_type, principal.name, n, credential.credential_type],
	))
}
