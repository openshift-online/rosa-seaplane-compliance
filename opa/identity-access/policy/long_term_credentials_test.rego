# Unit tests for RSC.IAM.CTRL01.AR01. Run with `conftest verify` (or `make test`).
# Not shipped in the complypack: scripts/publish-complypack.sh skips *_test.rego.

package rosa_seaplane.identity_access.long_term_credentials

import rego.v1

clean := {
	"assessment_requirement": "RSC.IAM.CTRL01.AR01",
	"target": "regional",
	"target_type": "aws-account",
	"collection": {"complete": true, "source": "credential-report", "generated_at": "2026-01-01T00:00:00Z"},
	"principals": [
		{"principal_type": "root", "name": "<root>", "credentials": [{"credential_type": "access-key", "long_term": true, "active": false}]},
		{"principal_type": "iam-user", "name": "svc", "credentials": [
			{"credential_type": "access-key", "long_term": true, "active": false},
			{"credential_type": "access-key", "long_term": true, "active": false},
		]},
	],
}

key(active) := {"credential_type": "access-key", "long_term": true, "active": active}

test_inactive_keys_pass if {
	count(deny) == 0 with input as clean
}

test_no_principals_is_valid_when_the_collection_is_complete if {
	count(deny) == 0 with input as object.union(clean, {"principals": []})
}

test_active_long_term_key_is_denied_and_named if {
	i := object.union(clean, {"principals": [{"principal_type": "iam-user", "name": "svc", "credentials": [key(true)]}]})
	violations := deny with input as i
	count(violations) == 1
	some msg in violations
	contains(msg, "regional")
	contains(msg, "svc")
	contains(msg, "active long-term credential")
}

test_root_with_an_active_key_is_denied if {
	i := object.union(clean, {"principals": [{"principal_type": "root", "name": "<root>", "credentials": [key(true)]}]})
	violations := deny with input as i
	some msg in violations
	contains(msg, "root")
}

test_two_active_keys_are_one_denial_that_says_two if {
	i := object.union(clean, {"principals": [{"principal_type": "iam-user", "name": "svc", "credentials": [key(true), key(true)]}]})
	violations := deny with input as i
	count(violations) == 1
	some msg in violations
	contains(msg, "holds 2 active")
}

test_each_principal_is_reported_separately if {
	i := object.union(clean, {"principals": [
		{"principal_type": "iam-user", "name": "a", "credentials": [key(true)]},
		{"principal_type": "iam-user", "name": "b", "credentials": [key(true)]},
	]})
	count(deny) == 2 with input as i
}

test_an_active_short_lived_credential_is_not_a_finding if {
	cred := {"credential_type": "session-token", "long_term": false, "active": true}
	i := object.union(clean, {"principals": [{"principal_type": "iam-user", "name": "svc", "credentials": [cred]}]})
	count(deny) == 0 with input as i
}

test_incomplete_collection_is_denied if {
	i := object.union(clean, {"collection": {"complete": false, "source": "credential-report", "generated_at": "x"}})
	violations := deny with input as i
	some msg in violations
	contains(msg, "incomplete")
}

test_incomplete_collection_with_no_principals_is_still_denied if {
	i := object.union(clean, {"collection": {"complete": false, "source": "x", "generated_at": "x"}, "principals": []})
	count(deny) == 1 with input as i
}

test_missing_collection_block_is_denied if {
	i := json.remove(clean, ["collection"])
	count(deny) >= 1 with input as i
}

test_ignores_other_ars_evidence if {
	count(deny) == 0 with input as {
		"assessment_requirement": "RSC.CMT.CTRL01.AR02",
		"repository": "openshift-online/example",
		"pull_requests": [],
	}
}

test_ignores_evidence_with_no_ar if {
	count(deny) == 0 with input as {"principals": [{"principal_type": "iam-user", "name": "x", "credentials": [key(true)]}]}
}
