# Unit tests for RSC.CMT.CTRL01.AR01. Run with `conftest verify` (or `make test`).
# Not shipped in the complypack: scripts/publish-complypack.sh skips *_test.rego.

package rosa_seaplane.change_management.github_default_branch_protection

import rego.v1

compliant := {
	"assessment_requirement": "RSC.CMT.CTRL01.AR01",
	"repository": "openshift-online/example",
	"branch": "main",
	"approval_gate": {"mechanism": "github-required-reviews", "requires_approval": true, "enforced_on_github": true},
	"protection": {
		"required_status_checks": {"strict": true, "contexts": ["ci"]},
		"enforce_admins": {"enabled": true},
		"allow_force_pushes": {"enabled": false},
	},
}

test_compliant_passes if {
	count(deny) == 0 with input as compliant
}

test_no_approval_gate_denied if {
	i := object.union(compliant, {"approval_gate": {"mechanism": "none", "requires_approval": false, "enforced_on_github": false}})
	violations := deny with input as i
	some msg in violations
	contains(msg, "no approval is required")
	contains(msg, "mechanism=none")
}

test_tide_gate_enforced_on_github_passes if {
	i := object.union(compliant, {"approval_gate": {"mechanism": "prow-tide", "requires_approval": true, "enforced_on_github": true}})
	count(deny) == 0 with input as i
}

test_tide_gate_not_enforced_on_github_denied if {
	i := object.union(compliant, {"approval_gate": {"mechanism": "prow-tide", "requires_approval": true, "enforced_on_github": false}})
	violations := deny with input as i
	count(violations) == 1
	some msg in violations
	contains(msg, "not enforced on GitHub")
	contains(msg, "prow-tide")
}

test_tide_query_without_approval_requirement_denied_and_named if {
	i := object.union(compliant, {"approval_gate": {
		"mechanism": "prow-tide", "requires_approval": false, "enforced_on_github": true,
		"queries_without_approval": ["dep-bot"],
	}})
	violations := deny with input as i
	some msg in violations
	contains(msg, "no approval is required")
	contains(msg, "dep-bot")
}

test_unenforced_gate_is_not_reported_when_there_is_no_gate if {
	i := object.union(compliant, {"approval_gate": {"mechanism": "none", "requires_approval": false, "enforced_on_github": false}})
	violations := deny with input as i
	count({m | some m in violations; contains(m, "not enforced")}) == 0
}

test_null_status_checks_denied if {
	violations := deny with input as object.union(compliant, {"protection": {"required_status_checks": null}})
	some msg in violations
	contains(msg, "required_status_checks")
}

test_empty_status_contexts_denied if {
	violations := deny with input as object.union(compliant, {"protection": {"required_status_checks": {"strict": true, "contexts": []}}})
	some msg in violations
	contains(msg, "required_status_checks")
}

test_force_push_allowed_denied if {
	violations := deny with input as object.union(compliant, {"protection": {"allow_force_pushes": {"enabled": true}}})
	some msg in violations
	contains(msg, "allow_force_pushes")
}

test_admin_bypass_denied if {
	violations := deny with input as object.union(compliant, {"protection": {"enforce_admins": {"enabled": false}}})
	some msg in violations
	contains(msg, "enforce_admins")
}

test_deny_message_names_repo if {
	violations := deny with input as object.union(compliant, {"protection": {"enforce_admins": {"enabled": false}}})
	some msg in violations
	contains(msg, "openshift-online/example")
}

test_unprotected_branch_denied if {
	violations := deny with input as {
		"assessment_requirement": "RSC.CMT.CTRL01.AR01",
		"repository": "openshift-online/example",
		"branch": "main",
		"protected": false,
		"approval_gate": {"mechanism": "none", "requires_approval": false, "enforced_on_github": false},
		"protection": {},
	}
	some msg in violations
	contains(msg, "no branch protection")
	count(violations) == 5
}

test_ignores_other_ars_evidence if {
	count(deny) == 0 with input as {
		"assessment_requirement": "RSC.CMT.CTRL01.AR02",
		"repository": "openshift-online/example",
		"base_ref": "main",
		"pull_requests": [],
	}
}

test_ignores_evidence_with_no_ar if {
	count(deny) == 0 with input as {"protection": {}}
}
