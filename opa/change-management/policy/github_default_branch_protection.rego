# RSC.CMT.CTRL01.AR01: the repository's merge gate for the default branch must
# require approval from someone other than the author and passing status checks,
# must be enforced so it cannot be bypassed (including by administrators), and
# must forbid force-pushes. Input: the JSON from evidence/RSC.CMT.CTRL01.AR01.sh.
# Package name must match the "id" in complytime-mapping.json.
#
# How approval is required varies (GitHub required reviews, or a merge bot such
# as Prow Tide). The collector normalizes it into input.approval_gate, so this
# policy reads one shape whatever the mechanism. Two separate facts are judged:
# the gate exists (requires_approval) and GitHub enforces it (enforced_on_github).
#
# The opa provider evaluates every mapped package against every file in the
# target's input_path, so each rule is guarded on the evidence's own
# assessment_requirement. A missing evidence file therefore produces no denials;
# containers/complyctl/entrypoint.py fails the run when an AR has no evidence.

# platform: github-branch-protection
# schema: schemas/github-branch-protection.cue
package rosa_seaplane.change_management.github_default_branch_protection

import rego.v1

applies if input.assessment_requirement == "RSC.CMT.CTRL01.AR01"

# Every denial carries a stable rule id as a trailing "[rule: <id>]", so reports can
# group and explain findings. The message stays a plain string (complyctl records it
# as is); config/findings/rules.yaml holds the title and fix hint for each id.
with_rule(id, text) := sprintf("%s [rule: %s]", [text, id])

deny contains msg if {
	applies
	input.protected == false
	msg := with_rule("merge-gate.no-branch-protection", sprintf("%s: %s has no branch protection configured", [input.repository, input.branch]))
}

deny contains msg if {
	applies
	not input.approval_gate.requires_approval == true
	msg := with_rule("merge-gate.no-approval-required", sprintf(
		"%s: no approval is required before merge to %s (mechanism=%s%s)",
		[input.repository, input.branch, input.approval_gate.mechanism, unapproved_queries_note],
	))
}

unapproved_queries_note := sprintf(", merge rules without an approval requirement for authors: %s", [concat(", ", input.approval_gate.queries_without_approval)]) if {
	count(input.approval_gate.queries_without_approval) > 0
} else := ""

deny contains msg if {
	applies
	input.approval_gate.requires_approval == true
	not input.approval_gate.enforced_on_github == true
	msg := with_rule("merge-gate.approval-not-enforced", sprintf(
		"%s: the approval requirement (%s) is not enforced on GitHub for %s, so a merge can skip it",
		[input.repository, input.approval_gate.mechanism, input.branch],
	))
}

deny contains msg if {
	applies
	not status_checks_required
	msg := with_rule("merge-gate.no-required-checks", sprintf(
		"%s: required_status_checks is missing, null, or has no contexts on %s",
		[input.repository, input.branch],
	))
}

status_checks_required if {
	count(input.protection.required_status_checks.contexts) > 0
}

deny contains msg if {
	applies
	not input.protection.allow_force_pushes.enabled == false
	msg := with_rule("merge-gate.force-pushes-allowed", sprintf(
		"%s: allow_force_pushes.enabled is true (or missing) on %s",
		[input.repository, input.branch],
	))
}

deny contains msg if {
	applies
	not input.protection.enforce_admins.enabled == true
	msg := with_rule("merge-gate.admin-bypass", sprintf(
		"%s: enforce_admins.enabled is false (or missing) on %s, so administrators can bypass the protection",
		[input.repository, input.branch],
	))
}
