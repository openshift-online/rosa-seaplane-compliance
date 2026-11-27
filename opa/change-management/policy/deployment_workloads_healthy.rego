# RSC.CMT.CTRL03.AR02: after a deployment, the applications that make up the environment are
# synchronized with their desired state and healthy; a state that is transient while a rollout
# settles is tolerated, but an application that stays unhealthy, or never finishes settling,
# for the whole lookback window is not. Input: the JSON from evidence/RSC.CMT.CTRL03.AR02.sh,
# one file per cluster. Package name must match the "id" in complytime-mapping.json.
#
# The collector reads the deployment tool's state from the platform's metrics and normalizes
# it, and decides per application what the whole window showed (evidence/lib/argocd_health.py
# has the exact rule: an application never healthy and in sync at any step is unhealthy for
# the window if it was bad at any step, and stuck if it only ever progressed; one that was ok
# at least once, or was seen at too few steps to be judged, is not flagged). This policy
# reads those facts, so it needs no knowledge of the deployment tool.
#
# What is a violation, and what is "could not tell":
#   - an incomplete collection (stale or missing metrics, a failed query, gaps in the window,
#     a cluster that reports no applications) is denied on its own, and nothing else is
#     concluded from it: unhealthy must never be mistaken for healthy because data is missing;
#   - an application unhealthy for the whole window, or progressing without ever settling for
#     the whole window, is a violation.
#
# The opa provider evaluates every mapped package against every file in the target's
# input_path, so each rule is guarded on the evidence's own assessment_requirement.
# Missing evidence therefore produces no denials; containers/complyctl/entrypoint.py
# fails the run when an AR has no evidence.
# platform: deployment-health
# schema: schemas/deployment-health.cue
package rosa_seaplane.change_management.deployment_workloads_healthy

import rego.v1

applies if input.assessment_requirement == "RSC.CMT.CTRL03.AR02"

# Every denial carries a stable rule id as a trailing "[rule: <id>]", so reports can
# group and explain findings. The message stays a plain string (complyctl records it
# as is); config/findings/rules.yaml holds the title and fix hint for each id.
with_rule(id, text) := sprintf("%s [rule: %s]", [text, id])

target := object.get(input, "target", "(unknown cluster)")

collection := object.get(input, "collection", {})

applications := object.get(input, "applications", [])

window_minutes := object.get(collection, "window_minutes", 0)

complete if collection.complete == true

# A cluster that reports no applications cannot be called healthy.
trustworthy if {
	complete
	count(applications) > 0
}

problem_text := concat("; ", collection.problems) if {
	count(object.get(collection, "problems", [])) > 0
} else := "the cluster reported no applications" if {
	complete
	count(applications) == 0
} else := "no reason recorded"

deny contains msg if {
	applies
	not trustworthy
	msg := with_rule("health.collection-incomplete", sprintf("%s: the state of the deployed applications could not be read reliably (%s), so nothing can be concluded", [target, problem_text]))
}

deny contains msg if {
	applies
	trustworthy
	some a in applications
	a.unhealthy_for_window == true
	msg := with_rule("health.application-unhealthy", sprintf("%s: application %s was unhealthy for the whole %d-minute window (sync: %s, health: %s)", [target, a.name, window_minutes, a.sync_state, a.health_state]))
}

deny contains msg if {
	applies
	trustworthy
	some a in applications
	a.stuck_progressing_for_window == true
	msg := with_rule("health.application-stuck", sprintf("%s: application %s kept progressing without ever settling for the whole %d-minute window", [target, a.name, window_minutes]))
}
