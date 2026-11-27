# Unit tests for RSC.CMT.CTRL03.AR02. Run with `conftest verify` (or `make test`).
# Not shipped in the complypack: scripts/publish-complypack.sh skips *_test.rego.

package rosa_seaplane.change_management.deployment_workloads_healthy

import rego.v1

app(name) := {
	"name": name,
	"project": "default",
	"sync_state": "synced",
	"health_state": "healthy",
	"observed_fraction": 1,
	"partially_observed": false,
	"unhealthy_for_window": false,
	"stuck_progressing_for_window": false,
}

good := {
	"assessment_requirement": "RSC.CMT.CTRL03.AR02",
	"generated_at": "2026-11-25T10:00:00Z",
	"target": "example-cluster",
	"target_type": "deployment-cluster",
	"collection": {
		"complete": true,
		"source": "deployment-metrics",
		"window_minutes": 30,
		"problems": [],
	},
	"applications": [app("a"), app("b")],
}

with_apps(apps) := object.union(good, {"applications": apps})

incomplete(problems) := object.union(good, {"collection": object.union(good.collection, {"complete": false, "problems": problems})})

test_healthy_cluster_passes if {
	count(deny) == 0 with input as good
}

test_unhealthy_for_the_whole_window_is_denied_and_named if {
	broken := object.union(app("broken"), {"unhealthy_for_window": true, "health_state": "degraded"})
	violations := deny with input as with_apps([app("a"), broken])
	count(violations) == 1
	some msg in violations
	contains(msg, "application broken was unhealthy for the whole 30-minute window")
	contains(msg, "health: degraded")
	contains(msg, "[rule: health.application-unhealthy]")
	contains(msg, "example-cluster")
}

test_out_of_sync_for_the_whole_window_is_denied if {
	drifted := object.union(app("drifted"), {"unhealthy_for_window": true, "sync_state": "out-of-sync"})
	violations := deny with input as with_apps([drifted])
	some msg in violations
	contains(msg, "sync: out-of-sync")
}

test_never_settling_is_denied_as_stuck if {
	stuck := object.union(app("slow"), {"stuck_progressing_for_window": true, "health_state": "progressing"})
	violations := deny with input as with_apps([stuck])
	count(violations) == 1
	some msg in violations
	contains(msg, "application slow kept progressing without ever settling")
	contains(msg, "[rule: health.application-stuck]")
}

# The collector already decided "whole window": a state that is not healthy right now but
# cleared or began inside the window carries no flag and is tolerated.
test_transient_states_are_tolerated if {
	rolling := object.union(app("rolling"), {"health_state": "progressing"})
	recovering := object.union(app("recovering"), {"health_state": "degraded", "sync_state": "out-of-sync"})
	count(deny) == 0 with input as with_apps([rolling, recovering])
}

test_a_partially_observed_application_is_not_judged if {
	new := object.union(app("new"), {"partially_observed": true, "observed_fraction": 0.2, "health_state": "degraded"})
	count(deny) == 0 with input as with_apps([new])
}

test_incomplete_collection_is_denied_on_its_own_and_nothing_else_is_concluded if {
	broken := object.union(app("broken"), {"unhealthy_for_window": true})
	violations := deny with input as object.union(incomplete(["the newest sample is 900 seconds old"]), {"applications": [broken]})
	count(violations) == 1
	some msg in violations
	contains(msg, "could not be read reliably")
	contains(msg, "the newest sample is 900 seconds old")
	contains(msg, "[rule: health.collection-incomplete]")
}

test_a_cluster_that_reports_no_applications_is_never_healthy if {
	violations := deny with input as with_apps([])
	count(violations) == 1
	some msg in violations
	contains(msg, "the cluster reported no applications")
	contains(msg, "[rule: health.collection-incomplete]")
}

test_incomplete_with_no_reason_still_denies if {
	violations := deny with input as incomplete([])
	some msg in violations
	contains(msg, "no reason recorded")
}

test_missing_collection_block_is_incomplete_not_a_pass if {
	violations := deny with input as {"assessment_requirement": "RSC.CMT.CTRL03.AR02", "target": "example-cluster", "applications": [app("a")]}
	count(violations) == 1
}

test_each_flagged_application_gets_its_own_finding if {
	one := object.union(app("one"), {"unhealthy_for_window": true})
	two := object.union(app("two"), {"unhealthy_for_window": true})
	count(deny) == 2 with input as with_apps([one, two])
}

test_ignores_other_ars_evidence if {
	count(deny) == 0 with input as {"assessment_requirement": "RSC.CMT.CTRL03.AR01", "target": "x", "applications": []}
}

test_ignores_evidence_with_no_ar if {
	count(deny) == 0 with input as {"applications": []}
}
