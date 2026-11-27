# RSC.CMT.CTRL03.AR01: every change merged to the default branch on the day the evidence covers (one UTC day)
# is deployed to the environment by the automated deployment pipeline, the deployment
# succeeded, and the environment is running the head of the branch (within an allowed
# lag), as of the collection time. Input: the JSON from evidence/RSC.CMT.CTRL03.AR01.sh. Package name must match the
# "id" in complytime-mapping.json.
#
# The collector normalizes the pipeline's own vocabulary (statuses, triggers, the applied
# record) so this policy reads one shape. Time is measured against the collection's own
# timestamp, never the clock, so the same evidence always gives the same answer.
#
# What is a violation, and what is "could not tell":
#   - an incomplete collection is denied on its own and nothing else is concluded from it;
#   - a change older than the allowed lag that was never deployed by a successful run,
#     a head that is not deployed, a latest run that failed and was never recovered (or
#     is stuck), and an applied record that contradicts the run's status are violations;
#   - a run that failed and was later followed by a success of the same or a later commit
#     is NOT a violation by itself (the evidence keeps it, marked recovered);
#   - a change newer than the allowed lag may simply still be deploying, so it is not
#     denied yet. A day with no merge and a complete, healthy history is a pass;
#   - the runs read go from the start of the day to the collection time (a change merged late
#     on the day is deployed after it), but only runs STARTED on the day are checked for
#     contradicting their applied record: a later day answers for its own runs.
#
# The opa provider evaluates every mapped package against every file in the target's
# input_path, so each rule is guarded on the evidence's own assessment_requirement.
# Missing evidence therefore produces no denials; containers/complyctl/entrypoint.py
# fails the run when an AR has no evidence.
# platform: deployment-pipeline
# schema: schemas/deployment-pipeline.cue
package rosa_seaplane.change_management.deployment_applied

import rego.v1

applies if input.assessment_requirement == "RSC.CMT.CTRL03.AR01"

# Every denial carries a stable rule id as a trailing "[rule: <id>]", so reports can
# group and explain findings. The message stays a plain string (complyctl records it
# as is); config/findings/rules.yaml holds the title and fix hint for each id.
with_rule(id, text) := sprintf("%s [rule: %s]", [text, id])

target := object.get(input, "target", "(unknown pipeline)")

collection := object.get(input, "collection", {})

complete if collection.complete == true

problem_text := concat("; ", collection.problems) if {
	count(object.get(collection, "problems", [])) > 0
} else := "no reason recorded"

lag_ns := collection.allowed_lag_minutes * 60 * 1000000000

now_ns := time.parse_rfc3339_ns(collection.generated_at)

older_than_lag(ts) if now_ns - time.parse_rfc3339_ns(ts) > lag_ns

short(sha) := substring(sha, 0, 7)

deny contains msg if {
	applies
	not complete
	msg := with_rule("deployment.collection-incomplete", sprintf("%s: the deployment history could not be fully read (%s), so nothing can be concluded", [target, problem_text]))
}

# A merged change, other than the head (the head has its own rule below), that no
# successful run applied or contained, and that is old enough to have been deployed.
deny contains msg if {
	applies
	complete
	some c in input.merged_commits
	c.sha != input.head.sha
	not c.deployed
	older_than_lag(c.merged_at)
	msg := with_rule("deployment.change-not-deployed", sprintf("%s: change %s merged %s was not deployed by a successful run (latest attempt: %s)", [target, short(c.sha), c.merged_at, c.deployed_by_execution_status]))
}

# The environment is not running the head of the branch.
deny contains msg if {
	applies
	complete
	not input.head.deployed
	older_than_lag(input.head.committed_at)
	msg := with_rule("deployment.head-not-deployed", sprintf("%s: the environment is not running the head of %s (%s, committed %s); latest attempt: %s", [target, input.branch, short(input.head.sha), input.head.committed_at, input.head.deployed_by_execution_status]))
}

# The newest run failed and nothing later recovered it, or it is stuck.
deny contains msg if {
	applies
	complete
	e := input.latest_execution
	e != null
	e.status in {"failed", "stopped"}
	not e.recovered == true
	older_than_lag(e.started)
	msg := with_rule("deployment.latest-execution-failed", sprintf("%s: the latest deployment run started %s is %s and no later run recovered it", [target, e.started, e.status]))
}

deny contains msg if {
	applies
	complete
	e := input.latest_execution
	e != null
	e.status in {"in-progress", "unknown"}
	older_than_lag(e.started)
	msg := with_rule("deployment.latest-execution-stuck", sprintf("%s: the latest deployment run started %s is still %s after the allowed lag", [target, e.started, e.status]))
}

# The pipeline's applied record contradicts the run's status.
contradiction(e) if {
	e.status == "succeeded"
	e.applied == false
}

contradiction(e) if {
	e.status == "succeeded"
	e.applied == true
	e.applied_sha != e.commit
}

contradiction(e) if {
	e.status != "succeeded"
	e.applied == true
}

# Evidence without a window is judged whole rather than silently skipped.
started_on_the_day(_) if not input.window

started_on_the_day(e) if {
	t := time.parse_rfc3339_ns(e.started)
	t >= time.parse_rfc3339_ns(input.window.start)
	t < time.parse_rfc3339_ns(input.window.end)
}

deny contains msg if {
	applies
	complete
	some e in input.executions
	started_on_the_day(e)
	contradiction(e)
	msg := with_rule("deployment.record-contradicts-status", sprintf("%s: the run started %s is %s but its applied record says otherwise", [target, e.started, e.status]))
}
