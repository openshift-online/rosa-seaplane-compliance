# RSC.IAM.CTRL01.AR02: no non-human principal in an in-scope target may have
# authenticated with a long-term credential on the UTC day the evidence covers, as far as
# the target's audit log records. Input: the JSON from evidence/RSC.IAM.CTRL01.AR02.sh.
# Package name must match the "id" in complytime-mapping.json.
#
# Source-neutral: it reads normalized events (credential_type, principal) and
# per-key facts, so a collector for another source only has to produce the same
# shape. Three things are denied:
#   - an incomplete collection (a lookup failed or was throttled out), so a window
#     that was not fully searched can never pass;
#   - a key whose cross-check is inconsistent (the source says it was used on the
#     day but the audit log shows nothing, or it was used where nothing was
#     searched): the evidence is suspect, and suspect is not a pass;
#   - every principal that authenticated with a long-term credential.
# Zero events from a complete, consistent collection (a quiet day) is a pass. The collector cannot
# always tell people from services, so every principal is reported.
#
# The opa provider evaluates every mapped package against every file in the
# target's input_path, so each rule is guarded on the evidence's own
# assessment_requirement. Missing evidence therefore produces no denials;
# containers/complyctl/entrypoint.py fails the run when an AR has no evidence.
# platform: principal-key-usage
# schema: schemas/principal-key-usage.cue
package rosa_seaplane.identity_access.long_term_credential_use

import rego.v1

applies if input.assessment_requirement == "RSC.IAM.CTRL01.AR02"

# Every denial carries a stable rule id as a trailing "[rule: <id>]", so reports can
# group and explain findings. The message stays a plain string (complyctl records it
# as is); config/findings/rules.yaml holds the title and fix hint for each id.
with_rule(id, text) := sprintf("%s [rule: %s]", [text, id])

# Defaults so that a missing or partial collection block still produces a denial
# (a rule whose message cannot be formatted would silently produce none).
lookup_errors := input.collection.lookup_errors if is_number(input.collection.lookup_errors) else := 0

covers_date := input.covers_date if is_string(input.covers_date) else := "(unknown day)"

deny contains msg if {
	applies
	not input.collection.complete == true
	msg := with_rule("credential-use.log-not-searched", sprintf(
		"%s: the audit log was not fully searched (%d lookup error(s)), so nothing can be concluded",
		[input.target, lookup_errors],
	))
}

# The source says the key was used on the day, but nothing in the audit log
# accounts for it. It may only have been used for calls that event history does not
# record (data-plane calls), so use cannot be ruled in or out.
deny contains msg if {
	applies
	some key in input.keys
	key.cross_checked == true
	key.last_used_in_window == true
	key.events_found == 0
	msg := with_rule("credential-use.log-shows-no-events", sprintf(
		"%s: %s key ...%s was used on %s (UTC) per the account, but the audit log shows no events for it (it may have been used only for calls the audit log does not record)",
		[input.target, key.principal, key.key_suffix, covers_date],
	))
}

# Used somewhere that was not searched.
deny contains msg if {
	applies
	some key in input.keys
	key.cross_checked == true
	key.last_used_in_window == true
	key.last_used_region_checked == false
	msg := with_rule("credential-use.region-not-searched", sprintf(
		"%s: %s key ...%s was last used in region %s, which was not searched",
		[input.target, key.principal, key.key_suffix, key.last_used_region],
	))
}

# One denial per principal, with how many events were seen (a lower bound when the
# collector stopped early).
deny contains msg if {
	applies
	some principal in {e.principal | some e in input.events; e.credential_type == "long-term"}
	seen := sum([k.events_found | some k in input.keys; k.principal == principal])
	more := count([k | some k in input.keys; k.principal == principal; k.events_truncated == true]) > 0
	msg := with_rule("credential-use.long-term-authentication", sprintf(
		"%s: %s authenticated with a long-term credential on %s (UTC) (%s%d event(s))",
		[input.target, principal, covers_date, at_least(more), seen],
	))
}

at_least(true) := "at least " 

at_least(false) := ""
