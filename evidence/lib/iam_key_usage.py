#!/usr/bin/env python3
"""Collect long-term-credential usage evidence for one AWS account.

    iam_key_usage.py --ar <AR id> --target <logical account> --profile <read-only profile>
                     --date YYYY-MM-DD [--regions us-east-1,...]

EVENT collector for ONE UTC day, the half-open [D 00:00:00Z, D+1 00:00:00Z) (lib/day_window.py).
Answers "did any principal authenticate with a long-term credential on that day?"
without scanning the whole audit log (CloudTrail's LookupEvents returns 50 events per
call at 2 calls per second per account and region, one filter at a time, so a full
scan of a busy account takes hours). Instead it asks for the events of each EXISTING
long-term key:

  1. list the IAM users and their access keys (active and inactive: an inactive key
     may have been active earlier in the window);
  2. for each key, look up CloudTrail events by access key, newest first, bounded to
     the day. One page with events already proves the key was used, so it stops
     there; a key with no events is paged until the day is exhausted. CloudTrail's end time
     is inclusive, so an event at exactly the end of the day is dropped (it belongs to the
     next day);
  3. cross-check each key with IAM's own last-used record. IAM keeps only the MOST RECENT
     use of a key, so it can contradict an empty day only when that use fell inside the day
     (a later use says nothing about the day). If IAM says a key was used on the day but
     CloudTrail has no event for it (for example it was only used
     for data-plane calls, which event history does not record), or it was last used
     in a region that was not searched, that is reported as a fact the policy denies:
     the evidence is suspect and is never read as a pass;
  4. if the root user has any access key, look up events by user name `root`.

Read-only: list, get and lookup calls only, through the read-only profile. Evidence is
normalized (schemas/principal-key-usage.cue) and holds only a bounded sample of
trimmed events per key: never source IPs, user agents, request parameters or full key
ids (only the last four characters).

Limits it cannot get around, recorded in collection.limitations: the keys are those that
exist when the collector runs (state, not the day's: for a past day, a key deleted since is
not checked); a day with no key at all is a complete, empty collection and passes; only management events of the
last 90 days are searched; sessions are not followed past the call made with the key.

Any lookup that fails or is throttled out makes collection.complete false, which the
policy denies. Failing to list the inventory at all is an error and writes no evidence.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

from aws_cli import ID_RE, THROTTLE_RE, Aws, AwsError, mask, utc_iso  # noqa: F401  (the shared aws CLI wrapper)
from day_window import DayError, day_for

SAMPLE_PER_KEY = 20
ROOT_PAGE_CAP = 40
HOME_REGION = "us-east-1"
SOURCE = "cloudtrail-event-history+iam-last-used"
LIMITATIONS = [
    "the keys checked are those that exist when the collector runs, so a key deleted since the covered day cannot be listed and is not checked",
    "IAM records only the most recent use of a key, so its last-used time can contradict an empty day only when that use fell inside the day",
    "only management events in CloudTrail event history (the last 90 days) are searched; data-plane calls are not",
    "a session started with a key is seen only as the call made with the key, not followed afterwards",
]
class CollectionError(RuntimeError):
    """The account's key inventory could not be read: no evidence can be written."""


def principal_of(identity: dict, fallback: str) -> str:
    kind = identity.get("type")
    if kind == "IAMUser":
        return identity.get("userName") or fallback or "unknown"
    if kind == "Root":
        return "root"
    # Never a session name: it can be a person. The role that issued it, if any.
    issuer = (identity.get("sessionContext") or {}).get("sessionIssuer") or {}
    return issuer.get("userName") or (kind or "unknown").lower()


def credential_type(identity: dict, key_id: str) -> str:
    kind = identity.get("type")
    if kind == "IAMUser" or key_id.startswith("AKIA"):
        # An IAM user's call is long-term even when the key is a session key: a session
        # derived from a long-term key still starts from one.
        return "long-term"
    if key_id.startswith("ASIA"):
        return "temporary"
    return "none"


def normalize_event(event: dict, region: str) -> dict:
    detail = json.loads(event.get("CloudTrailEvent") or "{}")
    identity = detail.get("userIdentity") or {}
    key_id = identity.get("accessKeyId") or event.get("AccessKeyId") or ""
    kind = identity.get("type") or "unknown"
    return {
        "time": utc_iso(event["EventTime"]),
        "event_name": event.get("EventName") or detail.get("eventName") or "unknown",
        "event_source": event.get("EventSource") or detail.get("eventSource") or "unknown",
        "principal_type": {"IAMUser": "iam-user", "Root": "root", "AssumedRole": "assumed-role"}.get(kind, kind.lower()),
        "principal": principal_of(identity, event.get("Username")),
        "credential_type": credential_type(identity, key_id),
        "region": region,
    }


def lookup_args(attribute: str, value: str, region: str, start: datetime, end: datetime, token: str = None) -> list:
    args = ["cloudtrail", "lookup-events", "--region", region,
            "--lookup-attributes", f"AttributeKey={attribute},AttributeValue={value}",
            "--start-time", utc_iso(start.timestamp()), "--end-time", utc_iso(end.timestamp()),
            "--max-results", "50"]
    return args + (["--next-token", token] if token else [])


def in_day(event: dict, start: datetime, end: datetime) -> bool:
    """CloudTrail's end time is inclusive: keep only events in the half-open [start, end)."""
    return start <= datetime.fromisoformat(utc_iso(event["EventTime"]).replace("Z", "+00:00")) < end


def lookup_key(aws: Aws, key_id: str, region: str, start: datetime, end: datetime):
    """(sample, events_seen, truncated) for one key in one region. Stops at the first events."""
    sample, seen, token = [], 0, None
    while True:
        page = aws.call(*lookup_args("AccessKeyId", key_id, region, start, end, token), region=region)
        batch = [e for e in page.get("Events") or [] if in_day(e, start, end)]
        seen += len(batch)
        for e in batch:
            if len(sample) < SAMPLE_PER_KEY:
                sample.append(normalize_event(e, region))
        token = page.get("NextToken")
        if seen:  # any event made with a long-term key proves it authenticated in the window
            return sample, seen, bool(token) or seen > len(sample)
        if not token:
            return sample, 0, False


def lookup_root(aws: Aws, region: str, start: datetime, end: datetime):
    """(sample, long_term_seen, resolved): root events carry no key, so only calls made
    with a long-term key count. Unresolved if the page cap is hit without finding any."""
    sample, found, token, pages = [], 0, None, 0
    while pages < ROOT_PAGE_CAP:
        page = aws.call(*lookup_args("Username", "root", region, start, end, token), region=region)
        pages += 1
        for e in page.get("Events") or []:
            if not in_day(e, start, end):
                continue
            n = normalize_event(e, region)
            if n["credential_type"] == "long-term":
                found += 1
                if len(sample) < SAMPLE_PER_KEY:
                    sample.append(n)
        token = page.get("NextToken")
        if found:
            return sample, found, True
        if not token:
            return sample, 0, True
    return sample, 0, False


def list_keys(aws: Aws) -> list:
    try:
        users = aws.call("iam", "list-users").get("Users") or []
        keys = []
        for user in users:
            meta = aws.call("iam", "list-access-keys", "--user-name", user["UserName"]).get("AccessKeyMetadata") or []
            for k in meta:
                keys.append({"principal": user["UserName"], "key_id": k["AccessKeyId"], "active": k.get("Status") == "Active"})
        return keys
    except AwsError as e:
        raise CollectionError(f"could not list the account's access keys: {e}") from None


def root_has_keys(aws: Aws) -> bool:
    try:
        return int((aws.call("iam", "get-account-summary").get("SummaryMap") or {}).get("AccountAccessKeysPresent", 0)) > 0
    except AwsError as e:
        raise CollectionError(f"could not read the account summary: {e}") from None


def collect(aws: Aws, ar: str, target: str, day: dict, regions: list, now: datetime = None) -> dict:
    now = now or datetime.now(timezone.utc)
    start = datetime.fromisoformat(day["start"].replace("Z", "+00:00"))
    end = datetime.fromisoformat(day["end"].replace("Z", "+00:00"))
    regions = [HOME_REGION] + [r for r in regions if r != HOME_REGION]
    inventory = list_keys(aws)
    root = root_has_keys(aws)
    errors, keys, events = 0, [], []

    for k in inventory:
        rec = {"principal_type": "iam-user", "principal": k["principal"], "key_suffix": k["key_id"][-4:],
               "active": k["active"], "last_used": None, "last_used_in_window": False, "last_used_region": None,
               "last_used_region_checked": True, "cross_checked": False, "events_found": 0, "events_truncated": False}
        try:
            used = aws.call("iam", "get-access-key-last-used", "--access-key-id", k["key_id"]).get("AccessKeyLastUsed") or {}
            rec["cross_checked"] = True
            if used.get("LastUsedDate"):
                rec["last_used"] = utc_iso(used["LastUsedDate"])
                rec["last_used_in_window"] = start <= datetime.fromisoformat(rec["last_used"].replace("Z", "+00:00")) < end
                region = used.get("Region")
                rec["last_used_region"] = region if region and region != "N/A" else None
                rec["last_used_region_checked"] = rec["last_used_region"] is None or rec["last_used_region"] in regions
        except AwsError:
            errors += 1
        for region in regions:
            try:
                sample, seen, truncated = lookup_key(aws, k["key_id"], region, start, end)
            except AwsError:
                errors += 1
                continue
            rec["events_found"] += seen
            rec["events_truncated"] = rec["events_truncated"] or truncated
            events.extend(sample)
            if seen:
                break  # proven; no need to search the other regions
        keys.append(rec)

    if root:
        rec = {"principal_type": "root", "principal": "root", "key_suffix": None, "active": True, "last_used": None,
               "last_used_in_window": False, "last_used_region": None, "last_used_region_checked": True,
               "cross_checked": False, "events_found": 0, "events_truncated": False}
        for region in regions:
            try:
                sample, found, resolved = lookup_root(aws, region, start, end)
            except AwsError:
                errors += 1
                continue
            if not resolved:
                errors += 1  # could not rule out use of a root key
            rec["events_found"] += found
            events.extend(sample)
            if found:
                break
        keys.append(rec)

    stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "assessment_requirement": ar,
        "generated_at": stamp,
        "target": target,
        "target_type": "aws-account",
        "covers_date": day["covers_date"],
        "window": {"start": day["start"], "end": day["end"]},
        "collection": {
            "complete": errors == 0, "source": SOURCE, "regions": regions,
            "keys_checked": len(keys), "lookup_errors": errors, "limitations": LIMITATIONS, "generated_at": stamp,
        },
        "keys": keys,
        "events": sorted(events, key=lambda e: e["time"], reverse=True),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ar", required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--profile", required=True)
    ap.add_argument("--date", required=True, help="the UTC day to cover, YYYY-MM-DD (already checked by the caller)")
    ap.add_argument("--regions", default=HOME_REGION, help="comma or space separated; us-east-1 is always included")
    args = ap.parse_args()
    regions = [r for r in re.split(r"[,\s]+", args.regions) if r]
    try:
        print(json.dumps(collect(Aws(args.profile), args.ar, args.target, day_for(args.date), regions), indent=2))
    except (CollectionError, AwsError, DayError) as e:
        sys.exit(f"ERROR: {e}")


if __name__ == "__main__":
    main()
