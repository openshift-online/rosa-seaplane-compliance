#!/usr/bin/env python3
"""Create, inspect or delete the compliance read-only role in one AWS account.

The role and every permission it needs are defined in
config/aws/compliance-readonly-role.yaml. This script applies that file to the
accounts of an environment. It is a stopgap until the role lives in the platform's
Terraform.

    aws_readonly_role.py plan   --env integration [--account A|all]
    aws_readonly_role.py apply  --env integration [--account A|all] --yes
    aws_readonly_role.py verify --env integration [--account A|all]
    aws_readonly_role.py delete --env integration [--account A|all] --yes

Access is set up as the platform's own dev scripts do (see scripts/aws_access.py):
a temporary AWS config built from the account snapshot, never ~/.aws/config.
`apply` and `delete` use each account's ADMIN profile (the role has to be created
by someone who can create roles); `verify` uses the read-only profile the collectors
will use. `plan` never writes. Output never includes account IDs.
"""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

import aws_access  # noqa: E402
import environment  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DEFINITION = ROOT / "config/aws/compliance-readonly-role.yaml"
ID_RE = re.compile(r"[0-9]{12}")
TAG_RE = re.compile(r"[\w\s.:/=+\-@]{1,256}")
WRITE_PROBES = ["iam:CreateUser", "iam:AttachRolePolicy", "s3:PutObject", "ec2:TerminateInstances"]


class DefinitionError(ValueError):
    pass


def mask(text: str) -> str:
    return ID_RE.sub("<ID>", text)


def load_definition(path: Path = DEFINITION) -> dict:
    d = yaml.safe_load(Path(path).read_text()) or {}
    if ID_RE.search(Path(path).read_text()) or "arn:aws:iam::" in "".join(
            line for line in Path(path).read_text().splitlines() if not line.lstrip().startswith("#")
            and "arn:aws:iam::aws:policy" not in line):
        raise DefinitionError("the role definition must not contain account IDs or account-scoped ARNs")
    for key in ("role-name", "trust", "managed-policies", "actions"):
        if key not in d:
            raise DefinitionError(f"missing {key}")
    if d["trust"] != "same-account":
        raise DefinitionError("only trust: same-account is supported")
    for k, v in (d.get("tags") or {}).items():
        # IAM rejects anything else, and only after the call is made.
        if not TAG_RE.fullmatch(str(k)) or not TAG_RE.fullmatch(str(v)):
            raise DefinitionError(f"tag {k!r}={v!r} has characters IAM does not allow")
    for p in d["managed-policies"]:
        if not p.get("arn", "").startswith("arn:aws:iam::aws:policy/") or not p.get("needed-by"):
            raise DefinitionError(f"managed policy needs an AWS-managed arn and needed-by: {p}")
    for a in d["actions"]:
        if not re.fullmatch(r"[a-z0-9-]+:[A-Za-z*]+", a.get("action", "")) or not a.get("needed-by"):
            raise DefinitionError(f"action needs service:Action and needed-by: {a}")
        if not re.match(r"(?:[a-z0-9-]+:)(Get|List|Describe|Lookup|Generate|View|Batch)", a["action"].replace("*", "")):
            raise DefinitionError(f"{a['action']} does not look read-only")
    return d


def trust_policy(account_id: str) -> dict:
    return {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"}, "Action": "sts:AssumeRole"}]}


def inline_policy(d: dict) -> dict:
    return {"Version": "2012-10-17", "Statement": [{
        "Sid": "ExplicitReadOnly", "Effect": "Allow", "Action": sorted({a["action"] for a in d["actions"]}), "Resource": "*"}]}


def aws(profile: str, *args: str, check: bool = True) -> str:
    cmd = ["aws", "--profile", profile, "--output", "json", *args]
    res = subprocess.run(cmd, capture_output=True, text=True, env={**__import__("os").environ, "AWS_PAGER": ""})
    if res.returncode != 0:
        if check:
            raise SystemExit("ERROR: " + mask(res.stderr.strip() or res.stdout.strip()))
        return ""
    return res.stdout


def account_id(profile: str) -> str:
    return json.loads(aws(profile, "sts", "get-caller-identity"))["Account"]


def existing(profile: str, name: str):
    out = aws(profile, "iam", "get-role", "--role-name", name, check=False)
    return json.loads(out)["Role"] if out else None


def cmd_plan(args, d) -> None:
    acct = account_id(args.profile)
    role = existing(args.profile, d["role-name"])
    print(f"profile {args.profile}: account <ID>")
    print(f"role {d['role-name']}: {'EXISTS' if role else 'does not exist'}")
    print("would apply:")
    print("  trust policy: same-account root principal (account filled in at apply time)")
    for p in d["managed-policies"]:
        print(f"  attach {p['arn']}")
    print(f"  inline policy ExplicitReadOnly: {', '.join(sorted(a['action'] for a in d['actions']))}")
    print(f"  tags: {d.get('tags', {})}")
    print("No changes made (plan only).")
    del acct


def cmd_apply(args, d) -> None:
    if not args.yes:
        raise SystemExit("ERROR: refusing to write without --yes (run `plan` first)")
    acct = account_id(args.profile)
    name = d["role-name"]
    tags = [f"Key={k},Value={v}" for k, v in d.get("tags", {}).items()]
    if existing(args.profile, name):
        aws(args.profile, "iam", "update-assume-role-policy", "--role-name", name,
            "--policy-document", json.dumps(trust_policy(acct)))
        aws(args.profile, "iam", "update-role", "--role-name", name, "--max-session-duration", str(d["max-session-seconds"]))
        print(f"updated role {name} in <ID>")
    else:
        aws(args.profile, "iam", "create-role", "--role-name", name, "--description", d["description"],
            "--max-session-duration", str(d["max-session-seconds"]),
            "--assume-role-policy-document", json.dumps(trust_policy(acct)), "--tags", *tags)
        print(f"created role {name} in <ID>")
    for p in d["managed-policies"]:
        aws(args.profile, "iam", "attach-role-policy", "--role-name", name, "--policy-arn", p["arn"])
    aws(args.profile, "iam", "put-role-policy", "--role-name", name, "--policy-name", "ExplicitReadOnly",
        "--policy-document", json.dumps(inline_policy(d)))
    print("attached managed policies and the inline policy. Run `verify` next.")


def cmd_verify(args, d) -> None:
    acct = account_id(args.profile)
    arn = f"arn:aws:iam::{acct}:role/{d['role-name']}"
    if not existing(args.profile, d["role-name"]):
        raise SystemExit("ERROR: the role does not exist; run apply first")
    # Write probes use the policy simulator from the admin session: nothing is executed.
    sim = json.loads(aws(args.profile, "iam", "simulate-principal-policy", "--policy-source-arn", arn,
                         "--action-names", *WRITE_PROBES))
    allowed = [r["EvalActionName"] for r in sim["EvaluationResults"] if r["EvalDecision"] == "allowed"]
    print("  write probes the role would be allowed (must be none):", allowed or "none")
    if allowed:
        raise SystemExit("ERROR: the role can write; refusing to call it read-only")
    # Reads run through the real read-only profile, exactly as the collectors will.
    ro = args.ro_profile
    who = json.loads(aws(ro, "sts", "get-caller-identity"))["Arn"]
    if f"assumed-role/{d['role-name']}/" not in who:
        raise SystemExit(f"ERROR: the read-only profile is not using the read-only role ({mask(who)})")
    bad = False
    for label, a in [("iam generate-credential-report", ["iam", "generate-credential-report"]),
                     ("cloudtrail lookup-events", ["cloudtrail", "lookup-events", "--max-results", "1", "--region", "us-east-1"]),
                     ("iam list-users", ["iam", "list-users", "--max-items", "1"])]:
        ok = bool(aws(ro, *a, check=False))
        bad = bad or not ok
        print(f"  {'ok  ' if ok else 'FAIL'} {label}")
    if bad:
        raise SystemExit("ERROR: the role cannot do something it needs")
    print("  verified: reads work, writes are not allowed.")


def cmd_delete(args, d) -> None:
    if not args.yes:
        raise SystemExit("ERROR: refusing to write without --yes")
    name = d["role-name"]
    if not existing(args.profile, name):
        print("role does not exist; nothing to do")
        return
    for p in json.loads(aws(args.profile, "iam", "list-attached-role-policies", "--role-name", name))["AttachedPolicies"]:
        aws(args.profile, "iam", "detach-role-policy", "--role-name", name, "--policy-arn", p["PolicyArn"])
    for n in json.loads(aws(args.profile, "iam", "list-role-policies", "--role-name", name))["PolicyNames"]:
        aws(args.profile, "iam", "delete-role-policy", "--role-name", name, "--policy-name", n)
    aws(args.profile, "iam", "delete-role", "--role-name", name)
    print(f"deleted role {name}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["plan", "apply", "verify", "delete"])
    ap.add_argument("--env", default=None, help="environment (default: $RSC_ENV or integration)")
    ap.add_argument("--account", default="all", help="logical account name, or all")
    ap.add_argument("--yes", action="store_true", help="required for apply and delete")
    args = ap.parse_args()
    try:
        d = load_definition()
        env = environment.load(args.env)
        names = [a["name"] for a in env["accounts"]]
        chosen = names if args.account == "all" else [args.account]
        unknown = [n for n in chosen if n not in names]
        if unknown:
            raise SystemExit(f"ERROR: unknown account {unknown}; this environment has: {', '.join(names)}")
        if args.command in ("apply", "delete") and not args.yes:
            raise SystemExit("ERROR: refusing to write without --yes (run `plan` first)")
        with aws_access.aws_environment(env):
            for name in chosen:
                print(f"== {env['name']} / {name}")
                args.profile = aws_access.admin_profile(name)
                args.ro_profile = aws_access.readonly_profile(name)
                {"plan": cmd_plan, "apply": cmd_apply, "verify": cmd_verify, "delete": cmd_delete}[args.command](args, d)
    except (DefinitionError, environment.EnvironmentError_, aws_access.AccessError) as e:
        sys.exit(f"ERROR: {mask(str(e))}")


if __name__ == "__main__":
    main()
