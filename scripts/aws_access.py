#!/usr/bin/env python3
"""AWS access for an environment, built the way the platform's own dev scripts do it.

rosa-seaplane's scripts/dev/*-env.sh write a TEMPORARY AWS config from the account
snapshot kept in rosa-seaplane-internal and log in with a SAML helper. This does the
same, so nothing here reads or writes ~/.aws/config, and no account ID is ever
written into this repository:

  account snapshot   ../rosa-seaplane-internal/infra/accounts/<snapshot>/terragrunt-accounts.json
                     (override with RSC_ACCOUNTS_FILE)
  SAML helper        ../rosa-seaplane/scripts/dev/cached_saml_credentials_process.py
                     (override the checkout with RSC_SEAPLANE_REPO), run through `uv`

Profiles in the temporary config (names only, no IDs):
  rsc-admin              SAML login into the control (central) account
  rsc-<account>-admin    admin role in a child account, chained from rsc-admin
  rsc-<account>-ro       the compliance read-only role (config/aws/compliance-readonly-role.yaml),
                         chained from the account's admin profile

    aws_access.py exec --env integration [--sanitize] -- <command ...>
        run a command with that temporary config in AWS_CONFIG_FILE; it is removed afterwards
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import environment  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
ADMIN_ROLE = "rosa-seaplane-account-admin"
READONLY_ROLE = "rosa-seaplane-compliance-readonly"
ID_RE = re.compile(r"[0-9]{12}")
AWS_ENV_VARS = ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION",
                "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")


class AccessError(RuntimeError):
    pass


def mask(text: str) -> str:
    return ID_RE.sub("<ID>", str(text))


def snapshot_file(env: dict, environ: dict = None) -> Path:
    environ = os.environ if environ is None else environ
    if environ.get("RSC_ACCOUNTS_FILE"):
        return Path(environ["RSC_ACCOUNTS_FILE"])
    return ROOT.parent / "rosa-seaplane-internal/infra/accounts" / env["snapshot"] / "terragrunt-accounts.json"


def seaplane_repo(environ: dict = None) -> Path:
    environ = os.environ if environ is None else environ
    return Path(environ.get("RSC_SEAPLANE_REPO") or ROOT.parent / "rosa-seaplane")


def _lookup(doc: dict, path: str):
    cur = doc
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur if isinstance(cur, str) and ID_RE.fullmatch(cur) else None


def resolve_accounts(env: dict, snap: Path) -> dict:
    """Account name -> ID from the snapshot (None when missing). Never printed unmasked."""
    if not snap.is_file():
        raise AccessError(
            f"account snapshot not found: {snap}\n"
            "    Clone rosa-seaplane-internal as a sibling directory, or set RSC_ACCOUNTS_FILE.")
    doc = json.loads(snap.read_text())
    region = env["regions"][0] if env["regions"] else ""
    return {a["name"]: _lookup(doc, a["snapshot_path"].replace("{region}", region)) for a in env["accounts"]}


def describe(env: dict, environ: dict = None) -> dict:
    snap = snapshot_file(env, environ)
    resolved = resolve_accounts(env, snap)
    return {"snapshot": str(snap), "resolved": {k: v is not None for k, v in resolved.items()}}


def config_text(env: dict, accounts: dict, seaplane: Path) -> str:
    """The temporary AWS config. Contains account IDs: it lives only in a temp dir."""
    missing = [n for n, v in accounts.items() if v is None]
    if missing:
        raise AccessError(f"accounts not found in the snapshot: {', '.join(missing)}")
    central = accounts["central"]
    region = env["regions"][0]
    helper = seaplane / "scripts/dev/cached_saml_credentials_process.py"
    out = [f"[profile rsc-admin]\n"
           f"credential_process = uv run {helper} {central} {central}-{env['saml_role']}\n"
           f"region = {region}\nduration_seconds = 3600\n"]
    for name, acct in accounts.items():
        admin = "rsc-admin"
        if name != "central":
            admin = f"rsc-{name}-admin"
            out.append(f"[profile {admin}]\nrole_arn = arn:aws:iam::{acct}:role/{ADMIN_ROLE}\n"
                       f"source_profile = rsc-admin\nregion = {region}\nduration_seconds = 3600\n")
        out.append(f"[profile rsc-{name}-ro]\nrole_arn = arn:aws:iam::{acct}:role/{READONLY_ROLE}\n"
                   f"source_profile = {admin}\nregion = {region}\n")
    return "\n".join(out)


def admin_profile(name: str) -> str:
    return "rsc-admin" if name == "central" else f"rsc-{name}-admin"


def readonly_profile(name: str) -> str:
    return f"rsc-{name}-ro"


@contextmanager
def aws_environment(env: dict, environ: dict = None):
    """Temporary AWS config for `env`, active in os.environ for the duration.

    Sanitizes inherited AWS variables so they cannot override the generated
    profiles, as the platform's init_aws_config does, and removes everything after.
    """
    snap = snapshot_file(env, environ)
    accounts = resolve_accounts(env, snap)
    text = config_text(env, accounts, seaplane_repo(environ))
    if not shutil.which("uv"):
        raise AccessError("uv is required (the SAML helper runs through it): https://docs.astral.sh/uv/")
    saved = {k: os.environ.get(k) for k in (*AWS_ENV_VARS, "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE")}
    tmp = tempfile.mkdtemp(prefix="rsc-aws-")
    try:
        os.chmod(tmp, 0o700)
        cfg, creds = Path(tmp) / "config", Path(tmp) / "credentials"
        cfg.write_text(text)
        creds.write_text("")
        for k in AWS_ENV_VARS:
            os.environ.pop(k, None)
        os.environ["AWS_CONFIG_FILE"], os.environ["AWS_SHARED_CREDENTIALS_FILE"] = str(cfg), str(creds)
        os.environ["AWS_PAGER"] = ""
        yield {"accounts": list(accounts), "config_dir": tmp}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    ex = sub.add_parser("exec", help="run a command with the temporary AWS config")
    ex.add_argument("--env", default=None)
    ex.add_argument("argv", nargs=argparse.REMAINDER)
    args = ap.parse_args()
    argv = args.argv[1:] if args.argv[:1] == ["--"] else args.argv
    if not argv:
        sys.exit("ERROR: give a command after --")
    try:
        with aws_environment(environment.load(args.env)):
            sys.exit(subprocess.run(argv).returncode)
    except (AccessError, environment.EnvironmentError_) as e:
        sys.exit(f"ERROR: {mask(e)}")


if __name__ == "__main__":
    main()
