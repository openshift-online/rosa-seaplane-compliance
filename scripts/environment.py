#!/usr/bin/env python3
"""Load an environment definition (config/environments/<name>.yaml).

The definition holds regions, logical account names and where each account's ID
sits in the platform's account snapshot, and nothing sensitive. AWS access for it
is set up by scripts/aws_access.py.

    environment.py [name]               print the environment (default: $RSC_ENV or
                                        integration) and whether its accounts can be resolved
    environment.py --accounts [name]    print only the logical account names, one per line
    environment.py --regions [name]     print the regions, comma separated
    environment.py --pipelines [name]   print the deployment pipeline names, one per line
    environment.py --deployment [name]  print the deployment block as JSON
    environment.py --clusters [name]    print the clusters whose deployed workloads are health-checked
    environment.py --health [name]      print the health block (metrics account, clusters, window) as JSON
"""
import json
import os
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
ENV_DIR = ROOT / "config/environments"
DEFAULT_ENV = "integration"


class EnvironmentError_(ValueError):
    pass


def available(env_dir: Path = ENV_DIR) -> list:
    return sorted(p.stem for p in env_dir.glob("*.yaml"))


def load(name: str = None, environ: dict = None, env_dir: Path = ENV_DIR) -> dict:
    """{name, regions, snapshot, saml_role, accounts: [{name, snapshot_path}]}."""
    environ = os.environ if environ is None else environ
    name = name or environ.get("RSC_ENV") or DEFAULT_ENV
    path = env_dir / f"{name}.yaml"
    if not re.fullmatch(r"[a-z0-9-]+", name) or not path.is_file():
        raise EnvironmentError_(f"unknown environment {name!r}; available: {', '.join(available(env_dir))}")
    doc = yaml.safe_load(path.read_text()) or {}
    if doc.get("name") != name:
        raise EnvironmentError_(f"{path.name}: name must be {name!r}")
    for key in ("snapshot", "saml-role", "accounts"):
        if not doc.get(key):
            raise EnvironmentError_(f"{path.name}: missing {key}")
    if not re.fullmatch(r"[a-z0-9-]+", str(doc["snapshot"])):
        raise EnvironmentError_(f"{path.name}: bad snapshot name")
    accounts = []
    for account, spec in doc["accounts"].items():
        if not re.fullmatch(r"[a-z0-9-]+", account) or not (spec or {}).get("snapshot-path"):
            raise EnvironmentError_(f"{path.name}: account {account!r} needs a name and a snapshot-path")
        accounts.append({"name": account, "snapshot_path": spec["snapshot-path"]})
    return {"name": name, "regions": list(doc.get("regions") or []), "snapshot": doc["snapshot"],
            "saml_role": doc["saml-role"], "accounts": accounts,
            "deployment": _deployment(doc.get("deployment"), [a["name"] for a in accounts], path.name)}


def _deployment(block, account_names: list, filename: str):
    """The validated deployment block, or None when the environment has none."""
    if block is None:
        return None
    if not isinstance(block, dict):
        raise EnvironmentError_(f"{filename}: deployment must be a mapping")
    repository, branch = block.get("repository"), block.get("branch")
    if not isinstance(repository, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise EnvironmentError_(f"{filename}: deployment.repository must be owner/name")
    if branch is not None and not (isinstance(branch, str) and re.fullmatch(r"[A-Za-z0-9_./-]+", branch)):
        raise EnvironmentError_(f"{filename}: deployment.branch must be a branch name or null")
    lag = block.get("allowed-lag-minutes")
    if isinstance(lag, bool) or not isinstance(lag, int) or not 1 <= lag <= 10080:
        raise EnvironmentError_(f"{filename}: deployment.allowed-lag-minutes must be a whole number of minutes (1 to 10080)")
    pipelines = []
    for p in block.get("pipelines") or []:
        pname, account = (p or {}).get("name"), (p or {}).get("account")
        if not isinstance(pname, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", pname):
            raise EnvironmentError_(f"{filename}: every deployment pipeline needs a name")
        if account not in account_names:
            raise EnvironmentError_(f"{filename}: pipeline {pname!r} names account {account!r}, which this environment does not list")
        pipelines.append({"name": pname, "account": account})
    if not pipelines:
        raise EnvironmentError_(f"{filename}: deployment needs at least one pipeline")
    if len({p["name"] for p in pipelines}) != len(pipelines):
        raise EnvironmentError_(f"{filename}: a deployment pipeline is listed twice")
    return {"repository": repository, "branch": branch, "allowed_lag_minutes": lag, "pipelines": pipelines,
            "health": _health(block.get("health"), account_names, filename)}


def _whole(block: dict, key: str, low: int, high: int, default: int, filename: str) -> int:
    value = block.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise EnvironmentError_(f"{filename}: deployment.health.{key} must be a whole number between {low} and {high}")
    return value


def _health(block, account_names: list, filename: str):
    """The validated health block (where the deployed workloads' state is read from, which
    clusters must report, how far back and how fresh), or None when there is none."""
    if block is None:
        return None
    if not isinstance(block, dict):
        raise EnvironmentError_(f"{filename}: deployment.health must be a mapping")
    account = block.get("account")
    if account not in account_names:
        raise EnvironmentError_(f"{filename}: deployment.health.account {account!r} is not an account this environment lists")
    clusters = block.get("clusters")
    if not isinstance(clusters, list) or not clusters:
        raise EnvironmentError_(f"{filename}: deployment.health.clusters needs at least one cluster")
    for c in clusters:
        if not isinstance(c, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,63}", c):
            raise EnvironmentError_(f"{filename}: deployment.health.clusters has an invalid cluster name {c!r}")
    if len(set(clusters)) != len(clusters):
        raise EnvironmentError_(f"{filename}: deployment.health.clusters lists a cluster twice")
    return {"account": account, "clusters": list(clusters),
            "lookback_minutes": _whole(block, "lookback-minutes", 5, 1440, 30, filename),
            "freshness_seconds": _whole(block, "freshness-seconds", 30, 3600, 300, filename),
            "step_seconds": _whole(block, "step-seconds", 15, 600, 60, filename)}


def deployment(name: str = None, environ: dict = None, env_dir: Path = ENV_DIR) -> dict:
    """The deployment block of an environment; an environment without one is an error,
    never a guess."""
    env = load(name, environ, env_dir)
    if env["deployment"] is None:
        raise EnvironmentError_(f"environment {env['name']!r} has no deployment block in config/environments/")
    return env["deployment"]


def health(name: str = None, environ: dict = None, env_dir: Path = ENV_DIR) -> dict:
    """The health block of an environment; an environment without one is an error, never a guess."""
    dep = deployment(name, environ, env_dir)
    if dep["health"] is None:
        raise EnvironmentError_(f"environment {load(name, environ, env_dir)['name']!r} has no deployment.health block in config/environments/")
    return dep["health"]


def cluster_names(name: str = None, environ: dict = None, env_dir: Path = ENV_DIR) -> list:
    """Cluster names whose deployed workloads are health-checked (empty if none are configured)."""
    dep = load(name, environ, env_dir)["deployment"]
    return list(dep["health"]["clusters"]) if dep and dep["health"] else []


def pipeline_names(name: str = None, environ: dict = None, env_dir: Path = ENV_DIR) -> list:
    """Logical names of the deployment pipelines of an environment (empty if it has none)."""
    dep = load(name, environ, env_dir)["deployment"]
    return [p["name"] for p in dep["pipelines"]] if dep else []


def account_names(name: str = None, environ: dict = None, env_dir: Path = ENV_DIR) -> list:
    """Logical account names of an environment: what checks must reach (never IDs)."""
    return [a["name"] for a in load(name, environ, env_dir)["accounts"]]


def main() -> None:
    flags = {a for a in sys.argv[1:] if a.startswith("--")}
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    env_name = args[0] if args else None
    simple = {
        "--regions": lambda: ",".join(load(env_name)["regions"]),
        "--accounts": lambda: "\n".join(a["name"] for a in load(env_name)["accounts"]),
        "--pipelines": lambda: "\n".join(pipeline_names(env_name)),
        "--deployment": lambda: json.dumps(deployment(env_name)),
        "--clusters": lambda: "\n".join(health(env_name)["clusters"]),
        "--health": lambda: json.dumps(health(env_name)),
    }
    for flag, fn in simple.items():
        if flag in flags:
            try:
                print(fn())
            except EnvironmentError_ as e:
                sys.exit(f"ERROR: {e}")
            return
    import aws_access
    try:
        env = load(args[0] if args else None)
        status = aws_access.describe(env)
    except (EnvironmentError_, aws_access.AccessError) as e:
        sys.exit(f"ERROR: {e}")
    print(f"environment: {env['name']}  regions: {', '.join(env['regions'])}")
    print(f"  account snapshot: {status['snapshot']}")
    for a in env["accounts"]:
        print(f"  {a['name']:<20} {'resolvable' if status['resolved'].get(a['name']) else 'NOT FOUND in snapshot'}")
    if env["deployment"]:
        print(f"  deployment pipelines: {', '.join(p['name'] for p in env['deployment']['pipelines'])}")
    else:
        print("  deployment pipelines: none configured")
    if env["deployment"] and env["deployment"]["health"]:
        print(f"  health-checked clusters: {', '.join(env['deployment']['health']['clusters'])}")


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    main()
