#!/usr/bin/env python3
"""Load and validate config/automation.yaml; print it as JSON for the collectors.

    automation_config.py [path]

Output: {"change_authors": [login...], "merge_automation": [login...],
         "exemption_approved": bool}
`exemption_approved` is true only when every change author has at least one
`approved-by`. Logins are normalized (no "[bot]" suffix).
"""
import json
import sys
from pathlib import Path

import yaml

DEFAULT = Path(__file__).resolve().parent.parent.parent / "config/automation.yaml"


class ConfigError(ValueError):
    pass


def base_login(login: str) -> str:
    return login[:-5] if login.endswith("[bot]") else login


def load(path: Path = DEFAULT) -> dict:
    doc = yaml.safe_load(Path(path).read_text()) or {}
    out = {"change_authors": [], "merge_automation": []}
    for key, field in (("change-authors", "change_authors"), ("merge-automation", "merge_automation")):
        for entry in doc.get(key) or []:
            login = str((entry or {}).get("login") or "").strip()
            if not login:
                raise ConfigError(f"{key}: every entry needs a login")
            if not str(entry.get("rationale") or "").strip():
                raise ConfigError(f"{key}: {login} needs a rationale")
            out[field].append(base_login(login))
    if len(set(out["change_authors"])) != len(out["change_authors"]):
        raise ConfigError("change-authors lists a login twice")
    approvers = [bool((e or {}).get("approved-by")) for e in doc.get("change-authors") or []]
    out["exemption_approved"] = bool(approvers) and all(approvers)
    return out


if __name__ == "__main__":
    try:
        print(json.dumps(load(Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT)))
    except (ConfigError, OSError) as e:
        sys.exit(f"ERROR: automation config: {e}")
