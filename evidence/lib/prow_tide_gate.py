#!/usr/bin/env python3
"""Normalize Prow Tide merge requirements for one repository and branch.

Tide is the merge bot behind OpenShift's Prow. Its `queries` say which labels a
PR needs before Tide will merge it, e.g. `lgtm` and `approved`. Those labels are
how the team requires review, so Tide's config is where the approval gate is
*defined* (whether it is *enforced* on GitHub is a separate fact, collected from
branch protection).

    prow_tide_gate.py <owner/repo> <branch> [_prowconfig.yaml ...]

prints one JSON object:
    queries                     Tide queries that apply to this repo and branch
    requires_approval           every query requires both `lgtm` and `approved`
    queries_without_approval    authors ("*" = anyone) of queries that do not
    holds_block_merge           every query blocks on do-not-merge/hold
    author_queries              authors with a dedicated query that requires both
                                approval labels, with any "[bot]" suffix removed

No config files, or none with an applicable query, means no Tide gate.
"""
import json
import sys

import yaml

APPROVAL_LABELS = {"lgtm", "approved"}
HOLD_LABEL = "do-not-merge/hold"


def applicable_queries(configs: list, repo: str, branch: str) -> list:
    org = repo.split("/")[0]
    out = []
    for cfg in configs:
        for q in ((cfg or {}).get("tide") or {}).get("queries") or []:
            in_scope = repo in (q.get("repos") or []) or org in (q.get("orgs") or [])
            if repo in (q.get("excludedRepos") or []):
                in_scope = False
            included, excluded = q.get("includedBranches"), q.get("excludedBranches") or []
            if included is not None and branch not in included:
                in_scope = False
            if branch in excluded:
                in_scope = False
            if in_scope:
                out.append(q)
    return out


def base_login(login: str) -> str:
    """GitHub names app accounts "name[bot]" in some places and "name" in others."""
    return login[:-5] if login.endswith("[bot]") else login


def normalize(configs: list, repo: str, branch: str) -> dict:
    queries = applicable_queries(configs, repo, branch)
    without = [q.get("author") or "*" for q in queries
               if not APPROVAL_LABELS <= set(q.get("labels") or [])]
    return {
        "queries": len(queries),
        "requires_approval": bool(queries) and not without,
        "queries_without_approval": without,
        "holds_block_merge": bool(queries) and all(HOLD_LABEL in (q.get("missingLabels") or []) for q in queries),
        "author_queries": sorted({base_login(q["author"]) for q in queries
                                  if q.get("author") and APPROVAL_LABELS <= set(q.get("labels") or [])}),
    }


def main() -> None:
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    repo, branch, files = sys.argv[1], sys.argv[2], sys.argv[3:]
    configs = [yaml.safe_load(open(f)) for f in files]
    print(json.dumps(normalize(configs, repo, branch)))


if __name__ == "__main__":
    main()
