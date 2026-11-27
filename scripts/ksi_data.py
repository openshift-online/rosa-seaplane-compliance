"""Loaders for the project's KSI scope buckets, KSI records and repo scope.

Records live in mappings/fedramp-20x/ksi/<KSI-ID>.yaml (see PLAN.md, "KSI
record"). They hold only what cannot be derived from the mappings, policy or
scan results: the SDR explanations and per-control exceptions.
"""
from pathlib import Path

import yaml

import fedramp_data

ROOT = Path(__file__).resolve().parent.parent
SCOPE_FILE = ROOT / "mappings/fedramp-20x/ksi-scope.yaml"
RECORD_DIR = ROOT / "mappings/fedramp-20x/ksi"
REPO_SCOPE_FILE = ROOT / "config/scope.yaml"

BUCKETS = ("automatable", "hybrid", "process")
DECISIONS = ("not-applicable", "inherited")
RECORD_KEYS = {
    "ksi", "target-types", "measures", "automation-verification",
    "validation", "control-decisions",
}


class RecordError(ValueError):
    pass


def load_scope(path: Path = SCOPE_FILE) -> dict:
    """Bucket name -> list of KSI IDs."""
    doc = yaml.safe_load(path.read_text()) or {}
    return {b: list(doc.get(b) or []) for b in BUCKETS}


def check_scope(scope: dict, ksis: dict) -> None:
    """Every dataset KSI is in exactly one bucket, and no bucket names a stranger."""
    seen = {}
    for bucket, ids in scope.items():
        for k in ids:
            if k in seen:
                raise RecordError(f"{k} is in both {seen[k]} and {bucket}")
            seen[k] = bucket
    unknown = sorted(set(seen) - set(ksis))
    if unknown:
        raise RecordError(f"scope names unknown KSIs: {', '.join(unknown)}")
    missing = sorted(set(ksis) - set(seen))
    if missing:
        raise RecordError(f"KSIs missing from scope: {', '.join(missing)}")


def load_repo_scope(path: Path = REPO_SCOPE_FILE) -> list:
    doc = yaml.safe_load(path.read_text()) or {}
    return list(doc.get("github-repositories") or [])


def validate_record(record: dict, ksis: dict) -> dict:
    """Return the record with control IDs normalized, or raise RecordError."""
    if not isinstance(record, dict):
        raise RecordError("record must be a mapping")
    extra = sorted(set(record) - RECORD_KEYS)
    if extra:
        raise RecordError(f"unknown record fields: {', '.join(extra)}")
    ksi = record.get("ksi")
    if ksi not in ksis:
        raise RecordError(f"unknown KSI: {ksi!r}")
    out = dict(record)
    decisions = {}
    related = set(ksis[ksi]["controls"])
    for raw_id, d in (record.get("control-decisions") or {}).items():
        try:
            cid = fedramp_data.normalize_control_id(str(raw_id))
        except ValueError as e:
            raise RecordError(f"{ksi}: {e}") from None
        if cid not in related:
            raise RecordError(f"{ksi}: {cid} is not a related control of this KSI")
        if not isinstance(d, dict) or d.get("decision") not in DECISIONS:
            raise RecordError(f"{ksi}: {cid} decision must be one of {', '.join(DECISIONS)}")
        if not str(d.get("rationale") or "").strip():
            raise RecordError(f"{ksi}: {cid} exception has no rationale")
        decisions[cid] = {"decision": d["decision"], "rationale": d["rationale"].strip()}
    out["control-decisions"] = decisions
    return out


def load_records(ksis: dict, record_dir: Path = RECORD_DIR) -> dict:
    """KSI ID -> validated record. The file name must match the KSI it holds."""
    records = {}
    for path in sorted(record_dir.glob("KSI-*.yaml")):
        rec = validate_record(yaml.safe_load(path.read_text()), ksis)
        if rec["ksi"] != path.stem:
            raise RecordError(f"{path.name} holds a record for {rec['ksi']}")
        records[rec["ksi"]] = rec
    return records


PENDING_MARKER = "[Proposed, pending review]"


def narrative_written(record: dict) -> bool:
    """True when all three SDR explanations are non-empty and reviewed.

    Text that still carries the pending-review marker was drafted but not yet read
    by a person, so it does not count as written.
    """
    texts = [str(record.get(k) or "").strip() for k in ("measures", "automation-verification", "validation")]
    return all(texts) and not any(PENDING_MARKER in t for t in texts)
