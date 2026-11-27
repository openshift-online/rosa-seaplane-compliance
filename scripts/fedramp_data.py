"""Loader for the vendored FedRAMP consolidated rules dataset.

The dataset (mappings/vendor/fedramp/fedramp-consolidated-rules.json) is the
authority for KSI statements and their related controls. This module also
normalizes control IDs, which use different spellings across sources: the
dataset uses "cm-3.2" while the mappings use "CM-03 (02)".
"""
import json
import re
from pathlib import Path

DATASET = (Path(__file__).resolve().parent.parent
           / "mappings/vendor/fedramp/fedramp-consolidated-rules.json")

_CONTROL_RE = re.compile(r"^\s*([A-Za-z]{2})-0*(\d+)\s*(?:\(\s*0*(\d+)\s*\)|\.(\d+))?\s*$")


def normalize_control_id(raw: str) -> str:
    """Return the dataset spelling: 'CM-03 (02)' and 'cm-3.2' both give 'cm-3.2'."""
    m = _CONTROL_RE.match(raw)
    if not m:
        raise ValueError(f"unrecognized control ID: {raw!r}")
    family, num, paren_enh, dot_enh = m.groups()
    enh = paren_enh or dot_enh
    out = f"{family.lower()}-{int(num)}"
    return f"{out}.{int(enh)}" if enh is not None else out


def load_dataset(path: Path = DATASET) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_ksis(dataset: dict = None, cls: str = "c") -> dict:
    """Map KSI ID to {family, name, statement, controls} for the given class.

    Some KSIs carry their statement under varies_by_class.<class> instead of
    at the top level; a KSI with no statement for `cls` gets statement None.
    """
    dataset = dataset or load_dataset()
    ksis = {}
    for family, fam in dataset["KSI"].items():
        for ksi_id, ind in fam["indicators"].items():
            statement = ind.get("statement")
            if statement is None:
                statement = ind.get("varies_by_class", {}).get(cls, {}).get("statement")
            ksis[ksi_id] = {
                "family": family,
                "name": ind["name"],
                "statement": statement,
                "controls": [normalize_control_id(c) for c in ind.get("controls", [])],
            }
    return ksis


def related_controls(ksis: dict) -> set:
    return {c for k in ksis.values() for c in k["controls"]}
