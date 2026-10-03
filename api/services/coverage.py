"""ATT&CK coverage: which techniques your rules and the knowledge base cover.

Coverage levels, strongest first:

* ``deployed``  — an approved rule is deployed to Splunk
* ``approved``  — an approved rule exists, not yet deployed
* ``draft``     — only draft rules exist
* ``reference`` — no rule of yours, but the knowledge base has reference detections
* ``None``      — nothing

Sub-techniques roll up to their parent technique. Rejected rules never count.
"""

from __future__ import annotations

from typing import Any

from api.services import attack, knowledge, library

TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution", "persistence",
    "privilege-escalation", "defense-evasion", "credential-access", "discovery",
    "lateral-movement", "collection", "command-and-control", "exfiltration", "impact",
]
LEVELS = ["deployed", "approved", "draft", "reference"]
_RANK = {level: i for i, level in enumerate(LEVELS)}


def tactic_title(key: str) -> str:
    return key.replace("-", " ").title().replace("And", "and")


def _parent(tid: str) -> str:
    return str(tid).upper().split(".")[0]


def _rule_level(rule: dict) -> str | None:
    if rule.get("status") == "rejected":
        return None
    if rule.get("status") == "approved" and rule.get("deployment"):
        return "deployed"
    if rule.get("status") == "approved":
        return "approved"
    return "draft"


def _stronger(a: str | None, b: str | None) -> str | None:
    if a is None:
        return b
    if b is None:
        return a
    return a if _RANK[a] <= _RANK[b] else b


def build_coverage() -> dict[str, Any]:
    dataset = attack.load_dataset()
    cells: dict[str, dict[str, Any]] = {}

    def cell(tid: str) -> dict[str, Any]:
        return cells.setdefault(_parent(tid), {"level": None, "rules": [], "references": 0})

    for rule in library.all_rules_full():
        level = _rule_level(rule)
        if not level:
            continue
        for mapping in rule.get("attack_mappings", []):
            if not mapping.get("reference_verified"):
                continue
            entry = cell(mapping["id"])
            entry["level"] = _stronger(entry["level"], level)
            if not any(r["id"] == rule["id"] for r in entry["rules"]):
                entry["rules"].append({"id": rule["id"], "title": rule.get("title", ""), "level": level})

    for example in knowledge.load_split("train") + knowledge.load_split("val") + knowledge.load_split("test"):
        for tid in example.get("output", {}).get("mitre", {}).get("technique_ids", []):
            entry = cell(tid)
            entry["references"] += 1
            entry["level"] = _stronger(entry["level"], "reference")

    columns: dict[str, list[dict[str, Any]]] = {t: [] for t in TACTIC_ORDER}
    for technique in dataset.techniques.values():
        if technique.is_subtechnique or "enterprise-attack" not in (technique.domains or ("enterprise-attack",)):
            continue
        entry = cells.get(technique.id, {"level": None, "rules": [], "references": 0})
        for tactic in technique.tactics:
            columns.setdefault(tactic, []).append(
                {
                    "id": technique.id,
                    "name": technique.name,
                    "level": entry["level"],
                    "rules": entry["rules"][:10],
                    "rule_count": len(entry["rules"]),
                    "references": entry["references"],
                }
            )

    tactics = []
    for key in TACTIC_ORDER + sorted(k for k in columns if k not in TACTIC_ORDER):
        items = sorted(columns.get(key, []), key=lambda t: t["id"])
        if not items:
            continue
        own = sum(1 for t in items if t["level"] in ("deployed", "approved"))
        tactics.append(
            {
                "key": key,
                "title": tactic_title(key),
                "techniques": items,
                "total": len(items),
                "covered": own,
                "coverage_pct": round(100 * own / len(items)) if items else 0,
            }
        )

    unique = {t["id"]: t for column in tactics for t in column["techniques"]}
    by_level = {level: sum(1 for t in unique.values() if t["level"] == level) for level in LEVELS}
    return {
        "tactics": tactics,
        "summary": {
            "techniques": len(unique),
            "by_level": by_level,
            "covered": by_level["deployed"] + by_level["approved"],
            # One decimal so early progress (1 of 222) does not read as 0%.
            "coverage_pct": round(100 * (by_level["deployed"] + by_level["approved"]) / len(unique), 1)
            if unique
            else 0,
        },
        "attack_version": dataset.version,
    }
