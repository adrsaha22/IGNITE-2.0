"""Import rules from the earlier IGNITE-Streamlit project into the rule library.

    ./venv/bin/python scripts/import_streamlit_history.py PATH/TO/ignite/data/history/rules.jsonl

Every imported rule arrives as a draft and is re-verified and re-scored by this
version's checks, because approvals made under the old tool do not carry over.
ATT&CK mappings are imported without evidence, so they show as "needs review"
until an analyst confirms them. Each import is recorded in the audit log with
the rule's original status.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from api.services import library  # noqa: E402


def load_rules(path: Path) -> list[dict]:
    """Latest copy of each rule (the old library appended a line per update)."""
    rules: dict[str, dict] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rule = json.loads(line)
            rules[rule.get("id", "")] = rule
    return list(rules.values())


def to_candidate(rule: dict) -> dict:
    generator = str(rule.get("generator", ""))
    return {
        "name": rule.get("title", "Imported rule"),
        "purpose": rule.get("description", ""),
        "spl": rule.get("spl_query", ""),
        "sigma_rule": rule.get("sigma_rule", ""),
        "severity": rule.get("severity", ""),
        "attack_mappings": [{"id": t, "evidence": ""} for t in rule.get("mitre", {}).get("technique_ids", [])],
        "benign_near_matches": rule.get("false_positives", []),
        "response_actions": rule.get("response_actions", []),
        "how_to_implement": rule.get("how_to_implement", ""),
        "log_source": {"sourcetype": ", ".join(rule.get("data_source", []))},
        "provenance": {
            # Demo-mode rules were adapted from a reference, not generated.
            "generator": "template" if generator.startswith("demo") else "imported",
            "provider": generator.split(":")[0] if generator else "unknown",
            "model": generator.split(":", 1)[1] if ":" in generator else "",
            "imported_from": "ignite-streamlit",
            "original_id": rule.get("id"),
            "original_created": rule.get("created"),
        },
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("rules_jsonl", type=Path)
    args = parser.parse_args()
    if not args.rules_jsonl.is_file():
        sys.exit(f"Not found: {args.rules_jsonl}")

    imported = 0
    for old in load_rules(args.rules_jsonl):
        if not str(old.get("spl_query", "")).strip():
            print(f"Skipping '{old.get('title')}' (no SPL).")
            continue
        rule = library.save_candidate(to_candidate(old), old.get("request", {}).get("description", ""))
        library.log_event(
            "imported",
            rule,
            f"Imported from IGNITE-Streamlit (original status: {old.get('status', 'draft')}). "
            "Re-review required.",
        )
        imported += 1
        print(f"Imported '{rule['title']}' - quality {rule['validation']['quality_score']}/100")
    print(f"{imported} rule(s) imported as drafts.")
