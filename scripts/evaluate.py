"""Measure generation quality on held-out techniques.

Each test example comes from a technique the retriever has never seen (the
dataset is split by technique). The ATT&CK technique is hidden from the
request, so the model must map it itself.

    ./venv/bin/python scripts/evaluate.py --limit 10

Every example is at least one provider request (more if repairs run), so this
spends real quota. Results are written to data/knowledge/evaluation.json and
shown on the Platform page.
"""

import argparse
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from api.services import knowledge, llm, rule_generator  # noqa: E402
from api.settings import KNOWLEDGE_DIR  # noqa: E402


def scenario_from_example(example: dict) -> str:
    match = re.search(r"Behavior to detect:\s*(.*)", example["input"])
    source = re.search(r"Available data source:\s*(.*)", example["input"])
    text = match.group(1).strip() if match else example["input"]
    if source and source.group(1).strip() != "unspecified":
        text += f" (data source: {source.group(1).strip()})"
    return text


def evaluate(limit: int, pause: float) -> dict:
    examples = knowledge.load_split("test")[:limit]
    if not examples:
        sys.exit("The test split is empty. Build the dataset first (scripts/build_dataset.py).")

    rows = []
    for index, example in enumerate(examples, 1):
        title = example["output"].get("title", example.get("id"))
        print(f"[{index}/{len(examples)}] {title}")
        expected = set(example["output"]["mitre"]["technique_ids"])
        expected_parents = {t.split(".")[0] for t in expected}

        result = rule_generator.generate_candidates(scenario_from_example(example))
        best = result.candidates[0] if result.candidates else None
        predicted = {m["id"] for m in (best.attack_mappings if best else []) if m.get("reference_verified")}
        validation = best.validation if best else {}
        repairs = best.provenance.get("repair_attempts", 0) if best else 0
        rows.append(
            {
                "example": title,
                "status": result.status,
                "expected_mitre": sorted(expected),
                "predicted_mitre": sorted(predicted),
                "mitre_exact": bool(expected & predicted),
                "mitre_parent": bool(expected_parents & {t.split(".")[0] for t in predicted}),
                "all_checks_passed": bool(validation.get("passed")),
                "first_try_pass": bool(validation.get("passed")) and repairs == 0,
                "quality_score": validation.get("quality_score", 0),
                "repair_attempts": repairs,
                "failed_checks": validation.get("failures", []),
            }
        )
        time.sleep(pause)

    n = len(rows)
    generated = [r for r in rows if r["status"] == "ok"]
    summary = {
        "evaluated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "provider": llm.provider_label(),
        "model": llm.active_model(),
        "examples": n,
        "generation_success_rate": len(generated) / n,
        "validation_pass_rate": sum(r["all_checks_passed"] for r in rows) / n,
        "first_try_pass_rate": sum(r["first_try_pass"] for r in rows) / n,
        "mitre_exact_match": sum(r["mitre_exact"] for r in rows) / n,
        "mitre_parent_match": sum(r["mitre_parent"] for r in rows) / n,
        "avg_quality_score": sum(r["quality_score"] for r in rows) / n,
        "avg_repair_attempts": sum(r["repair_attempts"] for r in rows) / n,
        "knowledge_base": knowledge.dataset_stats()["location"],
    }
    return {"summary": summary, "rows": rows}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--limit", type=int, default=10, help="number of test examples (default 10)")
    parser.add_argument("--pause", type=float, default=1.0, help="seconds between requests (rate limits)")
    args = parser.parse_args()

    if not llm.is_configured():
        sys.exit(llm.status_message(llm.LLMStatus.NOT_CONFIGURED))

    report = evaluate(args.limit, args.pause)
    out = KNOWLEDGE_DIR / "evaluation.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report["summary"], indent=2))
    print(f"Written to {out}")
