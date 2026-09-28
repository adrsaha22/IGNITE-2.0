"""Adapter between the existing detection modules and the redesigned UI.

This module calls the detection pipeline exactly as the previous app.py did
and collects the results into one dictionary. It deliberately contains no
detection logic of its own: every rule, score, technique and finding comes
from the existing modules, so nothing displayed is fabricated here.

The only additions are presentational: resolving MITRE technique IDs to their
official names via the already-loaded ATT&CK data, and flagging contradictions
that the underlying validator reports but does not itself reconcile.
"""

from datetime import datetime, timezone
from typing import Any

from modules.autonomous_rule_generator import generate_autonomous_rule
from modules.detection_engine import generate_detections
from modules.entity_extractor import extract_entities
from modules.explanation_engine import explain_detection
from modules.false_positive_reducer import reduce_false_positives
from modules.mitre_rule_builder import build_mitre_rule
from modules.rule_builder import build_splunk_rule
from modules.rule_quality import evaluate_rule_quality
from modules.rule_selector import select_best_rule
from modules.rule_validator import validate_rule
from modules.technique_mapper import map_attack_to_techniques
from modules.telemetry_engine import get_telemetry
from modules.telemetry_rule_builder import build_telemetry_rule

# Labels for the ranked candidates, in the order app.py assembles them.
BEHAVIOR_LABEL = "Entity-derived rule"
MITRE_LABEL = "MITRE context rule"
SIGMA_LABEL = "Sigma-derived rule"


def technique_name(technique_id: str) -> str:
    """Resolve a MITRE technique ID to its official name.

    Reads the ATT&CK bundle already loaded by modules.mitre_lookup. Returns an
    empty string when the ID is absent rather than inventing a name.
    """
    try:
        from modules.mitre_lookup import MITRE_DATA

        entry = MITRE_DATA.get(technique_id)
        if entry:
            return str(entry.get("name", ""))
    except Exception:
        pass
    return ""


def _rule_origin(rule_text: str, behavior_rule: str, mitre_rule: str) -> str:
    """Label where a ranked candidate came from, by identity with its source."""
    if rule_text == behavior_rule:
        return BEHAVIOR_LABEL
    if rule_text == mitre_rule:
        return MITRE_LABEL
    return SIGMA_LABEL


def _has_conditions(rule_text: str) -> bool:
    """Whether a generated query contains any field condition at all.

    A rule built from a technique with no knowledge-base entry can come back
    with an empty ``()`` group, which would match far too broadly. This is a
    static text observation, not a syntax validation.
    """
    text = rule_text or ""
    return "=" in text.replace("index=", "").replace("EventCode=", "")


def run_analysis(description: str) -> dict[str, Any]:
    """Run the full detection pipeline and return everything the UI renders.

    Raises whatever the underlying modules raise; the caller handles failure.
    """
    # --- Sigma / MITRE pipeline -------------------------------------------
    sigma_result = generate_detections(description)

    # --- Entity extraction and template builders -------------------------
    entities = extract_entities(description)
    behavior_rule = build_splunk_rule(entities)
    mitre_rule = build_mitre_rule(sigma_result["mitre_id"])

    sigma_rules = [d["spl"] for d in sigma_result["detections"]]

    candidates = [behavior_rule, mitre_rule] + sigma_rules
    ranked = select_best_rule(candidates)

    # Attach provenance and a static breadth observation to each candidate.
    for item in ranked:
        item["origin"] = _rule_origin(item["rule"], behavior_rule, mitre_rule)
        item["has_conditions"] = _has_conditions(item["rule"])

    best = ranked[0] if ranked else {"rule": "", "score": 0, "origin": "", "has_conditions": False}

    # --- Autonomous engine ------------------------------------------------
    # Mirrors the previous app.py ordering. Failures here are reported by the
    # caller; they do not invalidate the Sigma/entity results above.
    autonomous: dict[str, Any] = {"available": False, "error": None}
    try:
        techniques = map_attack_to_techniques(description)
        telemetry = get_telemetry(techniques)
        telemetry_rule = build_telemetry_rule(telemetry)

        autonomous_rule = reduce_false_positives(generate_autonomous_rule(techniques))

        validation = validate_rule(autonomous_rule)
        quality = evaluate_rule_quality(autonomous_rule)
        explanation = explain_detection(description, techniques, autonomous_rule)

        autonomous = {
            "available": True,
            "error": None,
            "techniques": techniques,
            "technique_names": {t: technique_name(t) for t in techniques},
            "telemetry": telemetry,
            "telemetry_rule": telemetry_rule,
            "rule": autonomous_rule,
            "rule_has_conditions": _has_conditions(autonomous_rule),
            "validation": validation,
            "quality": quality,
            "explanation": explanation,
        }
    except Exception as exc:  # surfaced in the Validation tab
        autonomous = {
            "available": False,
            "error": f"{type(exc).__name__}: {exc}",
            "techniques": [],
            "technique_names": {},
            "telemetry": {},
            "telemetry_rule": "",
            "rule": "",
            "rule_has_conditions": False,
            "validation": {},
            "quality": {},
            "explanation": "",
        }

    return {
        "description": description,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sigma": sigma_result,
        "mitre_id": sigma_result["mitre_id"],
        "mitre_name": sigma_result["mitre_name"],
        "entities": entities,
        "ranked": ranked,
        "best": best,
        "autonomous": autonomous,
    }


def validation_warnings(analysis: dict) -> list[str]:
    """Collect findings that deserve prominence regardless of the valid flag.

    The underlying validator can return ``valid: true`` while also listing
    issues such as "No attack indicators found". Rather than hiding those
    behind the boolean, they are surfaced here.
    """
    warnings: list[str] = []
    auto = analysis.get("autonomous", {})
    validation = auto.get("validation") or {}

    issues = validation.get("issues") or []
    if validation.get("valid") and issues:
        warnings.append(
            "Marked valid, but the validator still reported "
            f"{len(issues)} issue(s) — review them below."
        )

    if auto.get("available") and not auto.get("rule_has_conditions"):
        warnings.append(
            "The autonomous rule contains no field conditions, so it would match "
            "far more events than intended. This usually means no knowledge-base "
            "entry exists for the mapped technique(s)."
        )

    if not analysis.get("sigma", {}).get("detections"):
        warnings.append(
            "No Sigma rules were matched — the data/sigma directory appears to be empty."
        )

    if analysis.get("mitre_id") == "Unknown":
        warnings.append(
            "The attack description did not match any known keyword, so no MITRE "
            "technique was mapped."
        )

    best = analysis.get("best") or {}
    if best.get("rule") and not best.get("has_conditions"):
        warnings.append(
            "The top-ranked rule contains no field conditions and would be "
            "unacceptably broad in production."
        )

    return warnings


def export_payload(analysis: dict) -> dict[str, Any]:
    """Build the JSON export for the analysis currently held in state."""
    auto = analysis.get("autonomous", {})
    return {
        "metadata": {
            "tool": "IGNITE 2.0 — AI Detection Rule Generator",
            "generated_at": analysis.get("generated_at"),
            "attack_description": analysis.get("description"),
            "query_language": "Splunk SPL",
            "rule_status": "generated — not validated against a live Splunk instance",
        },
        "mitre": {
            "primary_technique_id": analysis.get("mitre_id"),
            "primary_technique_name": analysis.get("mitre_name"),
            "mapped_techniques": [
                {"id": t, "name": auto.get("technique_names", {}).get(t, "")}
                for t in auto.get("techniques", [])
            ],
        },
        "entities": analysis.get("entities", {}),
        "best_rule": {
            "spl": (analysis.get("best") or {}).get("rule", ""),
            "score": (analysis.get("best") or {}).get("score", 0),
            "origin": (analysis.get("best") or {}).get("origin", ""),
        },
        "candidate_rules": [
            {"spl": r.get("rule", ""), "score": r.get("score", 0), "origin": r.get("origin", "")}
            for r in analysis.get("ranked", [])
        ],
        "autonomous_engine": {
            "available": auto.get("available", False),
            "error": auto.get("error"),
            "rule": auto.get("rule", ""),
            "telemetry_rule": auto.get("telemetry_rule", ""),
            "telemetry": auto.get("telemetry", {}),
            "validation": auto.get("validation", {}),
            "quality": auto.get("quality", {}),
            "explanation": auto.get("explanation", ""),
        },
        "warnings": validation_warnings(analysis),
        "sigma_references": [
            {
                "title": d.get("title", ""),
                "spl": d.get("spl", ""),
                "tags": d.get("tags", []),
                "logsource": d.get("logsource", {}),
                "score": d.get("score"),
                "status": d.get("status"),
            }
            for d in analysis.get("sigma", {}).get("detections", [])
        ],
    }
