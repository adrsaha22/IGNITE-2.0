"""Rule library, review workflow, version history and audit log.

Lifecycle::

    generated ──► draft ──► approved ──► deployed (disabled / shadow / live)
                    │           │
                    ▼           └── edit ──► back to draft (re-approval needed)
                rejected

Governance rules enforced here, not in the UI:

* Everything is re-verified server-side. A candidate posted by the browser is
  re-checked against ATT&CK and re-scored; client-supplied scores are ignored.
* Approving a rule that still fails a quality check requires a written
  override justification, which is recorded with the approval.
* Only approved rules can be deployed, and editing an approved rule returns it
  to draft.
* Every edit stores the previous version, and edits use optimistic locking so
  two reviewers cannot silently overwrite each other.
* The audit log is append-only: SQLite triggers reject UPDATE and DELETE.

Stored in the same SQLite file as saved investigations.
"""

from __future__ import annotations

import csv
import getpass
import io
import json
import logging
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator

from api import settings
from api.services import attack, splunk_client, store, validators
from api.services.sigma_tools import sigma_to_spl

logger = logging.getLogger(__name__)

STATUSES = ("draft", "approved", "rejected")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS rules (
    id              TEXT PRIMARY KEY,
    title           TEXT NOT NULL,
    status          TEXT NOT NULL,
    severity        TEXT NOT NULL DEFAULT '',
    quality_score   INTEGER NOT NULL DEFAULT 0,
    passed          INTEGER NOT NULL DEFAULT 0,
    technique_ids   TEXT NOT NULL DEFAULT '[]',
    deployment_mode TEXT NOT NULL DEFAULT '',
    version         INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    created_by      TEXT NOT NULL,
    payload         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rules_updated ON rules (updated_at DESC);

CREATE TABLE IF NOT EXISTS rule_versions (
    rule_id   TEXT NOT NULL,
    version   INTEGER NOT NULL,
    saved_at  TEXT NOT NULL,
    actor     TEXT NOT NULL,
    payload   TEXT NOT NULL,
    PRIMARY KEY (rule_id, version)
);

CREATE TABLE IF NOT EXISTS audit_log (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    at          TEXT NOT NULL,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    rule_id     TEXT NOT NULL DEFAULT '',
    rule_title  TEXT NOT NULL DEFAULT '',
    detail      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_log (seq DESC);

CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'The audit log is append-only.'); END;
CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'The audit log is append-only.'); END;
"""

# Fields an analyst may change when editing a rule.
EDITABLE_FIELDS = (
    "title",
    "description",
    "spl",
    "sigma_rule",
    "severity",
    "benign_near_matches",
    "response_actions",
    "how_to_implement",
    "attack_mappings",
)


class LibraryError(Exception):
    """A rejected library operation. `status_code` maps onto HTTP."""

    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def current_actor() -> str:
    """Who is acting. There is no login yet, so this is the API operator.

    Replace this one function when SSO is added; every audit entry and review
    record goes through it.
    """
    if settings.OPERATOR_NAME:
        return settings.OPERATOR_NAME
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


@contextmanager
def _connect() -> Iterator[Any]:
    with store._connect() as connection:
        connection.executescript(_SCHEMA)
        yield connection


# --------------------------------------------------------------------- audit


def log_event(action: str, rule: dict | None = None, detail: str = "", connection: Any = None) -> None:
    row = (
        _now(),
        current_actor(),
        action,
        (rule or {}).get("id", ""),
        (rule or {}).get("title", ""),
        detail[:2000],
    )
    sql = "INSERT INTO audit_log (at, actor, action, rule_id, rule_title, detail) VALUES (?, ?, ?, ?, ?, ?)"
    if connection is not None:
        connection.execute(sql, row)
        return
    with _connect() as conn:
        conn.execute(sql, row)


def list_audit(limit: int = 500, action: str = "", rule_id: str = "") -> list[dict[str, Any]]:
    clauses, params = [], []
    if action:
        clauses.append("action = ?")
        params.append(action)
    if rule_id:
        clauses.append("rule_id = ?")
        params.append(rule_id)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with _connect() as conn:
        rows = conn.execute(
            f"SELECT * FROM audit_log {where} ORDER BY seq DESC LIMIT ?", (*params, max(1, min(limit, 5000)))
        ).fetchall()
    return [dict(row) for row in rows]


def audit_csv() -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["seq", "at", "actor", "action", "rule_id", "rule_title", "detail"])
    for row in list_audit(limit=5000):
        writer.writerow([row[k] for k in ("seq", "at", "actor", "action", "rule_id", "rule_title", "detail")])
    return buffer.getvalue()


# ------------------------------------------------------------------- helpers


def _verify_mappings(proposed: Any) -> list[dict[str, Any]]:
    items = proposed if isinstance(proposed, list) else []
    verdicts = attack.verify_mappings(
        [{"id": str(m.get("id", "")), "evidence": str(m.get("evidence", ""))} for m in items if isinstance(m, dict)]
    )
    return [
        {
            "id": v.id,
            "name": v.name,
            "reference_verified": v.reference_verified,
            "mapping_supported": v.mapping_supported,
            "status": v.status,
            "evidence": v.evidence,
            "note": v.note,
            "is_subtechnique": v.is_subtechnique,
            "tactics": list(v.tactics),
        }
        for v in verdicts
    ]


def _str_list(value: Any, limit: int = 30) -> list[str]:
    if isinstance(value, str):
        value = [line for line in value.splitlines()]
    if not isinstance(value, list):
        return []
    return [str(v).strip()[:1000] for v in value[:limit] if str(v).strip()]


def _splunk_or_none() -> Any:
    if not splunk_client.is_configured():
        return None
    try:
        return splunk_client.SplunkClient()
    except splunk_client.SplunkError:
        return None


def _revalidate(rule: dict, run_test: bool = False, earliest: str = "-24h") -> dict:
    """Recompute every check on the server. Client-supplied scores are ignored."""
    splunk = _splunk_or_none() if (run_test or splunk_client.is_configured()) else None
    if run_test and splunk is None:
        raise LibraryError("A test search needs a configured, reachable Splunk instance.", 409)
    checks = validators.run_all(
        rule,
        splunk=splunk,
        run_test=run_test,
        test_earliest=earliest,
        noisy_threshold=settings.NOISY_RESULT_THRESHOLD,
    )
    rule["validation"] = validators.summarize(checks)
    rule["validation"]["validated_at"] = _now()
    converted, _ = sigma_to_spl(rule["sigma_rule"]) if rule.get("sigma_rule") else (None, None)
    rule["spl_from_sigma"] = converted or ""
    return rule


def _technique_ids(rule: dict) -> list[str]:
    return [m["id"] for m in rule.get("attack_mappings", []) if m.get("reference_verified")]


def _row_values(rule: dict) -> tuple:
    validation = rule.get("validation") or {}
    return (
        rule["title"],
        rule["status"],
        rule.get("severity", ""),
        int(validation.get("quality_score", 0)),
        1 if validation.get("passed") else 0,
        json.dumps(_technique_ids(rule)),
        (rule.get("deployment") or {}).get("mode", ""),
        rule["version"],
        rule["updated_at"],
        json.dumps(rule, ensure_ascii=False),
    )


def _summary(row: Any) -> dict[str, Any]:
    payload = json.loads(row["payload"])
    validation = payload.get("validation") or {}
    deployment = payload.get("deployment") or {}
    return {
        "id": row["id"],
        "title": row["title"],
        "status": row["status"],
        "severity": row["severity"],
        "quality_score": row["quality_score"],
        "quality_grade": validation.get("quality_grade", ""),
        "passed": bool(row["passed"]),
        "technique_ids": json.loads(row["technique_ids"]),
        "deployment_mode": row["deployment_mode"],
        "deployment_stale": bool(deployment.get("stale")),
        "version": row["version"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "created_by": row["created_by"],
        "demo": (payload.get("provenance") or {}).get("generator") == "template",
    }


def _load(conn: Any, rule_id: str) -> dict:
    row = conn.execute("SELECT payload FROM rules WHERE id = ?", (rule_id,)).fetchone()
    if row is None:
        raise LibraryError("Rule not found.", 404)
    return json.loads(row["payload"])


def _persist(conn: Any, rule: dict) -> None:
    conn.execute(
        """UPDATE rules SET title = ?, status = ?, severity = ?, quality_score = ?, passed = ?,
           technique_ids = ?, deployment_mode = ?, version = ?, updated_at = ?, payload = ?
           WHERE id = ?""",
        (*_row_values(rule), rule["id"]),
    )


def _snapshot(conn: Any, rule: dict) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO rule_versions (rule_id, version, saved_at, actor, payload) VALUES (?, ?, ?, ?, ?)",
        (rule["id"], rule["version"], _now(), current_actor(), json.dumps(rule, ensure_ascii=False)),
    )


# ------------------------------------------------------------------- library


def save_candidate(candidate: dict[str, Any], scenario: str) -> dict:
    """Store a generated candidate as a draft rule, re-verified server-side."""
    spl = str(candidate.get("spl", "")).strip()
    if not spl:
        raise LibraryError("The candidate has no SPL query.")
    now = _now()
    actor = current_actor()
    provenance = candidate.get("provenance") if isinstance(candidate.get("provenance"), dict) else {}
    severity = str(candidate.get("severity", "")).strip().lower()
    rule: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "title": str(candidate.get("name") or "Untitled detection").strip()[:200],
        "description": str(candidate.get("purpose", "")).strip()[:2000],
        "scenario": str(scenario or "").strip()[:8000],
        "spl": spl[:20000],
        "sigma_rule": str(candidate.get("sigma_rule") or "").strip()[:20000],
        "spl_from_sigma": "",
        "severity": severity if severity in validators.SEVERITIES else "",
        "attack_mappings": _verify_mappings(candidate.get("attack_mappings")),
        "log_source": candidate.get("log_source") if isinstance(candidate.get("log_source"), dict) else {},
        "hypothesis": str(candidate.get("hypothesis", "")).strip()[:2000],
        "assumptions": _str_list(candidate.get("assumptions")),
        "blind_spots": _str_list(candidate.get("blind_spots")),
        "required_telemetry": _str_list(candidate.get("required_telemetry")),
        "benign_near_matches": _str_list(candidate.get("benign_near_matches")),
        "response_actions": _str_list(candidate.get("response_actions")),
        "how_to_implement": str(candidate.get("how_to_implement") or "").strip()[:2000],
        "references": _str_list(candidate.get("references")),
        "provenance": provenance,
        "status": "draft",
        "review": None,
        "deployment": None,
        "version": 1,
        "created_at": now,
        "updated_at": now,
        "created_by": actor,
    }
    _revalidate(rule)

    with _connect() as conn:
        conn.execute(
            """INSERT INTO rules (title, status, severity, quality_score, passed, technique_ids,
               deployment_mode, version, updated_at, payload, id, created_at, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (*_row_values(rule), rule["id"], now, actor),
        )
        _snapshot(conn, rule)
        validation = rule["validation"]
        outcome = (
            "all checks passed"
            if validation["passed"]
            else f"{len(validation['failures'])} failing check(s)"
        )
        log_event("saved", rule, f"Saved as draft — quality {validation['quality_score']}/100 ({outcome}).", conn)
    return rule


def list_rules(status: str = "", query: str = "") -> list[dict[str, Any]]:
    clauses, params = [], []
    if status:
        clauses.append("status = ?")
        params.append(status)
    if query.strip():
        clauses.append("(LOWER(title) LIKE ? OR LOWER(technique_ids) LIKE ?)")
        needle = f"%{query.strip().lower()}%"
        params += [needle, needle]
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with _connect() as conn:
        rows = conn.execute(f"SELECT * FROM rules {where} ORDER BY updated_at DESC", params).fetchall()
    return [_summary(row) for row in rows]


def get_rule(rule_id: str) -> dict:
    with _connect() as conn:
        rule = _load(conn, rule_id)
        versions = conn.execute(
            "SELECT version, saved_at, actor FROM rule_versions WHERE rule_id = ? ORDER BY version DESC",
            (rule_id,),
        ).fetchall()
    rule["versions"] = [dict(v) for v in versions]
    return rule


def get_version(rule_id: str, version: int) -> dict:
    with _connect() as conn:
        row = conn.execute(
            "SELECT payload FROM rule_versions WHERE rule_id = ? AND version = ?", (rule_id, version)
        ).fetchone()
    if row is None:
        raise LibraryError("That version does not exist.", 404)
    return json.loads(row["payload"])


def update_rule(rule_id: str, changes: dict[str, Any], expected_version: int, note: str = "") -> dict:
    """Edit a rule. Re-runs every check; an approved rule returns to draft."""
    with _connect() as conn:
        rule = _load(conn, rule_id)
        if rule["version"] != expected_version:
            raise LibraryError(
                f"This rule was changed by someone else (now version {rule['version']}). "
                "Reload it and re-apply your edit.",
                409,
            )
        changed = []
        for key in EDITABLE_FIELDS:
            if key not in changes or changes[key] is None:
                continue
            value = changes[key]
            if key == "attack_mappings":
                value = _verify_mappings(value)
            elif key in ("benign_near_matches", "response_actions"):
                value = _str_list(value)
            elif key == "severity":
                value = str(value).strip().lower()
                if value and value not in validators.SEVERITIES:
                    raise LibraryError(f"Severity must be one of {sorted(validators.SEVERITIES)}.")
            else:
                value = str(value).strip()
            if key in ("title", "spl") and not value:
                raise LibraryError(f"The {key} cannot be empty.")
            if value != rule.get(key):
                rule[key] = value
                changed.append(key)

        if not changed:
            return get_rule(rule_id)

        previous_status = rule["status"]
        _revalidate(rule)
        rule["version"] += 1
        rule["updated_at"] = _now()
        if previous_status == "approved":
            rule["status"] = "draft"
            rule["review"] = None
        if rule.get("deployment"):
            # Splunk still runs the previously deployed version.
            rule["deployment"]["stale"] = True
        _persist(conn, rule)
        _snapshot(conn, rule)
        detail = f"Edited {', '.join(changed)}; quality now {rule['validation']['quality_score']}/100."
        if previous_status == "approved":
            detail += " Returned to draft for re-approval."
        if note:
            detail += f" Note: {note[:500]}"
        log_event("edited", rule, detail, conn)
    return get_rule(rule_id)


def review(rule_id: str, decision: str, note: str = "", override_justification: str = "") -> dict:
    if decision not in ("approve", "reject"):
        raise LibraryError("Decision must be 'approve' or 'reject'.")
    with _connect() as conn:
        rule = _load(conn, rule_id)
        validation = rule.get("validation") or {}
        override = False
        if decision == "approve":
            if not validation.get("passed"):
                if len(override_justification.strip()) < settings.OVERRIDE_MIN_CHARS:
                    raise LibraryError(
                        "This rule still fails quality checks. Approving it needs a written override "
                        f"justification of at least {settings.OVERRIDE_MIN_CHARS} characters.",
                        422,
                    )
                override = True
            rule["status"] = "approved"
        else:
            if len(note.strip()) < 5:
                raise LibraryError("Rejecting a rule needs a short note explaining why.", 422)
            rule["status"] = "rejected"
        rule["review"] = {
            "decision": decision,
            "by": current_actor(),
            "at": _now(),
            "note": note.strip()[:2000],
            "override": override,
            "override_justification": override_justification.strip()[:2000] if override else "",
            "quality_score": validation.get("quality_score"),
            "version": rule["version"],
        }
        rule["updated_at"] = _now()
        _persist(conn, rule)
        detail = note.strip()[:500]
        if override:
            detail = (
                f"OVERRIDE with {len(validation.get('failures', []))} failing check(s): "
                f"{override_justification.strip()[:500]}" + (f" | {detail}" if detail else "")
            )
        log_event("approved" if decision == "approve" else "rejected", rule, detail, conn)
    return get_rule(rule_id)


def revalidate(rule_id: str, run_test: bool = False, earliest: str = "-24h") -> dict:
    with _connect() as conn:
        rule = _load(conn, rule_id)
    _revalidate(rule, run_test=run_test, earliest=earliest)
    with _connect() as conn:
        _persist(conn, rule)
        detail = f"Quality {rule['validation']['quality_score']}/100."
        if run_test:
            test = next((c for c in rule["validation"]["checks"] if c["name"] == "Test search"), None)
            if test:
                detail += f" Test search ({earliest}): {test['detail']}"
        log_event("revalidated", rule, detail, conn)
    return get_rule(rule_id)


def deploy(
    rule_id: str,
    mode: str,
    cron: str = "*/15 * * * *",
    earliest: str = "-20m",
    actions: str = "",
) -> dict:
    if mode not in splunk_client.DEPLOY_MODES:
        raise LibraryError(f"Mode must be one of {sorted(splunk_client.DEPLOY_MODES)}.")
    with _connect() as conn:
        rule = _load(conn, rule_id)
    if rule["status"] != "approved":
        raise LibraryError("Only approved rules can be deployed.", 409)
    if not splunk_client.is_configured():
        raise LibraryError("Splunk is not configured on the backend.", 409)
    try:
        result = splunk_client.SplunkClient().deploy(
            title=rule["title"],
            spl=rule["spl"],
            description=rule.get("description", ""),
            technique_ids=_technique_ids(rule),
            severity=rule.get("severity", ""),
            mode=mode,
            cron=cron,
            earliest=earliest,
            actions=actions,
        )
    except splunk_client.SplunkError as exc:
        log_event("deploy_failed", rule, str(exc))
        raise LibraryError(str(exc), 502) from exc

    rule["deployment"] = {
        **result,
        "at": _now(),
        "by": current_actor(),
        "cron": cron,
        "earliest": earliest,
        "version": rule["version"],
        "stale": False,
    }
    rule["updated_at"] = _now()
    with _connect() as conn:
        _persist(conn, rule)
        log_event(
            "deployed",
            rule,
            f"{result['action'].title()} saved search '{result['name']}' in app '{result['app']}' "
            f"as {mode} (cron {cron}, window {earliest}).",
            conn,
        )
    return get_rule(rule_id)


def delete_rule(rule_id: str) -> None:
    with _connect() as conn:
        rule = _load(conn, rule_id)
        conn.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
        detail = ""
        if rule.get("deployment"):
            detail = (
                f"The saved search '{rule['deployment'].get('name')}' was NOT removed from Splunk; "
                "disable it there."
            )
        log_event("deleted", rule, detail, conn)


def counts() -> dict[str, int]:
    with _connect() as conn:
        rows = conn.execute("SELECT status, COUNT(*) AS n FROM rules GROUP BY status").fetchall()
        deployed = conn.execute("SELECT COUNT(*) AS n FROM rules WHERE deployment_mode != ''").fetchone()
    result = {status: 0 for status in STATUSES}
    result.update({row["status"]: row["n"] for row in rows})
    result["deployed"] = deployed["n"]
    return result


def all_rules_full() -> list[dict]:
    with _connect() as conn:
        rows = conn.execute("SELECT payload FROM rules").fetchall()
    return [json.loads(row["payload"]) for row in rows]


# ------------------------------------------------- learning from approvals


def approved_examples() -> list[dict]:
    """Approved rules in knowledge-base format, used as retrieval references."""
    out = []
    for rule in all_rules_full():
        if rule.get("status") != "approved":
            continue
        tids = _technique_ids(rule)
        names = ", ".join(m.get("name", "") for m in rule.get("attack_mappings", []) if m.get("name"))
        out.append(
            {
                "id": f"approved:{rule['id']}:{rule['version']}",
                "split_key": tids[0].split(".")[0] if tids else "",
                "input": (
                    f"Create a Splunk detection rule for MITRE ATT&CK {', '.join(tids)} ({names}).\n"
                    f"Behavior to detect: {rule.get('scenario') or rule.get('description', '')}"
                ),
                "output": {
                    "title": rule.get("title"),
                    "description": rule.get("description"),
                    "mitre": {"technique_ids": tids, "technique_name": names},
                    "data_source": [
                        str(v) for v in ((rule.get("log_source") or {}).get("sourcetype"),) if v
                    ],
                    "sigma_rule": rule.get("sigma_rule"),
                    "spl_query": rule.get("spl"),
                    "false_positives": rule.get("benign_near_matches", []),
                    "severity": rule.get("severity"),
                },
                "meta": {"source": "approved"},
            }
        )
    return out
