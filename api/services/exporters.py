"""Deployable export formats for library rules.

* contentctl YAML — Splunk's detection-as-code format (ESCU style)
* savedsearches.conf — drop-in stanza for a Splunk app
* Sigma — the portable rule, for other SIEMs
* Markdown — a human-readable review report, including every quality check
* JSON — the complete record
"""

from __future__ import annotations

import json
import re
from datetime import date
from typing import Any

import yaml

from api.services.splunk_client import SEVERITY_LEVELS, saved_search_name

FORMATS = {
    "contentctl": ("yml", "application/x-yaml"),
    "savedsearches": ("conf", "text/plain"),
    "sigma": ("yml", "application/x-yaml"),
    "markdown": ("md", "text/markdown"),
    "json": ("json", "application/json"),
}


class _Literal(str):
    pass


def _literal_repr(dumper: yaml.SafeDumper, data: str) -> yaml.Node:
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")


yaml.add_representer(_Literal, _literal_repr, Dumper=yaml.SafeDumper)


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(text).lower()).strip("_")[:80] or "rule"


def _technique_ids(rule: dict) -> list[str]:
    return [m["id"] for m in rule.get("attack_mappings") or [] if m.get("reference_verified")]


def _data_sources(rule: dict) -> list[str]:
    log_source = rule.get("log_source") or {}
    return [str(v) for v in (log_source.get("sourcetype"), log_source.get("index")) if v]


def to_contentctl_yaml(rule: dict) -> str:
    """Splunk contentctl / ESCU-style detection YAML.

    Depending on your contentctl version you may need to add fields such as
    drilldown_searches or rba before running `contentctl validate`.
    """
    sources = " ".join(_data_sources(rule)).lower()
    domain = "endpoint"
    if any(k in sources for k in ("firewall", "network", "dns", "proxy", "zeek")):
        domain = "network"
    elif any(k in sources for k in ("okta", "azure", "aws", "gcp", "o365", "cloud")):
        domain = "cloud"
    doc = {
        "name": rule.get("title", ""),
        "id": rule.get("id"),
        "version": rule.get("version", 1),
        "date": date.today().isoformat(),
        "author": f"IGNITE 2.0 ({rule.get('created_by', 'unknown')})",
        "status": "production" if rule.get("status") == "approved" else "experimental",
        "type": "TTP",
        "description": rule.get("description", ""),
        "data_source": _data_sources(rule),
        "search": _Literal(rule.get("spl", "")),
        "how_to_implement": rule.get("how_to_implement", ""),
        "known_false_positives": " ".join(rule.get("benign_near_matches", [])),
        "references": [r for r in rule.get("references", []) if str(r).startswith("http")],
        "tags": {
            "analytic_story": ["IGNITE Generated Detections"],
            "asset_type": "Endpoint" if domain == "endpoint" else domain.title(),
            "mitre_attack_id": _technique_ids(rule),
            "product": ["Splunk Enterprise", "Splunk Enterprise Security", "Splunk Cloud"],
            "security_domain": domain,
        },
    }
    return yaml.dump(doc, Dumper=yaml.SafeDumper, sort_keys=False, allow_unicode=True, width=120)


def to_savedsearches_conf(rule: dict, cron: str = "*/15 * * * *", earliest: str = "-20m") -> str:
    name = saved_search_name(rule.get("title", ""))
    spl = str(rule.get("spl", "")).replace("\n", " \\\n")
    mitre = ", ".join(_technique_ids(rule))
    description = f"[{mitre}] {rule.get('description', '')}".replace("\n", " ")
    return "\n".join(
        [
            f"[{name}]",
            f"description = {description}",
            f"search = {spl}",
            "enableSched = 1",
            f"cron_schedule = {cron}",
            f"dispatch.earliest_time = {earliest}",
            "dispatch.latest_time = now",
            "counttype = number of events",
            "relation = greater than",
            "quantity = 0",
            "alert.track = 1",
            f"alert.severity = {SEVERITY_LEVELS.get(str(rule.get('severity', '')).lower(), 4)}",
            "alert.digest_mode = 1",
            "",
        ]
    )


def to_sigma_file(rule: dict) -> str:
    return str(rule.get("sigma_rule", "")).strip() + "\n"


def to_json(rule: dict) -> str:
    return json.dumps(rule, indent=2, ensure_ascii=False)


def to_markdown(rule: dict) -> str:
    validation = rule.get("validation") or {}
    checks = "\n".join(
        f"| {c['name']} | {c['status']} | {str(c['detail']).replace('|', '/')} |"
        for c in validation.get("checks", [])
    )
    mappings = "\n".join(
        f"- **{m['id']}** {m.get('name', '')} — {m.get('status', '')}"
        + (f": {m['evidence']}" if m.get("evidence") else "")
        for m in rule.get("attack_mappings", [])
    )
    fps = "\n".join(f"- {x}" for x in rule.get("benign_near_matches", []))
    actions = "\n".join(f"{i}. {x}" for i, x in enumerate(rule.get("response_actions", []), 1))
    review = rule.get("review") or {}
    deployment = rule.get("deployment") or {}
    sigma = rule.get("sigma_rule") or "_No Sigma rule._"
    return f"""# {rule.get('title', '')}

| | |
|---|---|
| Status | {rule.get('status', '')} (version {rule.get('version', 1)}) |
| Severity | {rule.get('severity') or 'not set'} |
| Quality score | {validation.get('quality_score', '–')}/100 ({validation.get('quality_grade', '–')}) |
| Created | {rule.get('created_at', '')} by {rule.get('created_by', '')} |
| Reviewed | {review.get('at', '–')} by {review.get('by', '–')} ({review.get('decision', 'not reviewed')}) |
| Deployed | {deployment.get('mode', 'not deployed')} {deployment.get('at', '')} |
| Generator | {(rule.get('provenance') or {}).get('provider', '')} {(rule.get('provenance') or {}).get('model', '')} |

## Description
{rule.get('description', '')}

## Scenario
{rule.get('scenario', '')}

## ATT&CK mapping
{mappings or '_None._'}

## Splunk SPL
```
{rule.get('spl', '')}
```

## Sigma rule
```yaml
{sigma}
```

## Known false positives
{fps or '_None listed._'}

## Response actions
{actions or '_None listed._'}

## How to implement
{rule.get('how_to_implement') or '_Not specified._'}

## Quality checks
| Check | Status | Detail |
|---|---|---|
{checks}

> These checks inspect the rule's text and structure. Passing them is not evidence that the
> rule detects the attack; validate in shadow mode against real telemetry before going live.
"""


def export(rule: dict, fmt: str) -> tuple[str, str, str]:
    """Return (filename, content, media_type) for one export format."""
    if fmt not in FORMATS:
        raise ValueError(f"Unknown export format '{fmt}'.")
    ext, media = FORMATS[fmt]
    content: dict[str, Any] = {
        "contentctl": to_contentctl_yaml,
        "savedsearches": to_savedsearches_conf,
        "sigma": to_sigma_file,
        "markdown": to_markdown,
        "json": to_json,
    }
    name = slug(rule.get("title", "rule"))
    filename = {
        "savedsearches": "savedsearches.conf",
        "sigma": f"{name}.sigma.yml",
    }.get(fmt, f"{name}.{ext}")
    return filename, content[fmt](rule), media
