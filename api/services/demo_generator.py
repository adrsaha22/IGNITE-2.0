"""Offline demo generation, for use when no LLM provider is available.

WHAT THIS IS
============
A deliberately narrow, template-based generator so the application can be
demonstrated without a provider. It is **not** a substitute for LLM
generation and never claims to be.

WHY IT REFUSES MOST SCENARIOS
=============================
The legacy template pipeline in ``modules/`` responds to any input, but for
anything outside a handful of keywords it emits::

    index=sysmon EventCode=1 | stats count by host user Image CommandLine ...

That rule contains no attack indicator and matches every process-creation
event. Returning it for, say, a ransomware scenario would present an unrelated
query as a working detection — so this module gates on a small set of
behaviours it can genuinely support, and returns an explicit
``unsupported_in_demo_mode`` result for everything else.

Every candidate produced here is labelled DEMO / TEMPLATE-BASED. Nothing is
described as LLM-generated, Splunk-validated, or proven to detect anything.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone

from api.services import attack

logger = logging.getLogger(__name__)

# Bump when a template changes.
TEMPLATE_VERSION = "demo/1"


@dataclass(frozen=True)
class DemoTemplate:
    """One hand-written detection template.

    `keywords` decide whether the template applies. `technique_id` is verified
    against the ATT&CK dataset at generation time — it is never trusted just
    because it is written here.
    """

    key: str
    name: str
    purpose: str
    spl: str
    hypothesis: str
    keywords: tuple[str, ...]
    technique_id: str
    behaviors: tuple[str, ...]
    log_source: dict
    assumptions: tuple[str, ...]
    expected_positive: tuple[str, ...]
    benign_near_matches: tuple[str, ...]
    blind_spots: tuple[str, ...]
    required_telemetry: tuple[str, ...]


# The complete set of behaviours demo mode can honestly support. Anything else
# is refused rather than answered with an unrelated rule.
TEMPLATES: tuple[DemoTemplate, ...] = (
    DemoTemplate(
        key="powershell_download",
        name="PowerShell download cradle",
        purpose="Detects PowerShell invoking a remote download in its command line.",
        spl=(
            'index=sysmon EventCode=1 Image="*\\\\powershell.exe" '
            '(CommandLine="*DownloadString*" OR CommandLine="*Invoke-WebRequest*" '
            'OR CommandLine="*Net.WebClient*")'
        ),
        hypothesis=(
            "Adversaries commonly stage a second-stage payload by invoking a "
            "download cradle from PowerShell."
        ),
        keywords=("powershell", "downloadstring", "iex", "invoke-webrequest", "webclient"),
        technique_id="T1059.001",
        behaviors=("process creation", "remote content download"),
        log_source={
            "index": "sysmon",
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            "fields": ["Image", "CommandLine", "ParentImage", "User"],
            "event_ids": [1],
        },
        assumptions=(
            "Sysmon process-creation (EventCode 1) is collected into the sysmon index.",
            "Command-line auditing is enabled and command lines are not truncated.",
        ),
        expected_positive=(
            "CommandLine contains a download cradle such as DownloadString.",
            "Image resolves to powershell.exe.",
        ),
        benign_near_matches=(
            "Administrative scripts that legitimately fetch files over HTTP.",
            "Software deployment tooling invoking Invoke-WebRequest.",
        ),
        blind_spots=(
            "Encoded or obfuscated command lines (-enc, string concatenation).",
            "Download cradles executed from a language other than PowerShell.",
        ),
        required_telemetry=("Sysmon EventCode 1 with CommandLine",),
    ),
    DemoTemplate(
        key="certutil_transfer",
        name="Certutil LOLBin transfer",
        purpose="Detects certutil.exe being used to retrieve or decode a remote file.",
        spl=(
            'index=sysmon EventCode=1 Image="*\\\\certutil.exe" '
            '(CommandLine="*-urlcache*" OR CommandLine="*-decode*" '
            'OR CommandLine="*-encode*")'
        ),
        hypothesis=(
            "certutil is a signed Windows binary frequently abused to download "
            "or decode payloads while blending into normal activity."
        ),
        keywords=("certutil", "lolbin", "urlcache", "decode"),
        technique_id="T1105",
        behaviors=("process creation", "ingress tool transfer"),
        log_source={
            "index": "sysmon",
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            "fields": ["Image", "CommandLine", "ParentImage", "User"],
            "event_ids": [1],
        },
        assumptions=(
            "Sysmon process-creation (EventCode 1) is collected into the sysmon index.",
        ),
        expected_positive=(
            "Image resolves to certutil.exe with -urlcache or -decode present.",
        ),
        benign_near_matches=(
            "PKI administration legitimately using certutil to fetch a CRL.",
            "Certificate troubleshooting that decodes a base64 certificate.",
        ),
        blind_spots=(
            "Renamed copies of certutil.exe (Image would not match).",
            "Other transfer LOLBins such as bitsadmin or curl.",
        ),
        required_telemetry=("Sysmon EventCode 1 with CommandLine",),
    ),
    DemoTemplate(
        key="scheduled_task",
        name="Scheduled task persistence",
        purpose="Detects scheduled task creation via schtasks.exe.",
        spl=(
            'index=sysmon EventCode=1 Image="*\\\\schtasks.exe" '
            'CommandLine="*/create*"'
        ),
        hypothesis=(
            "Scheduled tasks are a common persistence mechanism because they "
            "survive reboots and appear routine."
        ),
        keywords=("schtasks", "scheduled task", "task scheduler", "persistence"),
        technique_id="T1053.005",
        behaviors=("process creation", "persistence establishment"),
        log_source={
            "index": "sysmon",
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            "fields": ["Image", "CommandLine", "User"],
            "event_ids": [1],
        },
        assumptions=(
            "Sysmon process-creation (EventCode 1) is collected into the sysmon index.",
            "Task creation through the COM API or PowerShell cmdlets is not covered.",
        ),
        expected_positive=("schtasks.exe invoked with /create.",),
        benign_near_matches=(
            "Software installers registering legitimate maintenance tasks.",
            "Administrators scripting routine scheduled jobs.",
        ),
        blind_spots=(
            "Task creation via Register-ScheduledTask or the Task Scheduler COM API.",
            "Tasks created directly by writing to the Tasks folder.",
        ),
        required_telemetry=("Sysmon EventCode 1 with CommandLine",),
    ),
)

# Stated verbatim to the user when a scenario falls outside the templates.
SUPPORTED_SUMMARY = (
    "PowerShell download cradles, certutil transfers, and scheduled-task persistence"
)


def match_templates(scenario: str) -> list[tuple[DemoTemplate, list[str]]]:
    """Return templates whose keywords appear in the scenario, with the hits.

    The matched keywords become the mapping evidence, so a demo mapping is
    grounded in text the user actually supplied rather than asserted.
    """
    text = (scenario or "").lower()
    matches: list[tuple[DemoTemplate, list[str]]] = []

    for template in TEMPLATES:
        hits = [keyword for keyword in template.keywords if keyword in text]
        if hits:
            matches.append((template, hits))

    # Most keyword hits first — a rough relevance ordering, not a score.
    matches.sort(key=lambda pair: len(pair[1]), reverse=True)
    return matches


def build_candidates(scenario: str) -> tuple[list[dict], str]:
    """Build demo candidates for a scenario.

    Returns (candidates, refusal_message). When the scenario is not covered,
    candidates is empty and the message explains the limitation — no unrelated
    rule is ever returned in its place.
    """
    matches = match_templates(scenario)

    if not matches:
        return [], (
            "Demo mode has no template covering this scenario. It supports only "
            f"{SUPPORTED_SUMMARY}. Rather than return an unrelated rule, no "
            "candidates were produced. Switch to Gemini generation "
            "(DETECTION_GENERATION_MODE=gemini) for arbitrary scenarios."
        )

    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    attack_provenance = attack.dataset_provenance()

    candidates: list[dict] = []

    for template, hits in matches:
        # The technique ID is verified against the dataset exactly as in the
        # Gemini path — a hand-written ID gets no special trust.
        evidence = (
            f"Scenario mentions {', '.join(repr(h) for h in hits)}, which this "
            "template is written to detect."
        )
        verdict = attack.verify_mapping(template.technique_id, evidence)

        candidates.append(
            {
                # The DEMO prefix travels with the name so it appears wherever
                # the candidate is listed.
                "name": f"[DEMO] {template.name}",
                "purpose": template.purpose,
                "spl": template.spl,
                "hypothesis": template.hypothesis,
                "behaviors": list(template.behaviors),
                "attack_mappings": [
                    {
                        "id": verdict.id,
                        "name": verdict.name,
                        "reference_verified": verdict.reference_verified,
                        "mapping_supported": verdict.mapping_supported,
                        "status": verdict.status,
                        "evidence": verdict.evidence,
                        "note": verdict.note,
                        "is_subtechnique": verdict.is_subtechnique,
                        "tactics": list(verdict.tactics),
                    }
                ],
                "log_source": dict(template.log_source),
                "assumptions": [
                    "This is a pre-written template, not a rule generated for "
                    "this specific scenario.",
                    *template.assumptions,
                ],
                "expected_positive_characteristics": list(template.expected_positive),
                "benign_near_matches": list(template.benign_near_matches),
                "blind_spots": [
                    "Demo templates cover only the narrow behaviour they were "
                    "written for; anything else in this scenario is not detected.",
                    *template.blind_spots,
                ],
                "required_telemetry": list(template.required_telemetry),
                "references": [f"MITRE ATT&CK {template.technique_id}"],
                # Populated by the caller using the same static checks the
                # Gemini path uses, so findings are computed, not asserted.
                "static_findings": [],
                "provenance": {
                    # Never "llm" — this output must not read as model-generated.
                    "generator": "template",
                    "provider": "none",
                    "model": "",
                    "prompt_version": "",
                    "template_version": TEMPLATE_VERSION,
                    "template_key": template.key,
                    "generated_at": generated_at,
                    "attack_dataset_version": attack_provenance.get("version"),
                    "demo_mode": True,
                    "validation": {
                        "static_checks": "run",
                        "local_sample_test": "not_run",
                        "splunk_syntax_validation": "not_configured",
                        "real_telemetry_validation": "not_run",
                    },
                },
            }
        )

    return candidates, ""
