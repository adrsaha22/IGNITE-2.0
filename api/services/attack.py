"""ATT&CK technique verification against the bundled MITRE dataset.

Every technique ID that reaches a user is checked against the official STIX
bundle in data/mitre.json: the ID must exist, must not be revoked or
deprecated, and its canonical name comes from the dataset rather than from
whatever produced the ID.

Two things are deliberately kept apart:

* **Reference verified** — this ID exists in ATT&CK and here is its real name.
* **Mapping verified** — this specific detection genuinely covers that
  technique.

Only the first can be established from the dataset. The second needs
behavioural evidence, so a mapping without evidence is reported as a candidate
requiring analyst review, never as a confirmed mapping.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

MITRE_FILE = Path("data") / "mitre.json"

# T1059 or T1059.001
TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")


@dataclass(frozen=True)
class Technique:
    """One ATT&CK technique as the dataset defines it."""

    id: str
    name: str
    is_subtechnique: bool
    tactics: tuple[str, ...]
    domains: tuple[str, ...]
    description: str = ""


@dataclass
class AttackDataset:
    """The loaded bundle, with enough provenance to cite a version."""

    techniques: dict[str, Technique]
    # Latest `modified` timestamp across the bundle — the closest thing to a
    # version when the bundle carries no collection object.
    version: str
    loaded_at: str
    source: str
    total_objects: int
    excluded_revoked: int

    def get(self, technique_id: str) -> Technique | None:
        return self.techniques.get(technique_id.upper())


@dataclass
class MappingVerdict:
    """The result of checking one proposed technique mapping."""

    id: str
    # The ID exists in ATT&CK and is not revoked.
    reference_verified: bool
    # Canonical name from the dataset, never from the caller.
    name: str = ""
    is_subtechnique: bool = False
    tactics: tuple[str, ...] = ()
    # Evidence the caller supplied for why this detection covers the technique.
    evidence: str = ""
    # True only when a reference-verified ID also carries evidence.
    mapping_supported: bool = False
    status: str = "unverified"
    note: str = ""


# Status values, ordered from strongest to weakest claim.
STATUS_SUPPORTED = "supported"          # verified ID + evidence supplied
STATUS_NEEDS_REVIEW = "needs_review"    # verified ID, no evidence
STATUS_UNKNOWN_ID = "unknown_id"        # not in the dataset
STATUS_REVOKED = "revoked"              # exists but revoked/deprecated
STATUS_MALFORMED = "malformed_id"       # not a valid ATT&CK ID shape


@lru_cache(maxsize=1)
def load_dataset(path: str = str(MITRE_FILE)) -> AttackDataset:
    """Load and index the ATT&CK bundle.

    Cached because the bundle is ~48 MB and stable for the process lifetime.
    Revoked and deprecated techniques are excluded so they can never be
    presented as current.
    """
    source = Path(path)
    loaded_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    if not source.is_file():
        logger.warning("ATT&CK dataset not found at %s", source)
        return AttackDataset({}, "unavailable", loaded_at, str(source), 0, 0)

    try:
        with source.open("r", encoding="utf-8") as handle:
            bundle = json.load(handle)
    except (OSError, ValueError) as exc:
        logger.warning("ATT&CK dataset could not be read: %s", type(exc).__name__)
        return AttackDataset({}, "unreadable", loaded_at, str(source), 0, 0)

    objects = bundle.get("objects", [])
    techniques: dict[str, Technique] = {}
    excluded = 0
    latest_modified = ""

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue

        modified = str(obj.get("modified", ""))
        if modified > latest_modified:
            latest_modified = modified

        # Revoked or deprecated techniques must never surface as current.
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            excluded += 1
            continue

        attack_id = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                attack_id = str(ref.get("external_id", ""))
                break

        if not attack_id:
            continue

        tactics = tuple(
            str(phase.get("phase_name", ""))
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        )

        techniques[attack_id] = Technique(
            id=attack_id,
            name=str(obj.get("name", "")),
            is_subtechnique=bool(obj.get("x_mitre_is_subtechnique")),
            tactics=tactics,
            domains=tuple(str(d) for d in obj.get("x_mitre_domains", [])),
            description=str(obj.get("description", ""))[:600],
        )

    logger.info(
        "ATT&CK dataset loaded: %d current techniques, %d revoked/deprecated excluded",
        len(techniques),
        excluded,
    )

    return AttackDataset(
        techniques=techniques,
        version=latest_modified or "unknown",
        loaded_at=loaded_at,
        source=str(source),
        total_objects=len(objects),
        excluded_revoked=excluded,
    )


def verify_mapping(technique_id: str, evidence: str = "") -> MappingVerdict:
    """Verify one proposed technique mapping.

    A correct ID alone never yields `mapping_supported`. Without behavioural
    evidence the mapping is returned as `needs_review`, because an ID being
    real says nothing about whether this detection covers it.
    """
    raw = (technique_id or "").strip().upper()

    if not TECHNIQUE_ID.match(raw):
        return MappingVerdict(
            id=raw,
            reference_verified=False,
            status=STATUS_MALFORMED,
            note=f"'{technique_id}' is not a valid ATT&CK technique ID.",
        )

    dataset = load_dataset()
    technique = dataset.get(raw)

    if technique is None:
        # Distinguish "never existed" from "existed but was revoked", which the
        # loader excluded. Both are unusable, for different reasons.
        return MappingVerdict(
            id=raw,
            reference_verified=False,
            status=STATUS_UNKNOWN_ID,
            note=(
                f"{raw} is not a current technique in the bundled ATT&CK dataset. "
                "It may be revoked, deprecated, or invented."
            ),
        )

    has_evidence = bool(evidence and evidence.strip())

    return MappingVerdict(
        id=technique.id,
        reference_verified=True,
        name=technique.name,
        is_subtechnique=technique.is_subtechnique,
        tactics=technique.tactics,
        evidence=evidence.strip(),
        mapping_supported=has_evidence,
        status=STATUS_SUPPORTED if has_evidence else STATUS_NEEDS_REVIEW,
        note=(
            ""
            if has_evidence
            else "Technique ID verified, but no evidence was supplied linking this "
            "detection to it. Review before relying on this mapping."
        ),
    )


def verify_mappings(proposed: list[dict[str, str]]) -> list[MappingVerdict]:
    """Verify a list of {id, evidence} mappings, de-duplicated by ID."""
    seen: set[str] = set()
    verdicts: list[MappingVerdict] = []

    for item in proposed:
        if not isinstance(item, dict):
            continue
        technique_id = str(item.get("id", "")).strip().upper()
        if not technique_id or technique_id in seen:
            continue
        seen.add(technique_id)
        verdicts.append(verify_mapping(technique_id, str(item.get("evidence", ""))))

    return verdicts


def dataset_provenance() -> dict[str, Any]:
    """Describe the loaded dataset so the UI can cite it."""
    dataset = load_dataset()
    return {
        "source": dataset.source,
        "version": dataset.version,
        "loaded_at": dataset.loaded_at,
        "current_techniques": len(dataset.techniques),
        "revoked_excluded": dataset.excluded_revoked,
        "available": bool(dataset.techniques),
    }
