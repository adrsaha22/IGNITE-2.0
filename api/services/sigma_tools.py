"""Sigma helpers: structural validation and Sigma -> SPL conversion with pySigma.

pySigma is optional. Without it, structural checks still run and conversion is
reported as unavailable — never silently faked.
"""

from __future__ import annotations

from typing import Any

import yaml

try:
    from sigma.backends.splunk import SplunkBackend
    from sigma.collection import SigmaCollection

    HAVE_PYSIGMA = True
except ImportError:  # pragma: no cover - depends on the environment
    HAVE_PYSIGMA = False

_BACKENDS: dict[str, Any] = {}


def _backend(product: str | None):
    """Splunk backend, with the Windows field-mapping pipeline for Windows rules."""
    key = "windows" if product == "windows" else "default"
    if key not in _BACKENDS:
        backend = None
        if key == "windows":
            try:
                from sigma.pipelines.splunk import splunk_windows_pipeline

                backend = SplunkBackend(splunk_windows_pipeline())
            except Exception:
                backend = None
        _BACKENDS[key] = backend or SplunkBackend()
    return _BACKENDS[key]


def parse_sigma(text: str) -> tuple[dict | None, list[str]]:
    """Return (doc, errors). Structural checks always run; pySigma checks if installed."""
    errors: list[str] = []
    if not text or not str(text).strip():
        return None, ["Sigma rule is empty."]

    try:
        docs = [d for d in yaml.safe_load_all(text) if d is not None]
    except yaml.YAMLError as exc:
        return None, [f"Invalid YAML: {exc}"]

    if len(docs) != 1 or not isinstance(docs[0], dict):
        return None, ["Sigma rule must be a single YAML mapping."]

    doc = docs[0]
    for key in ("title", "logsource", "detection"):
        if key not in doc:
            errors.append(f"Missing required Sigma field '{key}'.")

    detection = doc.get("detection")
    if isinstance(detection, dict):
        if "condition" not in detection:
            errors.append("Sigma 'detection' block has no 'condition'.")
        elif len(detection) < 2:
            errors.append("Sigma 'detection' has a condition but no selections.")
    elif detection is not None:
        errors.append("Sigma 'detection' must be a mapping.")

    if isinstance(doc.get("logsource"), dict) and not doc["logsource"]:
        errors.append("Sigma 'logsource' is empty.")

    if not errors and HAVE_PYSIGMA:
        try:
            collection = SigmaCollection.from_yaml(text)
            for rule in collection.rules:
                for err in getattr(rule, "errors", []) or []:
                    errors.append(f"pySigma: {err}")
        except Exception as exc:
            errors.append(f"pySigma: {exc}")

    return doc, errors


def sigma_to_spl(text: str) -> tuple[str | None, str | None]:
    """Return (spl, error). spl is None if pySigma is missing or conversion fails."""
    if not HAVE_PYSIGMA:
        return None, "pySigma is not installed"
    try:
        doc = yaml.safe_load(text) or {}
        product = (doc.get("logsource") or {}).get("product")
        out = _backend(product).convert(SigmaCollection.from_yaml(text))
        if not out:
            return None, "Conversion produced no query"
        return str(out[0]).strip(), None
    except Exception as exc:
        return None, str(exc)


def add_scope(spl: str, index: str = "", sourcetype: str = "") -> str:
    """Prefix index/sourcetype to a raw search that does not already scope them."""
    if not spl or spl.lstrip().startswith("|"):
        return spl
    prefix = []
    if index and "index=" not in spl:
        prefix.append(f"index={index}")
    if sourcetype and "sourcetype=" not in spl:
        prefix.append(f'sourcetype="{sourcetype}"')
    return (" ".join(prefix) + " " + spl).strip() if prefix else spl
