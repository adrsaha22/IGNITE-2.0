"""Splunk REST client: connection test, SPL parsing, test searches, deployment.

Configured from the server environment only (see api/settings.py), so the
Splunk token never passes through the browser. TLS verification is on by
default; set SPLUNK_VERIFY_SSL=false only for a local test instance.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import quote

import requests

from api import settings

logger = logging.getLogger(__name__)

SEVERITY_LEVELS = {"informational": 2, "low": 3, "medium": 4, "high": 5, "critical": 6}

DEPLOY_MODES = {
    "disabled": "Saved but not scheduled — enable it manually in Splunk.",
    "shadow": "Runs on schedule; results go to Triggered Alerts only, with no notifications.",
    "live": "Runs on schedule and fires the alert actions you configure.",
}


class SplunkError(Exception):
    """A Splunk request failed. The message is safe to show a user."""


def saved_search_name(title: str) -> str:
    """Splunk-safe saved search name (brackets and newlines break .conf stanzas)."""
    clean = re.sub(r"[\[\]\r\n]", "", str(title or "Untitled")).strip()
    return f"IGNITE - {clean}"[:200]


def _search_string(spl: str) -> str:
    spl = spl.strip()
    return spl if spl.startswith("|") or spl.lower().startswith("search ") else f"search {spl}"


def _messages(resp: requests.Response) -> str:
    try:
        msgs = resp.json().get("messages", [])
        return "; ".join(m.get("text", "") for m in msgs) or resp.text[:300]
    except Exception:
        return resp.text[:300]


def is_configured() -> bool:
    """Whether a Splunk URL and credentials are set. Reveals no credential."""
    return bool(
        settings.SPLUNK_URL
        and (settings.SPLUNK_TOKEN or (settings.SPLUNK_USERNAME and settings.SPLUNK_PASSWORD))
    )


class SplunkClient:
    def __init__(self) -> None:
        if not is_configured():
            raise SplunkError(
                "Splunk is not configured. Set SPLUNK_URL and SPLUNK_TOKEN (or "
                "SPLUNK_USERNAME/SPLUNK_PASSWORD) in the backend environment."
            )
        self.url = settings.SPLUNK_URL
        self.app = settings.SPLUNK_APP
        self.owner = settings.SPLUNK_OWNER
        self.timeout = settings.SPLUNK_TIMEOUT
        self.session = requests.Session()
        self.session.verify = settings.SPLUNK_VERIFY_SSL
        if settings.SPLUNK_TOKEN:
            self.session.headers["Authorization"] = f"Bearer {settings.SPLUNK_TOKEN}"
        else:
            self.session.auth = (settings.SPLUNK_USERNAME, settings.SPLUNK_PASSWORD)

    def _request(self, method: str, path: str, **kw: Any) -> requests.Response:
        kw.setdefault("timeout", self.timeout)
        params = kw.pop("params", {}) or {}
        params.setdefault("output_mode", "json")
        try:
            return self.session.request(method, f"{self.url}{path}", params=params, **kw)
        except requests.RequestException as exc:
            # Log the type only; the message can echo the URL.
            logger.info("Splunk request failed: %s", type(exc).__name__)
            raise SplunkError(f"Cannot reach Splunk at {self.url}: {type(exc).__name__}") from exc

    def test_connection(self) -> dict[str, str]:
        resp = self._request("GET", "/services/server/info")
        if resp.status_code != 200:
            raise SplunkError(f"HTTP {resp.status_code}: {_messages(resp)}")
        content = resp.json()["entry"][0]["content"]
        return {"server": str(content.get("serverName", "")), "version": str(content.get("version", ""))}

    def parse_spl(self, spl: str) -> tuple[bool, str]:
        """Ask Splunk's own parser whether the SPL is valid. Returns (ok, message)."""
        resp = self._request("GET", "/services/search/parser", params={"q": _search_string(spl)})
        if resp.status_code == 200:
            return True, "Splunk's parser accepted the query."
        return False, _messages(resp)

    def test_search(
        self, spl: str, earliest: str = "-24h", latest: str = "now", max_count: int = 1000
    ) -> dict[str, Any]:
        """Run the query once (oneshot) and return the number of results."""
        resp = self._request(
            "POST",
            "/services/search/jobs",
            data={
                "search": _search_string(spl),
                "exec_mode": "oneshot",
                "earliest_time": earliest,
                "latest_time": latest,
                "count": max_count,
                "output_mode": "json",
            },
            timeout=max(self.timeout, 300),
        )
        if resp.status_code != 200:
            raise SplunkError(f"Search failed: {_messages(resp)}")
        results = resp.json().get("results", [])
        return {"result_count": len(results), "sample": results[:5]}

    def deploy(
        self,
        title: str,
        spl: str,
        description: str,
        technique_ids: list[str],
        severity: str,
        mode: str = "shadow",
        cron: str = "*/15 * * * *",
        earliest: str = "-20m",
        latest: str = "now",
        actions: str = "",
    ) -> dict[str, str]:
        """Create or update a saved search for this rule."""
        if mode not in DEPLOY_MODES:
            raise SplunkError(f"Unknown deploy mode '{mode}'.")
        name = saved_search_name(title)
        data = {
            "search": spl,
            "description": f"[{', '.join(technique_ids)}] {description}"[:1000],
            "cron_schedule": cron,
            "dispatch.earliest_time": earliest,
            "dispatch.latest_time": latest,
            "is_scheduled": 0 if mode == "disabled" else 1,
            "disabled": 1 if mode == "disabled" else 0,
            "alert_type": "number of events",
            "alert_comparator": "greater than",
            "alert_threshold": "0",
            "alert.track": 1,
            "alert.severity": SEVERITY_LEVELS.get(str(severity).lower(), 4),
            "alert.digest_mode": 1,
            # Alert actions fire only in live mode; shadow mode stays silent.
            "actions": actions if mode == "live" else "",
        }
        base = f"/servicesNS/{quote(self.owner)}/{quote(self.app)}/saved/searches"
        resp = self._request("POST", base, data={"name": name, **data})
        action = "created"
        if resp.status_code == 409:  # already exists -> update in place
            resp = self._request("POST", f"{base}/{quote(name, safe='')}", data=data)
            action = "updated"
        if resp.status_code not in (200, 201):
            raise SplunkError(f"Deploy failed (HTTP {resp.status_code}): {_messages(resp)}")
        return {"name": name, "action": action, "mode": mode, "app": self.app}


def status(check_connection: bool = False) -> dict[str, Any]:
    """Configuration and (optionally) reachability. Never includes credentials."""
    info: dict[str, Any] = {
        "configured": is_configured(),
        "url": settings.SPLUNK_URL if is_configured() else "",
        "app": settings.SPLUNK_APP,
        "verify_ssl": settings.SPLUNK_VERIFY_SSL,
        "auth": "token" if settings.SPLUNK_TOKEN else ("basic" if settings.SPLUNK_USERNAME else "none"),
        "reachable": None,
        "server": "",
        "version": "",
        "message": "",
    }
    if not info["configured"]:
        info["message"] = (
            "Splunk is not configured. Set SPLUNK_URL and SPLUNK_TOKEN in the backend "
            "environment to enable parser validation, test searches and deployment."
        )
        return info
    if check_connection:
        try:
            result = SplunkClient().test_connection()
            info.update(reachable=True, server=result["server"], version=result["version"])
        except SplunkError as exc:
            info.update(reachable=False, message=str(exc))
    return info


class SplunkValidator:
    """The real adapter behind spl_eval's ExternalValidator seam."""

    @property
    def available(self) -> bool:
        return is_configured()

    def validate(self, query: str) -> dict[str, Any]:
        ok, message = SplunkClient().parse_spl(query)
        return {"valid": ok, "message": message, "validator": "splunk_parser"}
