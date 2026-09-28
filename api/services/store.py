"""Saved investigations, persisted in SQLite.

SQLite is part of the standard library and needs no server, which suits this
single-user local application. Writes go through transactions, so a crash
mid-write cannot leave a half-written record.

The payload is versioned: a record written by an older build is loaded
defensively and reported rather than trusted blindly.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator

from api.settings import INVESTIGATIONS_DB

logger = logging.getLogger(__name__)

# Bump when the stored payload shape changes incompatibly.
SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS investigations (
    id              TEXT PRIMARY KEY,
    title           TEXT NOT NULL,
    notes           TEXT NOT NULL DEFAULT '',
    schema_version  INTEGER NOT NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    payload         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_investigations_updated
    ON investigations (updated_at DESC, created_at DESC);
"""


def _now() -> str:
    """Timestamp with microsecond precision.

    Second precision would make two records saved in the same second sort
    unpredictably, so ordering uses microseconds.
    """
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


@contextmanager
def _connect() -> Iterator[sqlite3.Connection]:
    """Open a connection with the schema ensured.

    The parent directory is created on demand so a fresh checkout works without
    a setup step.
    """
    INVESTIGATIONS_DB.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(INVESTIGATIONS_DB)
    connection.row_factory = sqlite3.Row
    try:
        connection.executescript(_SCHEMA)
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _row_to_summary(row: sqlite3.Row) -> dict[str, Any]:
    """Listing shape — omits the payload so listing stays cheap."""
    return {
        "id": row["id"],
        "title": row["title"],
        "notes": row["notes"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "schema_version": row["schema_version"],
    }


def _decode_payload(row: sqlite3.Row) -> tuple[dict[str, Any], str]:
    """Decode a stored payload defensively.

    Returns (payload, warning). A malformed or future-version record yields an
    empty payload plus an explanation, rather than raising or silently
    returning something that looks valid.
    """
    stored_version = row["schema_version"]

    try:
        payload = json.loads(row["payload"])
    except (ValueError, TypeError):
        logger.warning("Investigation %s has an unreadable payload", row["id"])
        return {}, "This saved record could not be read and may be corrupted."

    if not isinstance(payload, dict):
        return {}, "This saved record has an unexpected shape and was not loaded."

    if stored_version > SCHEMA_VERSION:
        return payload, (
            f"This record was saved by a newer version of IGNITE "
            f"(schema {stored_version} > {SCHEMA_VERSION}). Some fields may not load."
        )

    if stored_version < SCHEMA_VERSION:
        return payload, (
            f"This record uses an older schema ({stored_version}). "
            "It was loaded on a best-effort basis."
        )

    return payload, ""


def list_investigations(query: str = "") -> list[dict[str, Any]]:
    """List saved investigations, newest first, optionally filtered."""
    with _connect() as connection:
        if query.strip():
            needle = f"%{query.strip().lower()}%"
            rows = connection.execute(
                """
                SELECT * FROM investigations
                WHERE LOWER(title) LIKE ? OR LOWER(notes) LIKE ?
                ORDER BY updated_at DESC, created_at DESC, id DESC
                """,
                (needle, needle),
            ).fetchall()
        else:
            rows = connection.execute(
                "SELECT * FROM investigations ORDER BY updated_at DESC, created_at DESC, id DESC"
            ).fetchall()

    return [_row_to_summary(row) for row in rows]


def get_investigation(investigation_id: str) -> dict[str, Any] | None:
    """Load one investigation, including its payload."""
    with _connect() as connection:
        row = connection.execute(
            "SELECT * FROM investigations WHERE id = ?", (investigation_id,)
        ).fetchone()

    if row is None:
        return None

    payload, warning = _decode_payload(row)
    record = _row_to_summary(row)
    record["payload"] = payload
    record["warning"] = warning
    return record


def create_investigation(title: str, notes: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Save a new investigation under a fresh ID."""
    investigation_id = str(uuid.uuid4())
    timestamp = _now()

    with _connect() as connection:
        connection.execute(
            """
            INSERT INTO investigations
                (id, title, notes, schema_version, created_at, updated_at, payload)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                investigation_id,
                title.strip() or "Untitled investigation",
                notes.strip(),
                SCHEMA_VERSION,
                timestamp,
                timestamp,
                json.dumps(payload),
            ),
        )

    result = get_investigation(investigation_id)
    assert result is not None  # just inserted
    return result


def update_investigation(
    investigation_id: str,
    title: str | None = None,
    notes: str | None = None,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Update one investigation in place.

    Targets a single row by ID, so concurrent edits to different
    investigations cannot overwrite one another.
    """
    existing = get_investigation(investigation_id)
    if existing is None:
        return None

    with _connect() as connection:
        connection.execute(
            """
            UPDATE investigations
            SET title = ?, notes = ?, payload = ?, schema_version = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                (title if title is not None else existing["title"]).strip()
                or "Untitled investigation",
                (notes if notes is not None else existing["notes"]).strip(),
                json.dumps(payload if payload is not None else existing["payload"]),
                SCHEMA_VERSION,
                _now(),
                investigation_id,
            ),
        )

    return get_investigation(investigation_id)


def duplicate_investigation(investigation_id: str) -> dict[str, Any] | None:
    """Copy an investigation so the analyst can experiment freely."""
    existing = get_investigation(investigation_id)
    if existing is None:
        return None

    return create_investigation(
        title=f"{existing['title']} (copy)",
        notes=existing["notes"],
        payload=existing["payload"],
    )


def delete_investigation(investigation_id: str) -> bool:
    """Remove an investigation. Returns whether a row was deleted."""
    with _connect() as connection:
        cursor = connection.execute(
            "DELETE FROM investigations WHERE id = ?", (investigation_id,)
        )
        return cursor.rowcount > 0
