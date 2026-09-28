"""Tests for saved-investigation persistence.

Each test runs against a temporary database file so the developer's real
investigations are never touched.
"""

import json
import sqlite3

import pytest

from api.services import store


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    """Point the store at a throwaway database for every test."""
    monkeypatch.setattr(store, "INVESTIGATIONS_DB", tmp_path / "test.db")
    yield tmp_path / "test.db"


PAYLOAD = {
    "analysis": {"description": "powershell attack", "candidates": [{"spl": "index=a"}]},
    "selected_rule": 0,
    "test_cases": [{"_id": "e1", "EventCode": 1}],
}


# --- create / read -------------------------------------------------------


def test_create_returns_a_stable_id_and_timestamps():
    record = store.create_investigation("PowerShell staging", "initial notes", PAYLOAD)
    assert record["id"]
    assert record["created_at"]
    assert record["updated_at"]
    assert record["schema_version"] == store.SCHEMA_VERSION


def test_created_record_round_trips():
    created = store.create_investigation("Title", "Notes", PAYLOAD)
    loaded = store.get_investigation(created["id"])
    assert loaded is not None
    assert loaded["title"] == "Title"
    assert loaded["notes"] == "Notes"
    assert loaded["payload"] == PAYLOAD


def test_payload_preserves_rules_tests_and_selection():
    created = store.create_investigation("T", "", PAYLOAD)
    payload = store.get_investigation(created["id"])["payload"]
    assert payload["selected_rule"] == 0
    assert payload["test_cases"][0]["_id"] == "e1"
    assert payload["analysis"]["candidates"][0]["spl"] == "index=a"


def test_blank_title_gets_a_fallback():
    record = store.create_investigation("   ", "", {})
    assert record["title"] == "Untitled investigation"


def test_get_unknown_id_returns_none():
    assert store.get_investigation("does-not-exist") is None


# --- listing and search --------------------------------------------------


def test_list_is_newest_first():
    store.create_investigation("first", "", {})
    store.create_investigation("second", "", {})
    titles = [row["title"] for row in store.list_investigations()]
    assert titles[0] == "second"


def test_list_omits_the_payload_for_cheap_listing():
    store.create_investigation("t", "", PAYLOAD)
    assert "payload" not in store.list_investigations()[0]


def test_search_matches_title_and_notes():
    store.create_investigation("PowerShell staging", "", {})
    store.create_investigation("Certutil transfer", "mentions powershell", {})
    store.create_investigation("Unrelated", "nothing", {})

    assert len(store.list_investigations("powershell")) == 2
    assert len(store.list_investigations("certutil")) == 1
    assert len(store.list_investigations("nomatch")) == 0


def test_search_is_case_insensitive():
    store.create_investigation("PowerShell", "", {})
    assert len(store.list_investigations("POWERSHELL")) == 1


# --- update --------------------------------------------------------------


def test_update_changes_only_the_target_record():
    first = store.create_investigation("first", "a", {"k": 1})
    second = store.create_investigation("second", "b", {"k": 2})

    store.update_investigation(first["id"], title="renamed")

    assert store.get_investigation(first["id"])["title"] == "renamed"
    # The other investigation is untouched.
    other = store.get_investigation(second["id"])
    assert other["title"] == "second"
    assert other["payload"] == {"k": 2}


def test_partial_update_preserves_unspecified_fields():
    created = store.create_investigation("title", "notes", PAYLOAD)
    store.update_investigation(created["id"], notes="new notes")

    loaded = store.get_investigation(created["id"])
    assert loaded["notes"] == "new notes"
    assert loaded["title"] == "title"
    assert loaded["payload"] == PAYLOAD


def test_update_bumps_updated_at():
    created = store.create_investigation("t", "", {})
    store.update_investigation(created["id"], title="t2")
    loaded = store.get_investigation(created["id"])
    assert loaded["updated_at"] >= created["updated_at"]


def test_update_unknown_id_returns_none():
    assert store.update_investigation("nope", title="x") is None


# --- duplicate -----------------------------------------------------------


def test_duplicate_creates_an_independent_copy():
    original = store.create_investigation("Original", "notes", PAYLOAD)
    copy = store.duplicate_investigation(original["id"])

    assert copy["id"] != original["id"]
    assert copy["title"] == "Original (copy)"
    assert copy["payload"] == PAYLOAD


def test_editing_a_duplicate_does_not_affect_the_original():
    original = store.create_investigation("Original", "", {"v": 1})
    copy = store.duplicate_investigation(original["id"])

    store.update_investigation(copy["id"], payload={"v": 2})

    assert store.get_investigation(original["id"])["payload"] == {"v": 1}
    assert store.get_investigation(copy["id"])["payload"] == {"v": 2}


def test_duplicate_unknown_id_returns_none():
    assert store.duplicate_investigation("nope") is None


# --- delete --------------------------------------------------------------


def test_delete_removes_only_the_target():
    first = store.create_investigation("first", "", {})
    second = store.create_investigation("second", "", {})

    assert store.delete_investigation(first["id"]) is True
    assert store.get_investigation(first["id"]) is None
    assert store.get_investigation(second["id"]) is not None


def test_delete_unknown_id_reports_false():
    assert store.delete_investigation("nope") is False


# --- malformed and versioned records ------------------------------------


def test_malformed_payload_is_reported_not_raised(temp_db):
    created = store.create_investigation("t", "", {})

    # Corrupt the stored JSON directly.
    connection = sqlite3.connect(temp_db)
    connection.execute(
        "UPDATE investigations SET payload = ? WHERE id = ?", ("{not json", created["id"])
    )
    connection.commit()
    connection.close()

    loaded = store.get_investigation(created["id"])
    assert loaded["payload"] == {}
    assert "corrupted" in loaded["warning"]


def test_non_object_payload_is_rejected_gracefully(temp_db):
    created = store.create_investigation("t", "", {})
    connection = sqlite3.connect(temp_db)
    connection.execute(
        "UPDATE investigations SET payload = ? WHERE id = ?",
        (json.dumps([1, 2, 3]), created["id"]),
    )
    connection.commit()
    connection.close()

    loaded = store.get_investigation(created["id"])
    assert loaded["payload"] == {}
    assert loaded["warning"]


def test_newer_schema_version_is_flagged(temp_db):
    created = store.create_investigation("t", "", {"a": 1})
    connection = sqlite3.connect(temp_db)
    connection.execute(
        "UPDATE investigations SET schema_version = ? WHERE id = ?",
        (store.SCHEMA_VERSION + 5, created["id"]),
    )
    connection.commit()
    connection.close()

    loaded = store.get_investigation(created["id"])
    assert "newer version" in loaded["warning"]
    # The payload is still offered on a best-effort basis.
    assert loaded["payload"] == {"a": 1}


def test_older_schema_version_is_flagged(temp_db):
    created = store.create_investigation("t", "", {"a": 1})
    connection = sqlite3.connect(temp_db)
    connection.execute(
        "UPDATE investigations SET schema_version = 0 WHERE id = ?", (created["id"],)
    )
    connection.commit()
    connection.close()

    loaded = store.get_investigation(created["id"])
    assert "older schema" in loaded["warning"]


def test_healthy_record_has_no_warning():
    created = store.create_investigation("t", "", {"a": 1})
    assert store.get_investigation(created["id"])["warning"] == ""


# --- durability ----------------------------------------------------------


def test_database_is_created_on_demand(tmp_path, monkeypatch):
    target = tmp_path / "nested" / "dir" / "db.sqlite"
    monkeypatch.setattr(store, "INVESTIGATIONS_DB", target)
    store.create_investigation("t", "", {})
    assert target.exists()


def test_failed_write_does_not_corrupt_existing_rows(temp_db):
    """A transaction error must roll back, leaving earlier rows intact."""
    created = store.create_investigation("keep me", "", {"v": 1})

    class Unserialisable:
        pass

    with pytest.raises(TypeError):
        store.update_investigation(created["id"], payload={"bad": Unserialisable()})

    loaded = store.get_investigation(created["id"])
    assert loaded["title"] == "keep me"
    assert loaded["payload"] == {"v": 1}
