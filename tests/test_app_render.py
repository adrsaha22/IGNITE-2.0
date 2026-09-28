"""End-to-end render tests for the redesigned app.

Uses Streamlit's AppTest runner. The AI summarisation call is mocked in both
directions so no test depends on a running model server.
"""

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

POWERSHELL = (
    "Attacker used PowerShell to download a payload from GitHub via DownloadString "
    "and created a scheduled task with schtasks for persistence"
)

TIMEOUT = 180

# AppTest resolves relative paths against the calling test file, so point at
# the repository root explicitly.
APP_PATH = str(Path(__file__).resolve().parent.parent / "app.py")


def _app():
    return AppTest.from_file(APP_PATH, default_timeout=TIMEOUT)


def _generate(at):
    """Enter a description and click the primary generate button."""
    at.text_area[0].set_value(POWERSHELL).run()
    for button in at.button:
        if button.label == "Generate detection rules":
            button.click().run()
            return at
    pytest.fail("primary generate button not found")


# --- baseline render -------------------------------------------------------


def test_app_starts_without_error():
    at = _app().run()
    assert not at.exception


def test_empty_state_shows_no_tabs():
    """With no results the page stops before the tab strip."""
    at = _app().run()
    assert not at.exception
    assert len(at.tabs) == 0


def test_generate_button_disabled_when_input_empty():
    at = _app().run()
    primary = [b for b in at.button if b.label == "Generate detection rules"]
    assert primary and primary[0].disabled


def test_ai_panel_reachable_before_any_analysis():
    """The optional AI feature must not be gated behind generating rules."""
    at = _app().run()
    assert [b for b in at.button if b.label == "Run AI analysis"]


# --- render after generation ----------------------------------------------


def test_renders_after_generation():
    at = _generate(_app().run())
    assert not at.exception
    assert len(at.tabs) == 5


def test_results_survive_rerun():
    at = _generate(_app().run())
    assert len(at.tabs) == 5

    at.run()  # plain rerun
    assert not at.exception
    assert len(at.tabs) == 5, "results must survive a rerun"


def test_results_survive_unrelated_button_click():
    """Switching tabs is client-side; clicking another widget forces a rerun."""
    at = _generate(_app().run())

    ai_buttons = [b for b in at.button if b.label == "Run AI analysis"]
    assert ai_buttons
    ai_buttons[0].click().run()

    assert not at.exception
    assert len(at.tabs) == 5, "results must survive an unrelated interaction"


def test_download_buttons_present_after_generation():
    at = _generate(_app().run())
    labels = [d.label for d in at.download_button]
    assert "Full analysis (JSON)" in labels
    assert "Best rule (.spl)" in labels


def test_spl_export_is_enabled_when_a_rule_exists():
    """AppTest exposes downloads as media URLs rather than inline data, so the
    payload itself is asserted in test_ui_pipeline; here we check the control
    is offered and enabled."""
    at = _generate(_app().run())
    spl = [d for d in at.download_button if d.label == "Best rule (.spl)"]
    assert spl
    assert not spl[0].proto.disabled


def test_all_candidates_export_offered_when_multiple_rules():
    at = _generate(_app().run())
    labels = [d.label for d in at.download_button]
    assert "All candidate rules (.spl)" in labels


# --- staleness -------------------------------------------------------------


def test_editing_input_warns_about_stale_results():
    at = _generate(_app().run())
    at.text_area[0].set_value("something completely different").run()

    assert not at.exception
    warnings = " ".join(w.value for w in at.warning)
    assert "input has changed" in warnings


# --- clearing --------------------------------------------------------------


def test_clear_removes_results():
    at = _generate(_app().run())
    assert len(at.tabs) == 5

    clear = [b for b in at.button if b.label == "Clear analysis"]
    assert clear
    clear[0].click().run()

    assert not at.exception
    assert len(at.tabs) == 0
    assert at.text_area[0].value == ""


# --- example scenarios ----------------------------------------------------


def test_example_button_fills_input():
    at = _app().run()
    example = [b for b in at.button if "PowerShell download" in b.label]
    assert example
    example[0].click().run()

    assert not at.exception
    assert "PowerShell" in at.text_area[0].value


# --- AI analysis: unavailable path ---------------------------------------


def test_ai_failure_does_not_crash_app(monkeypatch):
    """A connection failure must render an actionable warning, not a traceback."""
    at = _app()
    at.run()

    # modules.ai_summary returns this marker string instead of raising.
    import modules.ai_summary as ai

    monkeypatch.setattr(
        ai,
        "summarize_attack",
        lambda _: (
            "AI analysis unavailable: HTTPConnectionPool(host='localhost', port=11434): "
            "Max retries exceeded"
        ),
    )

    at.text_area[0].set_value(POWERSHELL).run()
    ai_buttons = [b for b in at.button if b.label == "Run AI analysis"]
    assert ai_buttons
    ai_buttons[0].click().run()

    assert not at.exception
    warnings = " ".join(w.value for w in at.warning)
    assert "AI analysis is unavailable" in warnings


def test_detection_still_works_when_ai_unavailable(monkeypatch):
    """Rule generation must not depend on the LLM being reachable."""
    import modules.ai_summary as ai

    monkeypatch.setattr(
        ai, "summarize_attack", lambda _: "AI analysis unavailable: connection refused"
    )

    at = _generate(_app().run())
    assert not at.exception
    assert len(at.tabs) == 5


def test_ai_success_renders_output(monkeypatch):
    import modules.ai_summary as ai

    monkeypatch.setattr(ai, "summarize_attack", lambda _: "Behaviours: PowerShell download.")

    at = _app()
    at.run()
    at.text_area[0].set_value(POWERSHELL).run()
    [b for b in at.button if b.label == "Run AI analysis"][0].click().run()

    assert not at.exception
    body = " ".join(m.value for m in at.markdown)
    assert "Behaviours: PowerShell download." in body


# --- pipeline failure -----------------------------------------------------


def test_pipeline_failure_shows_error_not_traceback(monkeypatch):
    from ui import pipeline

    monkeypatch.setattr(
        pipeline,
        "run_analysis",
        lambda _: (_ for _ in ()).throw(RuntimeError("pipeline exploded")),
    )

    at = _app().run()
    at.text_area[0].set_value(POWERSHELL).run()
    [b for b in at.button if b.label == "Generate detection rules"][0].click().run()

    assert not at.exception
    errors = " ".join(e.value for e in at.error)
    assert "pipeline exploded" in errors


# --- vague input edge case -----------------------------------------------


def test_vague_input_renders_cleanly():
    """Empty entity lists and an unmapped technique must not break the page."""
    at = _app().run()
    at.text_area[0].set_value("lateral movement via unknown vector").run()
    [b for b in at.button if b.label == "Generate detection rules"][0].click().run()

    assert not at.exception
    assert len(at.tabs) == 5
