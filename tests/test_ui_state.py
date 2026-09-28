"""Tests for session-state persistence and staleness detection.

``st.session_state`` is exercised through Streamlit's own test runner so the
widget-state rules apply as they do at runtime.
"""

import pytest
from streamlit.testing.v1 import AppTest

SCRIPT = """
import streamlit as st
from ui import state

state.init()
st.text_area("desc", key=state.INPUT_WIDGET)

if st.button("save"):
    state.save_analysis(state.current_input().strip(), {"best": {"rule": "index=a", "score": 7}})

if st.button("fail"):
    state.save_error("pipeline exploded")

if st.button("clear", on_click=state.clear):
    pass

st.text(f"has={state.has_analysis()}")
st.text(f"stale={state.is_stale()}")
st.text(f"err={state.get(state.ERROR)}")
st.text(f"input={state.get(state.ANALYSED_INPUT)}")
"""


def _run():
    at = AppTest.from_string(SCRIPT)
    at.run()
    return at


def _texts(at):
    return [t.value for t in at.text]


def test_starts_with_no_analysis():
    at = _run()
    assert "has=False" in _texts(at)


def test_analysis_persists_across_rerun():
    at = _run()
    at.text_area[0].set_value("powershell attack").run()
    at.button[0].click().run()
    assert "has=True" in _texts(at)

    # A bare rerun models the user interacting with an unrelated widget.
    at.run()
    assert "has=True" in _texts(at)


def test_analysis_survives_unrelated_widget_interaction():
    at = _run()
    at.text_area[0].set_value("powershell attack").run()
    at.button[0].click().run()
    assert "has=True" in _texts(at)

    # Clicking a different button reruns the script; results must remain.
    at.button[1].click().run()
    assert "has=True" in _texts(at)


def test_records_the_input_that_produced_the_result():
    at = _run()
    at.text_area[0].set_value("certutil download").run()
    at.button[0].click().run()
    assert "input=certutil download" in _texts(at)


def test_editing_input_marks_result_stale():
    at = _run()
    at.text_area[0].set_value("powershell attack").run()
    at.button[0].click().run()
    assert "stale=False" in _texts(at)

    at.text_area[0].set_value("a completely different attack").run()
    assert "stale=True" in _texts(at)


def test_whitespace_only_edit_is_not_stale():
    at = _run()
    at.text_area[0].set_value("powershell attack").run()
    at.button[0].click().run()

    at.text_area[0].set_value("  powershell attack  ").run()
    assert "stale=False" in _texts(at)


def test_failure_preserves_previous_analysis():
    at = _run()
    at.text_area[0].set_value("powershell attack").run()
    at.button[0].click().run()
    assert "has=True" in _texts(at)

    at.button[1].click().run()  # "fail"
    assert "has=True" in _texts(at), "a failed run must not erase the last result"
    assert "err=pipeline exploded" in _texts(at)


def test_success_clears_previous_error():
    at = _run()
    at.button[1].click().run()
    assert "err=pipeline exploded" in _texts(at)

    at.text_area[0].set_value("powershell attack").run()
    at.button[0].click().run()
    assert "err=None" in _texts(at)


def test_clear_resets_everything_including_input():
    at = _run()
    at.text_area[0].set_value("powershell attack").run()
    at.button[0].click().run()
    assert "has=True" in _texts(at)

    at.button[2].click().run()  # "clear"
    assert "has=False" in _texts(at)
    assert "input=" in _texts(at)
    assert at.text_area[0].value == ""


def test_clear_does_not_raise_widget_state_error():
    """Clearing writes the widget key from a callback, which must be legal."""
    at = _run()
    at.text_area[0].set_value("x").run()
    at.button[2].click().run()
    assert not at.exception
