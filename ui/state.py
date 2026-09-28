"""Session state management for IGNITE 2.0.

Streamlit re-runs the whole script on every interaction, so results held in
local variables disappear as soon as the user touches any widget. This module
keeps the last analysis in ``st.session_state`` and records which input
produced it, so the UI can tell a current result from a stale one.

State is only mutated through these helpers, never by reaching into
``st.session_state`` from the page body.
"""

from typing import Any

import streamlit as st

# Result of the detection pipeline for the analysed description.
ANALYSIS = "ig_analysis"
# The exact attack description that produced ANALYSIS.
ANALYSED_INPUT = "ig_analysed_input"
# Result of the optional, separate AI analysis feature.
AI_RESULT = "ig_ai_result"
# The description that produced AI_RESULT.
AI_INPUT = "ig_ai_input"
# Whether the last AI attempt succeeded, for the header indicator.
AI_OK = "ig_ai_ok"
# Short human-readable qualifier for the AI status.
AI_DETAIL = "ig_ai_detail"
# Error message from the most recent failed generation, if any.
ERROR = "ig_error"

# Widget key for the attack description text area. Kept separate from the
# stored analysis input so widget state is never written after instantiation.
INPUT_WIDGET = "ig_input_widget"

_DEFAULTS: dict[str, Any] = {
    ANALYSIS: None,
    ANALYSED_INPUT: "",
    AI_RESULT: None,
    AI_INPUT: "",
    AI_OK: False,
    AI_DETAIL: "not run",
    ERROR: None,
}


def init() -> None:
    """Initialise state keys once per session. Safe to call on every rerun."""
    for key, value in _DEFAULTS.items():
        if key not in st.session_state:
            st.session_state[key] = value


def get(key: str, default: Any = None) -> Any:
    """Read a state value."""
    return st.session_state.get(key, default)


def current_input() -> str:
    """Return the text currently in the attack description widget."""
    return str(st.session_state.get(INPUT_WIDGET, "") or "")


def has_analysis() -> bool:
    """Whether a completed analysis is stored."""
    return st.session_state.get(ANALYSIS) is not None


def save_analysis(description: str, analysis: dict) -> None:
    """Store a successful analysis alongside the input that produced it."""
    st.session_state[ANALYSIS] = analysis
    st.session_state[ANALYSED_INPUT] = description
    st.session_state[ERROR] = None


def save_error(message: str) -> None:
    """Record a generation failure.

    The previous successful analysis is deliberately left in place so a failed
    run does not destroy work the user can still read; the UI labels it as
    belonging to an earlier input.
    """
    st.session_state[ERROR] = message


def save_ai_result(description: str, text: str, ok: bool, detail: str) -> None:
    """Store the outcome of the optional AI analysis feature."""
    st.session_state[AI_RESULT] = text
    st.session_state[AI_INPUT] = description
    st.session_state[AI_OK] = ok
    st.session_state[AI_DETAIL] = detail


def is_stale() -> bool:
    """Whether the stored analysis came from different text than is in the box.

    Guards against an old result being read as a result for the current input.
    Whitespace-only edits are ignored.
    """
    if not has_analysis():
        return False
    return current_input().strip() != str(st.session_state.get(ANALYSED_INPUT, "")).strip()


def ai_is_stale() -> bool:
    """Whether the stored AI analysis came from different text than the box."""
    if st.session_state.get(AI_RESULT) is None:
        return False
    return current_input().strip() != str(st.session_state.get(AI_INPUT, "")).strip()


def clear() -> None:
    """Reset the workspace, including the input widget.

    Called from a button callback, which runs before widgets are instantiated
    on the following rerun, so clearing the widget key here is safe.
    """
    for key, value in _DEFAULTS.items():
        st.session_state[key] = value
    st.session_state[INPUT_WIDGET] = ""
