"""Reusable presentation components for IGNITE 2.0.

Small rendering helpers that keep app.py readable and give the interface a
consistent look. These render data they are given; they never compute or
invent detection results.
"""

import html
from typing import Iterable, Sequence

import streamlit as st

from ui.theme import MUTED, score_color


def _esc(value) -> str:
    """Escape a value for safe interpolation into our HTML snippets."""
    return html.escape(str(value))


def app_header(ai_online: bool, ai_detail: str = "") -> None:
    """Render the branded header with a compact AI availability indicator.

    ``ai_online`` reflects the last observed state of the AI analysis
    feature; ``ai_detail`` is a short human-readable qualifier.
    """
    dot = "ig-dot-on" if ai_online else "ig-dot-off"
    label = "AI Analysis online" if ai_online else "AI Analysis offline"
    if ai_detail:
        label = f"{label} — {ai_detail}"

    st.markdown(
        f"""
        <div class="ig-header">
          <div class="ig-brand">
            <div class="ig-brand-mark">IGNITE<span> 2.0</span></div>
            <div class="ig-brand-sub">AI Detection Rule Generator</div>
          </div>
          <div class="ig-status">
            <span class="ig-dot {dot}"></span>{_esc(label)}
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def section(title: str) -> None:
    """Render a compact uppercase section label."""
    st.markdown(f'<div class="ig-section">{_esc(title)}</div>', unsafe_allow_html=True)


def score_card(
    label: str,
    value,
    unit: str = "",
    note: str = "",
    meter: bool = False,
    maximum: float = 100.0,
) -> None:
    """Render a compact score chip, optionally with a proportional meter.

    Used instead of a bare number so a value always carries its scale and a
    color cue. Colors are readability aids, not calibrated probabilities.
    """
    bar = ""
    if meter:
        try:
            pct = max(0.0, min(100.0, (float(value) / maximum) * 100.0))
        except (TypeError, ValueError):
            pct = 0.0
        color = score_color(pct)
        bar = (
            '<div class="ig-meter">'
            f'<div class="ig-meter-fill" style="width:{pct:.0f}%;background:{color};"></div>'
            "</div>"
        )

    unit_html = f'<span class="ig-score-unit">{_esc(unit)}</span>' if unit else ""
    note_html = f'<div class="ig-score-note">{_esc(note)}</div>' if note else ""

    st.markdown(
        f"""
        <div class="ig-score">
          <div class="ig-score-label">{_esc(label)}</div>
          <div class="ig-score-value">{_esc(value)}{unit_html}</div>
          {bar}{note_html}
        </div>
        """,
        unsafe_allow_html=True,
    )


def badges(items: Iterable, empty_message: str, plain: bool = False) -> None:
    """Render values as badges, or a quiet empty-state note if there are none."""
    values = [v for v in (items or []) if str(v).strip()]
    if not values:
        empty_state(empty_message)
        return

    cls = "ig-badge ig-badge-plain" if plain else "ig-badge"
    chips = "".join(f'<span class="{cls}">{_esc(v)}</span>' for v in values)
    st.markdown(f'<div class="ig-badges">{chips}</div>', unsafe_allow_html=True)


def empty_state(message: str) -> None:
    """Render a small placeholder in place of an empty list or missing field."""
    st.markdown(f'<div class="ig-empty">{_esc(message)}</div>', unsafe_allow_html=True)


def bullet_list(items: Sequence, empty_message: str, icon: str = "") -> None:
    """Render a list of short strings, or an empty-state note."""
    values = [str(v) for v in (items or []) if str(v).strip()]
    if not values:
        empty_state(empty_message)
        return

    prefix = f"{icon} " if icon else ""
    for value in values:
        st.markdown(
            f'<div style="font-size:0.88rem;margin:0.12rem 0;">{_esc(prefix)}{_esc(value)}</div>',
            unsafe_allow_html=True,
        )


def spl_block(query: str, height: int | None = None) -> None:
    """Render an SPL query as a syntax-highlighted block.

    Streamlit's code block provides its own copy-to-clipboard control.
    """
    text = (query or "").strip()
    if not text:
        empty_state("No query generated.")
        return

    if height is not None:
        st.code(text, language="sql", height=height)
    else:
        st.code(text, language="sql")


def caption_muted(text: str) -> None:
    """Render small muted helper text."""
    st.markdown(
        f'<div style="font-size:0.78rem;color:{MUTED};">{_esc(text)}</div>',
        unsafe_allow_html=True,
    )
