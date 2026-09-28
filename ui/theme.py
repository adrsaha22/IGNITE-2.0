"""Visual theme for IGNITE 2.0.

Native theme tokens live in .streamlit/config.toml. This module holds the
supplementary CSS that Streamlit's theme options cannot express (header
layout, badge/score chips, spacing tightening).

Styling only — no application logic. Selectors are restricted to Streamlit's
stable public hooks (``data-testid`` attributes and our own class names)
rather than nested internal DOM structure, so they survive minor upgrades.
"""

import streamlit as st

# Palette — kept in sync with .streamlit/config.toml.
BG = "#0F1419"
PANEL = "#161C24"
BORDER = "#252E3A"
TEXT = "#E6EDF3"
MUTED = "#8B98A5"
ACCENT = "#38BDF8"

# Semantic colors for scores and statuses.
GOOD = "#3FB950"
WARN = "#D29922"
BAD = "#F85149"

_CSS = f"""
<style>
/* ---------- Layout ---------- */

/* Tighten Streamlit's default top padding and cap content width so lines
   stay readable on wide monitors. */
.block-container {{
    padding-top: 2.2rem;
    padding-bottom: 3rem;
    max-width: 1400px;
}}

/* Prevent accidental horizontal scrolling of the page itself. */
section.main {{ overflow-x: hidden; }}

/* ---------- Application header ---------- */

.ig-header {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 0.75rem;
    padding: 0.85rem 1.15rem;
    margin-bottom: 1.1rem;
    background: linear-gradient(90deg, {PANEL} 0%, rgba(22,28,36,0.55) 100%);
    border: 1px solid {BORDER};
    border-left: 3px solid {ACCENT};
    border-radius: 0.55rem;
}}

.ig-brand {{
    display: flex;
    align-items: baseline;
    gap: 0.6rem;
    min-width: 0;
}}

.ig-brand-mark {{
    font-size: 1.32rem;
    font-weight: 700;
    letter-spacing: 0.055em;
    color: {TEXT};
}}

.ig-brand-mark span {{ color: {ACCENT}; }}

.ig-brand-sub {{
    font-size: 0.86rem;
    color: {MUTED};
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}}

/* ---------- Status pill (AI availability) ---------- */

.ig-status {{
    display: inline-flex;
    align-items: center;
    gap: 0.45rem;
    padding: 0.28rem 0.7rem;
    font-size: 0.78rem;
    font-weight: 500;
    color: {MUTED};
    background: rgba(15,20,25,0.65);
    border: 1px solid {BORDER};
    border-radius: 999px;
    white-space: nowrap;
}}

.ig-dot {{
    width: 7px;
    height: 7px;
    border-radius: 50%;
    flex: 0 0 auto;
}}

.ig-dot-on  {{ background: {GOOD}; }}
.ig-dot-off {{ background: {BAD}; }}

/* ---------- Score chips ---------- */

/* Compact horizontal score indicator used in place of bare st.metric
   numbers, so a value always carries its own scale and color. */
.ig-score {{
    padding: 0.7rem 0.85rem;
    background: {PANEL};
    border: 1px solid {BORDER};
    border-radius: 0.5rem;
    height: 100%;
}}

.ig-score-label {{
    font-size: 0.72rem;
    font-weight: 600;
    letter-spacing: 0.07em;
    text-transform: uppercase;
    color: {MUTED};
    margin-bottom: 0.3rem;
}}

.ig-score-value {{
    font-size: 1.5rem;
    font-weight: 700;
    line-height: 1.1;
    color: {TEXT};
}}

.ig-score-unit {{
    font-size: 0.82rem;
    font-weight: 500;
    color: {MUTED};
}}

.ig-score-note {{
    font-size: 0.74rem;
    color: {MUTED};
    margin-top: 0.15rem;
}}

/* Thin meter bar beneath a score value. */
.ig-meter {{
    height: 4px;
    width: 100%;
    background: {BORDER};
    border-radius: 2px;
    margin-top: 0.45rem;
    overflow: hidden;
}}

.ig-meter-fill {{
    height: 100%;
    border-radius: 2px;
}}

/* ---------- Badges ---------- */

.ig-badges {{
    display: flex;
    flex-wrap: wrap;
    gap: 0.35rem;
    margin: 0.15rem 0 0.3rem 0;
}}

.ig-badge {{
    display: inline-block;
    padding: 0.2rem 0.55rem;
    font-size: 0.78rem;
    font-family: monospace;
    color: {TEXT};
    background: rgba(56,189,248,0.10);
    border: 1px solid rgba(56,189,248,0.32);
    border-radius: 0.3rem;
    white-space: nowrap;
}}

.ig-badge-plain {{
    background: rgba(139,152,165,0.10);
    border-color: {BORDER};
    color: {MUTED};
}}

/* ---------- Empty state ---------- */

.ig-empty {{
    padding: 0.55rem 0.75rem;
    font-size: 0.83rem;
    color: {MUTED};
    background: rgba(139,152,165,0.06);
    border: 1px dashed {BORDER};
    border-radius: 0.4rem;
}}

/* ---------- Section headings ---------- */

.ig-section {{
    font-size: 0.74rem;
    font-weight: 700;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: {MUTED};
    margin: 0.2rem 0 0.5rem 0;
    padding-bottom: 0.3rem;
    border-bottom: 1px solid {BORDER};
}}

/* ---------- Tabs ---------- */

.stTabs [data-baseweb="tab-list"] {{
    gap: 0.15rem;
    border-bottom: 1px solid {BORDER};
}}

.stTabs [data-baseweb="tab"] {{
    padding: 0.55rem 1rem;
    font-size: 0.9rem;
    font-weight: 500;
}}

/* Hover affordance on inactive tabs. */
.stTabs [data-baseweb="tab"]:hover {{
    color: {ACCENT};
    background: rgba(56,189,248,0.06);
}}

/* ---------- Buttons ---------- */

.stButton > button {{
    font-weight: 600;
    transition: border-color 120ms ease, color 120ms ease;
}}

/* Visible keyboard focus ring for accessibility. */
.stButton > button:focus-visible,
.stTextArea textarea:focus-visible,
.stDownloadButton > button:focus-visible {{
    outline: 2px solid {ACCENT};
    outline-offset: 2px;
}}

/* ---------- Text area ---------- */

.stTextArea textarea {{
    font-size: 0.92rem;
    line-height: 1.5;
}}

/* ---------- Code blocks ---------- */

/* Wrap long SPL lines instead of scrolling them off-screen. */
[data-testid="stCode"] pre {{
    white-space: pre-wrap;
    word-break: break-word;
    font-size: 0.83rem;
    line-height: 1.5;
}}

/* ---------- Native metric tightening ---------- */

[data-testid="stMetric"] {{
    padding: 0.6rem 0.8rem;
    background: {PANEL};
    border: 1px solid {BORDER};
    border-radius: 0.5rem;
}}

[data-testid="stMetricLabel"] p {{
    font-size: 0.72rem;
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: {MUTED};
}}

/* ---------- Sidebar ---------- */

[data-testid="stSidebar"] {{ border-right: 1px solid {BORDER}; }}

[data-testid="stSidebar"] .block-container {{ padding-top: 1.5rem; }}

/* ---------- Narrow screens ---------- */

@media (max-width: 640px) {{
    .ig-header {{ flex-direction: column; align-items: flex-start; }}
    .ig-brand {{ flex-direction: column; gap: 0.1rem; }}
    .block-container {{ padding-left: 1rem; padding-right: 1rem; }}
}}
</style>
"""


def inject_css() -> None:
    """Apply the supplementary stylesheet. Call once, early in the script."""
    st.markdown(_CSS, unsafe_allow_html=True)


def score_color(value: float, good: float = 80.0, warn: float = 60.0) -> str:
    """Return the semantic color for a 0-100 score.

    Thresholds are presentation choices for readability, not calibrated
    measures of detection effectiveness.
    """
    if value >= good:
        return GOOD
    if value >= warn:
        return WARN
    return BAD
