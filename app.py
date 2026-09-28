"""IGNITE 2.0 — AI Detection Rule Generator.

Streamlit front end. Detection logic lives in modules/; the presentation layer
lives in ui/. This file wires the two together and owns the page layout only.
"""

import json

import streamlit as st

from modules.ai_summary import summarize_attack
from ui import pipeline, state
from ui.components import (
    app_header,
    badges,
    bullet_list,
    caption_muted,
    empty_state,
    score_card,
    section,
    spl_block,
)
from ui.theme import inject_css

st.set_page_config(
    page_title="IGNITE 2.0 — Detection Rule Generator",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

inject_css()
state.init()

# Prefix that modules.ai_summary returns instead of raising on failure.
AI_ERROR_PREFIX = "AI analysis unavailable"

EXAMPLES = {
    "PowerShell download + persistence": (
        "Attacker used PowerShell to download a payload from GitHub via "
        "DownloadString and created a scheduled task with schtasks for persistence"
    ),
    "Certutil LOLBin transfer": (
        "Threat actor used certutil.exe to download an encoded payload from a "
        "remote host and decoded it on disk"
    ),
    "Credential dumping": (
        "Adversary ran mimikatz against lsass to perform credential dumping on "
        "a domain controller"
    ),
}


def _ai_status() -> tuple[bool, str]:
    """Report the last observed AI analysis state for the header indicator.

    Reflects only what has already been attempted in this session; it never
    issues a model request of its own, so reruns stay cheap.
    """
    if state.get(state.AI_RESULT) is None:
        return False, "not run"
    return (True, "ready") if state.get(state.AI_OK) else (False, "unreachable")


def _use_example(text: str) -> None:
    """Insert an example scenario into the input widget.

    Runs as a button callback, before widgets are instantiated on the next
    rerun, so writing the widget key here is safe.
    """
    st.session_state[state.INPUT_WIDGET] = text


def render_ai_panel() -> None:
    """Render the optional AI summary panel.

    Deliberately independent of detection results so it is reachable whether or
    not an analysis has been generated, and so a failure here never blocks
    rule generation.
    """
    st.markdown("")

    with st.container(border=True):
        section("AI analysis (optional)")
        caption_muted(
            "Separate LLM summary of the attack description. It does not feed into "
            "detection-rule generation, which works with or without it."
        )

        run_ai = st.button("Run AI analysis", disabled=not state.current_input().strip())

        if run_ai:
            target = state.current_input().strip()
            with st.spinner("Requesting AI analysis…"):
                # Existing behaviour preserved: summarize_attack returns a
                # marker string on failure rather than raising.
                text = summarize_attack(target)
            ok = not str(text).startswith(AI_ERROR_PREFIX)
            state.save_ai_result(target, text, ok, "ready" if ok else "unreachable")

        ai_text = state.get(state.AI_RESULT)
        if ai_text is None:
            return

        if state.ai_is_stale():
            caption_muted("This summary was generated from an earlier description.")

        if state.get(state.AI_OK):
            st.markdown(ai_text)
        else:
            st.warning(
                "AI analysis is unavailable — the language model could not be "
                "reached. Detection-rule generation is unaffected and can still "
                "be used.",
                icon="⚠️",
            )
            with st.expander("Technical detail"):
                st.code(str(ai_text), language="text")


# ==========================================================================
# HEADER
# ==========================================================================

ai_online, ai_detail = _ai_status()
app_header(ai_online, ai_detail)


# ==========================================================================
# SIDEBAR — secondary controls only
# ==========================================================================

with st.sidebar:
    section("Workspace")
    if st.button("Clear analysis", width="stretch", on_click=state.clear):
        pass
    caption_muted("Resets the input and all results.")

    st.divider()
    section("Example scenarios")
    for name, text in EXAMPLES.items():
        st.button(name, width="stretch", on_click=_use_example, args=(text,))

    st.divider()
    section("About")
    caption_muted(
        "Generates Splunk SPL detection candidates from a plain-English attack "
        "description using MITRE ATT&CK, Sigma references and template builders."
    )
    caption_muted(
        "Rules are generated starting points. They are not validated against a "
        "live Splunk instance and require review before deployment."
    )


# ==========================================================================
# INPUT WORKSPACE
# ==========================================================================

with st.container(border=True):
    section("Attack scenario")

    description = st.text_area(
        "Attack scenario",
        key=state.INPUT_WIDGET,
        height=120,
        max_chars=4000,
        placeholder=(
            "Describe the attack in plain English — tools used, commands observed, "
            "and the behaviour you want to detect."
        ),
        label_visibility="collapsed",
    )

    typed = state.current_input()

    left, right = st.columns([3, 1], vertical_alignment="bottom")

    with left:
        caption_muted(
            f"{len(typed)} characters"
            + ("" if typed.strip() else " — enter a description to begin")
        )

    with right:
        generate = st.button(
            "Generate detection rules",
            type="primary",
            width="stretch",
            disabled=not typed.strip(),
        )


# ==========================================================================
# GENERATION
# ==========================================================================

if generate:
    current = state.current_input().strip()
    with st.spinner("Running detection pipeline…"):
        try:
            result = pipeline.run_analysis(current)
            state.save_analysis(current, result)
        except Exception as exc:
            # The previous successful analysis is retained and labelled stale.
            state.save_error(f"{type(exc).__name__}: {exc}")

if state.get(state.ERROR):
    st.error(f"Detection pipeline failed: {state.get(state.ERROR)}")
    if state.has_analysis():
        caption_muted("The results below are from your previous successful run.")


# ==========================================================================
# RESULTS
# ==========================================================================

if not state.has_analysis():
    st.markdown("")
    empty_state(
        "No analysis yet. Describe an attack scenario above, or pick an example "
        "from the sidebar, then select Generate detection rules."
    )
    # The optional AI panel is independent of detection results, so it stays
    # reachable before any analysis has been run.
    render_ai_panel()
    st.stop()

analysis = state.get(state.ANALYSIS)
auto = analysis.get("autonomous", {})
best = analysis.get("best", {})
warnings = pipeline.validation_warnings(analysis)

if state.is_stale():
    st.warning(
        "The input has changed since these results were generated. "
        "Select Generate detection rules to refresh them.",
        icon="⚠️",
    )

# --- Compact summary strip -------------------------------------------------

validation = auto.get("validation") or {}
quality = auto.get("quality") or {}

c1, c2, c3, c4, c5 = st.columns(5)

with c1:
    score_card("Best rule score", best.get("score", 0), meter=True, maximum=125)
with c2:
    score_card(
        "Validation",
        validation.get("score", "—"),
        unit="/100" if validation else "",
        meter=bool(validation),
    )
with c3:
    score_card(
        "Quality",
        quality.get("quality_score", "—"),
        unit="/100" if quality else "",
        meter=bool(quality),
    )
with c4:
    score_card("Techniques", len(auto.get("techniques", [])), note="MITRE mapped")
with c5:
    score_card("Candidates", len(analysis.get("ranked", [])), note="rules ranked")

if warnings:
    st.markdown("")
    with st.container(border=True):
        section(f"Attention — {len(warnings)} finding(s)")
        for item in warnings:
            st.markdown(f"⚠️ {item}")

st.markdown("")

tab_overview, tab_rules, tab_intel, tab_validation, tab_export = st.tabs(
    ["Overview", "Detection Rules", "Attack Intelligence", "Validation", "Export"]
)


# ==========================================================================
# OVERVIEW
# ==========================================================================

with tab_overview:
    col_main, col_side = st.columns([2, 1], gap="medium")

    with col_main:
        section("Best detection rule")
        origin = best.get("origin", "")
        caption_muted(
            f"{origin} · score {best.get('score', 0)} · generated, not validated "
            "against a live Splunk instance"
        )
        spl_block(best.get("rule", ""), height=260)

    with col_side:
        section("Attack summary")
        desc = analysis.get("description", "")
        st.markdown(
            f'<div style="font-size:0.86rem;line-height:1.5;">{desc[:400]}'
            f'{"…" if len(desc) > 400 else ""}</div>',
            unsafe_allow_html=True,
        )

        st.markdown("")
        section("Primary technique")
        mitre_id = analysis.get("mitre_id", "Unknown")
        mitre_name = analysis.get("mitre_name", "Unknown")
        if mitre_id == "Unknown":
            empty_state("No technique mapped from the description.")
        else:
            badges([f"{mitre_id} — {mitre_name}"], "No technique mapped.")

        st.markdown("")
        section("Detection status")
        if validation:
            valid = bool(validation.get("valid"))
            issues = validation.get("issues") or []
            if valid and not issues:
                st.success("Passed all static checks", icon="✅")
            elif valid and issues:
                st.warning(f"Passed, with {len(issues)} reported issue(s)", icon="⚠️")
            else:
                st.error("Failed static validation", icon="❌")
            caption_muted("Static text checks only — not runtime validation.")
        else:
            empty_state("Autonomous engine did not produce a validation report.")


# ==========================================================================
# DETECTION RULES
# ==========================================================================

with tab_rules:
    ranked = analysis.get("ranked", [])

    section("Candidate rules")
    if not ranked:
        empty_state("No candidate rules were generated.")
    else:
        labels = [
            f"#{i + 1} · {r.get('origin', 'rule')} · score {r.get('score', 0)}"
            for i, r in enumerate(ranked)
        ]
        chosen = st.radio(
            "Select a rule to inspect",
            options=range(len(ranked)),
            format_func=lambda i: labels[i],
            horizontal=False,
            label_visibility="collapsed",
        )

        rule = ranked[chosen]

        m1, m2, m3 = st.columns(3)
        with m1:
            score_card("Score", rule.get("score", 0), meter=True, maximum=125)
        with m2:
            score_card("Source", rule.get("origin", "—"))
        with m3:
            score_card(
                "Field conditions",
                "present" if rule.get("has_conditions") else "none",
                note="static text check",
            )

        if not rule.get("has_conditions"):
            st.warning(
                "This rule has no field conditions and would match far too "
                "broadly in production.",
                icon="⚠️",
            )

        st.markdown("")
        caption_muted(
            "Generated SPL — reviewed by static text checks only, never executed "
            "or validated against Splunk."
        )
        spl_block(rule.get("rule", ""), height=300)

    st.markdown("")
    section("Autonomous engine rule")
    if auto.get("available"):
        caption_muted(
            "Built from mapped techniques, then narrowed by the false-positive reducer."
        )
        spl_block(auto.get("rule", ""), height=220)

        with st.expander("Telemetry-aware variant"):
            caption_muted("Derived from the telemetry catalog for the mapped techniques.")
            spl_block(auto.get("telemetry_rule", ""), height=220)
    else:
        empty_state(f"Autonomous engine unavailable: {auto.get('error') or 'unknown error'}")

    sigma_refs = analysis.get("sigma", {}).get("detections", [])
    st.markdown("")
    section(f"Sigma references ({len(sigma_refs)})")
    if not sigma_refs:
        empty_state(
            "No Sigma rules matched. The data/sigma directory is empty, so this "
            "pipeline has no corpus to search."
        )
    else:
        for i, detection in enumerate(sigma_refs, start=1):
            with st.expander(f"{i}. {detection.get('title', 'Untitled')}"):
                if detection.get("tags"):
                    badges(detection["tags"], "No tags.", plain=True)
                if detection.get("logsource"):
                    caption_muted(f"Log source: {detection['logsource']}")
                spl_block(detection.get("spl", ""), height=200)


# ==========================================================================
# ATTACK INTELLIGENCE
# ==========================================================================

with tab_intel:
    col_a, col_b = st.columns(2, gap="medium")

    with col_a:
        section("Mapped MITRE techniques")
        techniques = auto.get("techniques", [])
        if not techniques:
            empty_state("No techniques mapped from the description.")
        else:
            names = auto.get("technique_names", {})
            for tid in techniques:
                name = names.get(tid) or "name unavailable"
                st.markdown(
                    f'<div style="font-size:0.88rem;margin:0.2rem 0;">'
                    f'<span class="ig-badge">{tid}</span> &nbsp;{name}</div>',
                    unsafe_allow_html=True,
                )
            caption_muted(
                "Names resolved from the bundled ATT&CK data. Tactic mappings are "
                "not available from the current pipeline."
            )

        st.markdown("")
        section("Extracted tools")
        badges(analysis.get("entities", {}).get("tools", []), "No tools extracted.")

        st.markdown("")
        section("Indicators")
        badges(analysis.get("entities", {}).get("indicators", []), "No indicators extracted.")

    with col_b:
        section("Log sources")
        badges(
            analysis.get("entities", {}).get("logs", []),
            "No log sources extracted.",
            plain=True,
        )

        st.markdown("")
        section("Fields referenced")
        badges(
            analysis.get("entities", {}).get("fields", []),
            "No fields extracted.",
            plain=True,
        )

        st.markdown("")
        section("Telemetry requirements")
        telemetry = auto.get("telemetry") or {}
        if not telemetry or not any(telemetry.values()):
            empty_state("No telemetry requirements available for the mapped techniques.")
        else:
            caption_muted("Event codes")
            badges(telemetry.get("events", []), "None listed.", plain=True)
            caption_muted("Log sources")
            badges(telemetry.get("logs", []), "None listed.", plain=True)
            caption_muted("Fields")
            badges(telemetry.get("fields", []), "None listed.", plain=True)

    st.markdown("")
    section("Detection rationale")
    explanation = auto.get("explanation", "")
    if explanation.strip():
        with st.expander("Why this detection works, and expected false positives", expanded=True):
            st.text(explanation)
    else:
        empty_state("No explanation was generated.")


# ==========================================================================
# VALIDATION
# ==========================================================================

with tab_validation:
    if not auto.get("available"):
        st.error(f"Autonomous engine unavailable: {auto.get('error') or 'unknown error'}")
        empty_state("Validation and quality reports require the autonomous engine.")
    else:
        v1, v2, v3 = st.columns(3)
        with v1:
            score_card(
                "Validation score",
                validation.get("score", 0),
                unit="/100",
                meter=True,
                note="static checks",
            )
        with v2:
            score_card(
                "Quality score",
                quality.get("quality_score", 0),
                unit="/100",
                meter=True,
                note="heuristic",
            )
        with v3:
            score_card(
                "Reported status",
                "Valid" if validation.get("valid") else "Invalid",
                note=f"{len(validation.get('issues') or [])} issue(s) listed",
            )

        st.info(
            "These scores come from static text checks on the generated query — "
            "they are not calibrated probabilities and do not measure real-world "
            "detection effectiveness.",
            icon="ℹ️",
        )

        if validation.get("valid") and (validation.get("issues") or []):
            st.warning(
                "The validator reported this rule as valid **and** listed unresolved "
                "issues. Read the issues below before trusting the status.",
                icon="⚠️",
            )

        col_l, col_r = st.columns(2, gap="medium")

        with col_l:
            section("Reported issues")
            bullet_list(validation.get("issues"), "No issues reported.", icon="•")

            st.markdown("")
            section("Weaknesses")
            bullet_list(quality.get("weaknesses"), "No weaknesses reported.", icon="•")

        with col_r:
            section("Strengths")
            bullet_list(quality.get("strengths"), "No strengths reported.", icon="•")

            st.markdown("")
            section("False-positive considerations")
            caption_muted(
                "The generated rule may fire on legitimate activity such as "
                "administrative scripting, software deployment and automation "
                "frameworks. Tune against your own baseline before deploying."
            )

        st.markdown("")
        section("Validation scope")
        caption_muted(
            "Generated — produced by the template and knowledge-base pipeline. "
            "Statically checked — inspected for required fields and indicators as "
            "text. Externally validated — not performed; no Splunk instance is "
            "contacted by this tool."
        )


# ==========================================================================
# EXPORT
# ==========================================================================

with tab_export:
    payload = pipeline.export_payload(analysis)
    stamp = (analysis.get("generated_at") or "").replace(":", "").replace("-", "")

    section("Downloads")
    caption_muted(
        f"Exports reflect the analysis generated at {analysis.get('generated_at')} UTC "
        "from the description shown in the Overview tab."
    )

    d1, d2 = st.columns(2)

    with d1:
        st.download_button(
            "Full analysis (JSON)",
            data=json.dumps(payload, indent=2),
            file_name=f"ignite_analysis_{stamp}.json",
            mime="application/json",
            width="stretch",
        )

    with d2:
        st.download_button(
            "Best rule (.spl)",
            data=(best.get("rule") or "").strip() + "\n",
            file_name=f"ignite_best_rule_{stamp}.spl",
            mime="text/plain",
            width="stretch",
            disabled=not (best.get("rule") or "").strip(),
        )

    ranked = analysis.get("ranked", [])
    if len(ranked) > 1:
        combined = "\n\n".join(
            f"# Candidate {i + 1} — {r.get('origin', 'rule')} — score {r.get('score', 0)}\n"
            f"{(r.get('rule') or '').strip()}"
            for i, r in enumerate(ranked)
        )
        st.download_button(
            "All candidate rules (.spl)",
            data=combined + "\n",
            file_name=f"ignite_all_rules_{stamp}.spl",
            mime="text/plain",
        )

    st.markdown("")
    section("Export preview")
    with st.expander("Inspect JSON payload"):
        st.json(payload, expanded=False)


render_ai_panel()
