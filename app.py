import streamlit as st
import json

from modules.detection_engine import generate_detections
from modules.ai_summary import summarize_attack

from modules.entity_extractor import extract_entities
from modules.rule_builder import build_splunk_rule
from modules.mitre_rule_builder import build_mitre_rule
from modules.rule_selector import select_best_rule

from modules.technique_mapper import map_attack_to_techniques
from modules.autonomous_rule_generator import generate_autonomous_rule
from modules.false_positive_reducer import reduce_false_positives
from modules.rule_validator import validate_rule
from modules.rule_quality import evaluate_rule_quality
from modules.explanation_engine import explain_detection

from modules.telemetry_engine import get_telemetry
from modules.telemetry_rule_builder import build_telemetry_rule

st.set_page_config(
    page_title="AI Detection Rule Generator",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ AI Detection Rule Generator")

st.markdown("""
Generate Detection Rules using:

- MITRE ATT&CK
- SigmaHQ
- Splunk
- Ollama
- AI Rule Generation
""")

attack_description = st.text_area(
    "Describe the attack scenario:",
    height=200
)

# ======================================
# AI ANALYSIS
# ======================================

if st.button("🤖 Generate AI Analysis"):

    if attack_description.strip():

        with st.spinner("Running AI Analysis..."):

            summary = summarize_attack(
                attack_description
            )

        st.subheader("🤖 AI Analysis")
        st.info(summary)

    else:

        st.warning(
            "Enter an attack description first."
        )

# ======================================
# DETECTION GENERATION
# ======================================

if st.button("🛡️ Generate Detection Rules"):

    if attack_description.strip() == "":

        st.warning(
            "Please enter an attack description."
        )

        st.stop()

    with st.spinner(
        "Generating detections..."
    ):

        result = generate_detections(
            attack_description
        )

    st.success(
        "Detection Rules Generated"
    )

    # ======================================
    # MITRE INFO
    # ======================================

    st.subheader("📊 Detection Summary")

    col1, col2, col3 = st.columns(3)

    with col1:

        st.metric(
            "MITRE Technique",
            result["mitre_id"]
        )

    with col2:

        st.metric(
            "Sigma Rules",
            len(result["detections"])
        )

    with col3:

        st.metric(
            "Technique Name",
            result["mitre_name"]
        )

    # ======================================
    # ENTITY EXTRACTION
    # ======================================

    entities = extract_entities(
        attack_description
    )

    st.divider()

    st.subheader(
        "🔍 Extracted Attack Entities"
    )

    st.json(
        entities
    )

    # ======================================
    # BEHAVIOR RULE
    # ======================================

    behavior_rule = build_splunk_rule(
        entities
    )

    # ======================================
    # MITRE RULE
    # ======================================

    mitre_rule = build_mitre_rule(
        result["mitre_id"]
    )

    # ======================================
    # SIGMA RULES
    # ======================================

    sigma_rules = []

    for detection in result["detections"]:

        sigma_rules.append(
            detection["spl"]
        )

    # ======================================
    # COMBINE RULES
    # ======================================

    all_rules = [
        behavior_rule,
        mitre_rule
    ]

    all_rules.extend(
        sigma_rules
    )

    ranked_rules = select_best_rule(
        all_rules
    )

    # ======================================
    # BEST RULE
    # ======================================

    st.divider()

    st.subheader(
        "🏆 Best Detection Rule"
    )

    best_rule = ranked_rules[0]

    st.success(
        f"Rule Score: {best_rule['score']}"
    )

    st.code(
        best_rule["rule"],
        language="sql"
    )

    # ======================================
    # AUTONOMOUS AI DETECTION ENGINE
    # ======================================

    st.divider()

    st.subheader(
        "🤖 Autonomous AI Detection Engine"
    )

    techniques = []
    autonomous_rule = ""
    validation = {}
    quality = {}
    explanation = ""

    try:

        techniques = map_attack_to_techniques(
            attack_description
        )

        telemetry = get_telemetry(
            techniques
        )

        telemetry_rule = build_telemetry_rule(
            telemetry
        )

        autonomous_rule = generate_autonomous_rule(
            techniques
        )

        autonomous_rule = reduce_false_positives(
            autonomous_rule
        )

        validation = validate_rule(
            autonomous_rule
        )

        quality = evaluate_rule_quality(
            autonomous_rule
        )

        explanation = explain_detection(
            attack_description,
            techniques,
            autonomous_rule
        )

        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric(
                "MITRE Techniques",
                len(techniques)
            )

        with col2:
            st.metric(
                "Validation Score",
                validation["score"]
            )

        with col3:
            st.metric(
                "Quality Score",
                quality["quality_score"]
            )

        with col4:
            st.metric(
                "Status",
                "Valid"
                if validation["valid"]
                else "Invalid"
            )

        st.write("### ATT&CK Techniques")
        st.write(", ".join(techniques))

        st.write("### Autonomous Detection Rule")

        st.code(
            autonomous_rule,
            language="sql"
        )

        st.write(
            "### Telemetry Aware Detection Rule"
        )

        st.code(
            telemetry_rule,
            language="sql"
        )

        st.write("### Validation Report")
        st.json(validation)

        st.write("### Quality Assessment")
        st.json(quality)

        st.write("### Detection Explanation")
        st.text(explanation)

    except Exception as e:

        st.error(
            f"Autonomous Engine Error: {str(e)}"
        )

    # ======================================
    # ALTERNATIVE RULES
    # ======================================

    st.divider()

    st.subheader(
        "📚 Alternative Detection Rules"
    )

    for i, item in enumerate(
        ranked_rules[1:],
        start=1
    ):

        with st.expander(
            f"Alternative Rule #{i} (Score: {item['score']})"
        ):

            st.code(
                item["rule"],
                language="sql"
            )

    # ======================================
    # ORIGINAL SIGMA DETECTIONS
    # ======================================

    st.divider()

    st.subheader(
        "📜 Sigma Detection References"
    )

    for i, detection in enumerate(
        result["detections"],
        start=1
    ):

        with st.expander(
            f"Sigma Detection {i}: {detection['title']}"
        ):

            if "score" in detection:

                st.metric(
                    "Confidence",
                    f"{detection['score']}%"
                )

            if "logsource" in detection:

                st.write(
                    "**Log Source**"
                )

                st.json(
                    detection["logsource"]
                )

            if detection.get(
                "tags"
            ):

                st.write(
                    "**MITRE Tags**"
                )

                st.write(
                    ", ".join(
                        detection["tags"]
                    )
                )

            st.code(
                detection["spl"],
                language="sql"
            )

    # ======================================
    # JSON EXPORT
    # ======================================

    st.divider()

    export_data = {
        "sigma_pipeline": result,
        "best_rule": best_rule,
        "techniques": techniques,
        "autonomous_rule": autonomous_rule,
        "validation": validation,
        "quality": quality,
        "explanation": explanation
    }

    json_data = json.dumps(
        export_data,
        indent=4
    )

    st.download_button(
        "📥 Download JSON",
        json_data,
        file_name="detections.json",
        mime="application/json"
    )
