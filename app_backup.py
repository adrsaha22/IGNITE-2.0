import streamlit as st
import json

from modules.detection_engine import generate_detections

st.set_page_config(
    page_title="AI Detection Rule Generator",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ AI Detection Rule Generator")

st.markdown("""
Generate Splunk detection rules automatically using:

- MITRE ATT&CK
- SigmaHQ
- Splunk
- Ollama/Qwen3
""")

attack_description = st.text_area(
    "Describe the attack scenario:",
    height=200,
    key="attack_input"
)

if st.button("Generate Detection Rules"):

    if not attack_description.strip():
        st.warning("Please enter an attack description.")
        st.stop()

    with st.spinner("Generating detections..."):

        result = generate_detections(
            attack_description
        )

    st.success("Detection Rules Generated")

    # -----------------------------
    # Download JSON
    # -----------------------------

    json_data = json.dumps(
        result,
        indent=4
    )

    st.download_button(
        label="📥 Download JSON",
        data=json_data,
        file_name="detections.json",
        mime="application/json"
    )

    # -----------------------------
    # MITRE SECTION
    # -----------------------------

    st.subheader("MITRE ATT&CK Mapping")

    col1, col2 = st.columns(2)

    with col1:
        st.metric(
            "Technique ID",
            result["mitre_id"]
        )

    with col2:
        st.metric(
            "Technique Name",
            result["mitre_name"]
        )

    st.divider()

    # -----------------------------
    # DETECTIONS
    # -----------------------------

    st.subheader("Generated Detection Rules")

    for i, detection in enumerate(
        result["detections"],
        start=1
    ):

        with st.expander(
            f"Detection {i}: {detection['title']}"
        ):

            # Confidence

            if "score" in detection:

                st.metric(
                    "Confidence",
                    f"{detection['score']}%"
                )

            # Status

            if "status" in detection:

                st.write(
                    f"**Status:** {detection['status']}"
                )

            # Log Source

            if "logsource" in detection:

                st.write(
                    "**Log Source**"
                )

                st.json(
                    detection["logsource"]
                )

            # ATT&CK Tags

            if detection.get("tags"):

                st.write(
                    "**ATT&CK Tags**"
                )

                st.write(
                    ", ".join(
                        detection["tags"]
                    )
                )

            # SPL Query

            st.write(
                "**Splunk Detection Query**"
            )

            st.code(
                detection["spl"],
                language="sql"
            )