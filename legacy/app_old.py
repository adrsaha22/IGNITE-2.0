import streamlit as st

from modules.mitre_lookup import find_technique
from modules.sigma_lookup import find_sigma_rules
from modules.rule_generator import generate_rule

st.set_page_config(
    page_title="AI Detection Rule Generator",
    layout="wide"
)

st.title("🛡️ AI Detection Rule Generator")

st.markdown("""
Generate MITRE ATT&CK mappings, Sigma matches, and Splunk detection rules automatically.
""")

attack_description = st.text_area(
    "Enter Attack Description",
    height=200,
    key="attack_input"
)

if st.button("Generate Detection"):

    if attack_description.strip():

        # MITRE Mapping
        mitre = find_technique(
            attack_description
        )

        # Sigma Mapping
        sigma_rules = find_sigma_rules(
            attack_description
        )

        # Detection Rule
        rule = generate_rule(
            mitre["id"]
        )

        col1, col2 = st.columns(2)

        # LEFT PANEL
        with col1:

            st.subheader("MITRE ATT&CK")

            st.info(
                f"{mitre['id']} - {mitre['name']}"
            )

            if mitre.get("description"):
                st.caption(
                    mitre["description"][:500]
                )

        # RIGHT PANEL
        with col2:

            st.subheader("Sigma Matches")

            if sigma_rules:

                for sigma in sigma_rules:
                    st.success(sigma)

            else:
                st.warning(
                    "No Sigma rules found."
                )

        st.divider()

        # Detection Section

        st.subheader("Detection Title")

        st.success(
            rule["title"]
        )

        st.subheader("Severity")

        severity = rule["severity"]

        if severity == "Critical":
            st.error(severity)

        elif severity == "High":
            st.warning(severity)

        elif severity == "Medium":
            st.info(severity)

        else:
            st.success(severity)

        st.subheader(
            "Generated Splunk Detection"
        )

        st.code(
            rule["spl"],
            language="sql"
        )

    else:

        st.warning(
            "Please enter an attack description."
        )