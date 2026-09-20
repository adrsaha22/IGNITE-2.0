from modules.reasoning_engine import (
    get_behavior_context
)

from modules.detection_logic_builder import (
    build_logic
)


def generate_autonomous_rule(
    techniques
):

    all_conditions = []

    for mitre_id in techniques:

        context = get_behavior_context(
            mitre_id
        )

        logic = build_logic(
            context
        )

        if logic["logic"]:
            all_conditions.append(
                logic["logic"]
            )

    combined_logic = " OR ".join(
        all_conditions
    )

    query = f"""
index=sysmon EventCode=1
({combined_logic})
| stats count by host user Image CommandLine ParentImage
"""

    return query