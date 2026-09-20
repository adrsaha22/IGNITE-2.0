from modules.mitre_context import MITRE_CONTEXT


def build_mitre_rule(mitre_id):

    data = MITRE_CONTEXT.get(
        mitre_id,
        {}
    )

    logs = data.get(
        "logs",
        []
    )

    fields = data.get(
        "fields",
        []
    )

    indicators = data.get(
        "indicators",
        []
    )

    query = "index=sysmon EventCode=1 "

    indicator_conditions = []

    for indicator in indicators:

        indicator_conditions.append(
            f'CommandLine="*{indicator}*"'
        )

    if indicator_conditions:

        query += "("
        query += " OR ".join(
            indicator_conditions
        )
        query += ")"

    query += """
 | stats count by host user Image CommandLine ParentImage
"""

    return query