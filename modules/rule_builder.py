def build_splunk_rule(entities):

    query_parts = []

    # Base Sysmon Process Creation
    query_parts.append(
        "index=sysmon EventCode=1"
    )

    # Tools
    for tool in entities["tools"]:

        query_parts.append(
            f'Image="*{tool}*"'
        )

    # Indicators
    indicator_queries = []

    for indicator in entities["indicators"]:

        indicator_queries.append(
            f'CommandLine="*{indicator}*"'
        )

    if indicator_queries:

        query_parts.append(
            "(" +
            " OR ".join(indicator_queries) +
            ")"
        )

    query = " ".join(query_parts)

    query += """
 | stats count by host user Image CommandLine ParentImage
"""

    return query