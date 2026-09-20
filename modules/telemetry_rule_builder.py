def build_telemetry_rule(telemetry):

    event_filters = []

    for event in telemetry["events"]:

        event_filters.append(
            f"EventCode={event}"
        )

    event_block = " OR ".join(
        event_filters
    )

    indicator_filters = []

    for indicator in telemetry["indicators"]:

        indicator_filters.append(
            f'CommandLine="*{indicator}*"'
        )

    indicator_block = " OR ".join(
        indicator_filters
    )

    rule = f"""
index=sysmon

(
{event_block}
)

(
{indicator_block}
)

| stats count by host user Image CommandLine ParentImage
"""

    return rule