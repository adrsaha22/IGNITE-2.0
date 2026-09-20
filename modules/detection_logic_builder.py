def build_logic(context):

    fields = context.get(
        "fields",
        []
    )

    indicators = context.get(
        "indicators",
        []
    )

    conditions = []

    for indicator in indicators:

        conditions.append(
            f'CommandLine="*{indicator}*"'
        )

    logic = " OR ".join(
        conditions
    )

    return {
        "fields": fields,
        "logic": logic
    }