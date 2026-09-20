def convert_sigma_to_splunk(parsed_rule):

    detection = parsed_rule.get(
        "detection",
        {}
    )

    conditions = []

    for key, value in detection.items():

        if key == "condition":
            continue

        if not isinstance(value, dict):
            continue

        for field, field_value in value.items():

            if isinstance(field_value, list):

                sub_conditions = []

                for item in field_value[:20]:

                    sub_conditions.append(
                        f'{field}="*{item}*"'
                    )

                conditions.append(
                    "(" +
                    " OR ".join(sub_conditions) +
                    ")"
                )

            else:

                conditions.append(
                    f'{field}="*{field_value}*"'
                )

    if not conditions:

        return "index=*"

    return (
        "search " +
        " AND ".join(conditions)
    )