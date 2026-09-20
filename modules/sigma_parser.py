import yaml


def parse_sigma_rule(rule_path):

    try:

        with open(
            rule_path,
            "r",
            encoding="utf-8"
        ) as f:

            rule = yaml.safe_load(f)

        return {

            "title": rule.get(
                "title",
                "Unknown"
            ),

            "description": rule.get(
                "description",
                ""
            ),

            "tags": rule.get(
                "tags",
                []
            ),

            "logsource": rule.get(
                "logsource",
                {}
            ),

            "detection": rule.get(
                "detection",
                {}
            )
        }

    except Exception as e:

        print(e)

        return None