from modules.mitre_lookup import find_technique
from modules.sigma_search import search_sigma_by_attack
from modules.rule_ranker import rank_rules
from modules.sigma_parser import parse_sigma_rule
from modules.sigma_to_splunk import convert_sigma_to_splunk


def generate_detections(attack_description):

    mitre = find_technique(
        attack_description
    )

    attack_id = mitre["id"]

    sigma_rules = search_sigma_by_attack(
        attack_id
    )

    ranked_rules = rank_rules(
        sigma_rules,
        attack_description
    )

    detections = []

    for rule_info in ranked_rules[:5]:

        try:

            parsed_rule = parse_sigma_rule(
                rule_info["path"]
            )

            spl = convert_sigma_to_splunk(
                parsed_rule
            )

            score = max(
                100 - (len(detections) * 10),
                60
            )

            detections.append({

                "title":
                parsed_rule.get(
                    "title",
                    "Unknown Rule"
                ),

                "spl":
                spl,

                "tags":
                parsed_rule.get(
                    "tags",
                    []
                ),

                "score":
                score,

                "status":
                parsed_rule.get(
                    "status",
                    "unknown"
                ),

                "logsource":
                parsed_rule.get(
                    "logsource",
                    {}
                )

            })

        except Exception as e:

            print(
                f"Error parsing rule: {e}"
            )

    return {

        "mitre_id":
        mitre["id"],

        "mitre_name":
        mitre["name"],

        "detections":
        detections

    }