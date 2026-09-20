from modules.sigma_search import search_sigma_by_attack
from modules.sigma_parser import parse_sigma_rule


def build_detection_context(attack_id, limit=5):

    matches = search_sigma_by_attack(attack_id)

    context = []

    for rule in matches[:limit]:

        try:

            parsed = parse_sigma_rule(
                rule["path"]
            )

            context.append(
                {
                    "title": rule["title"],
                    "logsource": parsed["logsource"],
                    "detection": parsed["detection"]
                }
            )

        except:
            pass

    return context