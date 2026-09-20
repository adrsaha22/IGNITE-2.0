from modules.rule_scorer import score_rule


def select_best_rule(rules):

    ranked = []

    for rule in rules:

        ranked.append({
            "rule": rule,
            "score": score_rule(rule)
        })

    ranked.sort(
        key=lambda x: x["score"],
        reverse=True
    )

    return ranked