def rank_rules(rules, attack_description):

    attack_text = attack_description.lower()

    scored_rules = []

    for rule in rules:

        score = 0

        title = rule["title"].lower()

        words = attack_text.split()

        for word in words:

            if word in title:
                score += 1

        scored_rules.append(
            (score, rule)
        )

    scored_rules.sort(
        key=lambda x: x[0],
        reverse=True
    )

    return [
        r[1]
        for r in scored_rules[:5]
    ]