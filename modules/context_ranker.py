def rank_context_rules(
    attack_description,
    rules
):

    keywords = attack_description.lower().split()

    scored = []

    for rule in rules:

        score = 0

        title = rule["title"].lower()

        detection_text = str(
            rule["detection"]
        ).lower()

        for word in keywords:

            if word in title:
                score += 5

            if word in detection_text:
                score += 3

        scored.append(
            (
                score,
                rule
            )
        )

    scored.sort(
        reverse=True,
        key=lambda x: x[0]
    )

    return [
        r[1]
        for r in scored
    ]