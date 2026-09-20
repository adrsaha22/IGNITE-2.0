def evaluate_rule_quality(rule):

    score = 0

    strengths = []
    weaknesses = []

    if "EventCode=1" in rule:
        score += 15
        strengths.append(
            "Uses process creation events"
        )

    if "Image=" in rule:
        score += 20
        strengths.append(
            "Filters on process image"
        )

    if "CommandLine=" in rule:
        score += 20
        strengths.append(
            "Uses command line indicators"
        )

    if "ParentImage" in rule:
        score += 10
        strengths.append(
            "Captures parent-child relationships"
        )

    if "| stats" in rule:
        score += 15
        strengths.append(
            "Includes aggregation"
        )

    if "OR" in rule and "AND" not in rule:
        weaknesses.append(
            "Broad OR logic may create false positives"
        )
        score -= 10

    if score > 100:
        score = 100

    return {
        "quality_score": score,
        "strengths": strengths,
        "weaknesses": weaknesses
    }