def telemetry_score(rule):

    score = 0

    if "EventCode" in rule:
        score += 30

    if "CommandLine" in rule:
        score += 20

    if "Image" in rule:
        score += 20

    if "ParentImage" in rule:
        score += 10

    if "| stats" in rule:
        score += 20

    return score