def score_rule(rule):

    score = 0

    if "EventCode=1" in rule:
        score += 20

    if "Image" in rule:
        score += 20

    if "CommandLine" in rule:
        score += 20

    if "ParentImage" in rule:
        score += 10

    if "| stats" in rule:
        score += 10

    indicators = [
        "DownloadString",
        "Invoke-WebRequest",
        "IEX",
        "WebClient",
        "certutil",
        "powershell"
    ]

    for indicator in indicators:
        if indicator.lower() in rule.lower():
            score += 5

    return score