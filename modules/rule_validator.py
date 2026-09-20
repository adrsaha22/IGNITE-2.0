def validate_rule(rule):

    issues = []
    score = 100

    # Data Source
    if "index=" not in rule:
        issues.append(
            "Missing datasource/index"
        )
        score -= 20

    # EventCode
    if "EventCode" not in rule:
        issues.append(
            "Missing EventCode"
        )
        score -= 15

    # CommandLine
    if "CommandLine" not in rule:
        issues.append(
            "Missing CommandLine field"
        )
        score -= 10

    # Image
    if "Image" not in rule:
        issues.append(
            "Missing Image field"
        )
        score -= 10

    # Aggregation
    if "| stats" not in rule:
        issues.append(
            "Missing aggregation"
        )
        score -= 15

    # Indicators
    indicators = [
        "powershell",
        "iex",
        "downloadstring",
        "invoke-webrequest",
        "curl",
        "wget",
        "certutil",
        "schtasks"
    ]

    found = False

    for indicator in indicators:

        if indicator.lower() in rule.lower():
            found = True
            break

    if not found:

        issues.append(
            "No attack indicators found"
        )

        score -= 20

    return {
        "valid": score >= 70,
        "score": max(score, 0),
        "issues": issues
    }