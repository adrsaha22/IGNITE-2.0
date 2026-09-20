def explain_detection(
    attack_description,
    techniques,
    rule
):

    explanation = []

    explanation.append(
        f"Attack Summary: {attack_description}"
    )

    explanation.append(
        "\nDetected ATT&CK Techniques:"
    )

    for technique in techniques:

        explanation.append(
            f"- {technique}"
        )

    explanation.append(
        "\nWhy this detection works:"
    )

    if "powershell" in rule.lower():
        explanation.append(
            "- Monitors PowerShell execution activity"
        )

    if "iex" in rule.lower():
        explanation.append(
            "- Detects in-memory code execution"
        )

    if "downloadstring" in rule.lower():
        explanation.append(
            "- Detects payload download behavior"
        )

    if "schtasks" in rule.lower():
        explanation.append(
            "- Detects scheduled task persistence"
        )

    if "certutil" in rule.lower():
        explanation.append(
            "- Detects LOLBin file downloads"
        )

    explanation.append(
        "\nPotential False Positives:"
    )

    explanation.append(
        "- Administrative scripts"
    )

    explanation.append(
        "- Software deployment tools"
    )

    explanation.append(
        "- Automation frameworks"
    )

    return "\n".join(explanation)