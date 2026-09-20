def map_attack_to_techniques(text):

    text = text.lower()

    techniques = []

    if (
        "powershell" in text
        or "iex" in text
        or "downloadstring" in text
    ):
        techniques.append(
            "T1059.001"
        )

    if (
        "download" in text
        or "curl" in text
        or "wget" in text
        or "certutil" in text
    ):
        techniques.append(
            "T1105"
        )

    if (
        "scheduled task" in text
        or "schtasks" in text
        or "persistence" in text
    ):
        techniques.append(
            "T1053.005"
        )

    return list(
        set(techniques)
    )