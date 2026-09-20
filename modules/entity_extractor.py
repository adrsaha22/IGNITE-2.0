import re


def extract_entities(attack_description):

    text = attack_description.lower()

    result = {
        "tools": [],
        "indicators": [],
        "logs": [],
        "fields": []
    }

    # ------------------
    # PowerShell
    # ------------------

    if any(x in text for x in [
        "powershell",
        "pwsh",
        "iex",
        "downloadstring",
        "invoke-webrequest",
        "invoke-restmethod"
    ]):

        result["tools"].append(
            "powershell.exe"
        )

        result["logs"].append(
            "Sysmon"
        )

        result["fields"].extend([
            "Image",
            "CommandLine",
            "ParentImage"
        ])

    # ------------------
    # Certutil
    # ------------------

    if "certutil" in text:

        result["tools"].append(
            "certutil.exe"
        )

        result["logs"].append(
            "Sysmon"
        )

        result["fields"].extend([
            "Image",
            "CommandLine"
        ])

    # ------------------
    # Rundll32
    # ------------------

    if "rundll32" in text:

        result["tools"].append(
            "rundll32.exe"
        )

        result["logs"].append(
            "Sysmon"
        )

        result["fields"].extend([
            "Image",
            "CommandLine"
        ])

    # ------------------
    # GitHub
    # ------------------

    if "github" in text:

        result["indicators"].append(
            "github"
        )

    # ------------------
    # Download Activity
    # ------------------

    if any(x in text for x in [
        "download",
        "payload",
        "malware"
    ]):

        result["indicators"].extend([
            "DownloadString",
            "Invoke-WebRequest",
            "WebClient"
        ])

    # Remove duplicates

    result["tools"] = list(
        set(result["tools"])
    )

    result["indicators"] = list(
        set(result["indicators"])
    )

    result["logs"] = list(
        set(result["logs"])
    )

    result["fields"] = list(
        set(result["fields"])
    )

    return result