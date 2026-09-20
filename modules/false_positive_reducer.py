def reduce_false_positives(rule):

    # PowerShell specific
    if (
        "powershell.exe" in rule.lower()
        or "iex" in rule.lower()
        or "downloadstring" in rule.lower()
    ):

        return """
index=sysmon EventCode=1
Image="*powershell.exe*"
(
CommandLine="*IEX*"
OR CommandLine="*DownloadString*"
OR CommandLine="*Invoke-WebRequest*"
)
| stats count by host user Image CommandLine ParentImage
"""

    # Scheduled Task specific
    if (
        "schtasks" in rule.lower()
        or "/create" in rule.lower()
    ):

        return """
index=sysmon EventCode=1
Image="*schtasks.exe*"
(
CommandLine="*/create*"
OR CommandLine="*/sc*"
OR CommandLine="*/tn*"
)
| stats count by host user Image CommandLine ParentImage
"""

    return rule