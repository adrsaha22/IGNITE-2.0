SPLUNK_RULES = {

    "T1059.001": {
        "title": "Suspicious PowerShell Download",

        "severity": "High",

        "spl": """
index=windows
EventCode=4104
(
ScriptBlockText="*Invoke-WebRequest*"
OR ScriptBlockText="*DownloadString*"
OR ScriptBlockText="*Net.WebClient*"
)
"""
    },

    "T1003.001": {
        "title": "LSASS Credential Dumping",

        "severity": "Critical",

        "spl": """
index=windows
EventCode=4688
(
CommandLine="*sekurlsa*"
OR CommandLine="*mimikatz*"
OR process_name="mimikatz.exe"
)
"""
    },

    "T1569.002": {
        "title": "PsExec Remote Execution",

        "severity": "High",

        "spl": """
index=windows
EventCode=4688
(
process_name="psexec.exe"
OR CommandLine="*psexec*"
)
"""
    },

    "T1053.005": {
        "title": "Scheduled Task Persistence",

        "severity": "Medium",

        "spl": """
index=windows
EventCode=4698
"""
    },

    "T1047": {
        "title": "WMI Execution",

        "severity": "High",

        "spl": """
index=windows
EventCode=4688
(
CommandLine="*wmic*"
OR ParentProcessName="WmiPrvSE.exe"
)
"""
    }
}