MITRE_CONTEXT = {

    "T1059.001": {
        "logs": [
            "Sysmon",
            "PowerShell Operational",
            "Windows Security"
        ],

        "fields": [
            "Image",
            "CommandLine",
            "ParentImage",
            "User",
            "EventCode"
        ],

        "indicators": [
            "powershell.exe",
            "pwsh.exe",
            "IEX",
            "DownloadString",
            "Invoke-WebRequest",
            "Invoke-RestMethod",
            "WebClient"
        ]
    }

}