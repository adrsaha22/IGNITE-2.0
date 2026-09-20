TELEMETRY_DB = {

    "T1059.001": {
        "name": "PowerShell",
        "datasources": [
            "Sysmon",
            "PowerShell Operational",
            "Windows Security"
        ],
        "eventcodes": [
            "1",
            "4104",
            "4688"
        ],
        "fields": [
            "Image",
            "CommandLine",
            "ParentImage",
            "User",
            "EventCode"
        ]
    },

    "T1105": {
        "name": "Ingress Tool Transfer",
        "datasources": [
            "Sysmon",
            "Proxy Logs"
        ],
        "eventcodes": [
            "1",
            "3"
        ],
        "fields": [
            "Image",
            "CommandLine",
            "DestinationIp",
            "DestinationHostname"
        ]
    },

    "T1053.005": {
        "name": "Scheduled Task",
        "datasources": [
            "Sysmon",
            "Windows Security",
            "TaskScheduler"
        ],
        "eventcodes": [
            "1",
            "4698"
        ],
        "fields": [
            "Image",
            "CommandLine",
            "TaskName",
            "User"
        ]
    },

    "T1547.001": {
        "name": "Registry Run Keys",
        "datasources": [
            "Sysmon"
        ],
        "eventcodes": [
            "13"
        ],
        "fields": [
            "TargetObject",
            "Details",
            "Image",
            "User"
        ]
    }
}