MITRE_TELEMETRY = {

    "T1059.001": {
        "logs": [
            "Sysmon",
            "PowerShell Operational",
            "Windows Security"
        ],

        "events": [
            1,
            4104,
            4688
        ],

        "fields": [
            "Image",
            "CommandLine",
            "ParentImage",
            "User"
        ]
    },

    "T1105": {
        "logs": [
            "Sysmon"
        ],

        "events": [
            3
        ],

        "fields": [
            "DestinationIp",
            "DestinationPort",
            "Image"
        ]
    },

    "T1053.005": {
        "logs": [
            "Sysmon",
            "Task Scheduler"
        ],

        "events": [
            1,
            4698
        ],

        "fields": [
            "Image",
            "CommandLine",
            "User"
        ]
    }
}
def get_telemetry_context(techniques):

    logs = set()
    events = set()
    fields = set()

    for tech in techniques:

        if tech not in MITRE_TELEMETRY:
            continue

        info = MITRE_TELEMETRY[tech]

        logs.update(
            info["logs"]
        )

        events.update(
            info["events"]
        )

        fields.update(
            info["fields"]
        )

    return {
        "logs": list(logs),
        "events": list(events),
        "fields": list(fields)
    }