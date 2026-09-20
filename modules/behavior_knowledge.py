# modules/behavior_knowledge.py

BEHAVIOR_DB = {
    
"T1105": {

    "name": "Ingress Tool Transfer",

    "logs": [
        "Sysmon",
        "Windows Security"
    ],

    "fields": [
        "Image",
        "CommandLine",
        "DestinationIp"
    ],

    "indicators": [
        "curl",
        "wget",
        "certutil",
        "bitsadmin",
        "download",
        "transfer"
    ]
},

"T1053.005": {

    "name": "Scheduled Task",

    "logs": [
        "Task Scheduler",
        "Sysmon",
        "Windows Security"
    ],

    "fields": [
        "Image",
        "CommandLine",
        "TaskName"
    ],

    "indicators": [
        "schtasks.exe",
        "/create",
        "/sc",
        "/tn",
        "scheduled task"
    ]
}
}