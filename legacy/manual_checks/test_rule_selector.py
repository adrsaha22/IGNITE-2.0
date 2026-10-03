from modules.rule_selector import select_best_rule

rules = [

"""
index=sysmon EventCode=1
Image="*powershell.exe*"
CommandLine="*IEX*"
| stats count by host user
""",

"""
index=sysmon
powershell
""",

"""
EventCode=1
CommandLine="*DownloadString*"
"""
]

results = select_best_rule(rules)

for item in results:

    print("\nSCORE:", item["score"])
    print(item["rule"])
    print("=" * 60)