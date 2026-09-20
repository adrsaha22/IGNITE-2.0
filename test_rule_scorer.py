from modules.rule_scorer import score_rule

rule = """
index=sysmon EventCode=1
Image="*powershell.exe*"
CommandLine="*IEX*"
| stats count by host user
"""

print(score_rule(rule))