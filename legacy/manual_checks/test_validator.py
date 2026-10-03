from modules.rule_validator import (
    validate_rule
)

rule = """
index=sysmon EventCode=1
Image="*powershell.exe*"
CommandLine="*IEX*"
| stats count by host user
"""

result = validate_rule(
    rule
)

print(result)