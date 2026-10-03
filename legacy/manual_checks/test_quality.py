# test_quality.py

from modules.rule_quality import (
    evaluate_rule_quality
)

rule = """
index=sysmon EventCode=1
Image="*powershell.exe*"
CommandLine="*IEX*"
| stats count by host user
"""

print(
    evaluate_rule_quality(
        rule
    )
)