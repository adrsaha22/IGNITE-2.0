from modules.mitre_rule_builder import build_mitre_rule

rule = build_mitre_rule(
    "T1059.001"
)

print(rule)