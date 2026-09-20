from modules.entity_extractor import extract_entities
from modules.rule_builder import build_splunk_rule

attack = """
Attacker uses PowerShell to download
a payload from GitHub and execute it
in memory using IEX.
"""

entities = extract_entities(
    attack
)

rule = build_splunk_rule(
    entities
)

print(rule)