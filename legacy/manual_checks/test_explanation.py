from modules.technique_mapper import (
    map_attack_to_techniques
)

from modules.autonomous_rule_generator import (
    generate_autonomous_rule
)

from modules.explanation_engine import (
    explain_detection
)

attack = """
Attacker uses PowerShell to
download malware and creates
a scheduled task for persistence.
"""

techniques = map_attack_to_techniques(
    attack
)

rule = generate_autonomous_rule(
    techniques
)

print(
    explain_detection(
        attack,
        techniques,
        rule
    )
)