from modules.technique_mapper import (
    map_attack_to_techniques
)

from modules.autonomous_rule_generator import (
    generate_autonomous_rule
)

attack = """
Attacker uses PowerShell to download malware
and creates a scheduled task for persistence.
"""

techniques = map_attack_to_techniques(
    attack
)

print(
    generate_autonomous_rule(
        techniques
    )
)