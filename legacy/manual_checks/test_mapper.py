from modules.technique_mapper import (
    map_attack_to_techniques
)

attack = """
Attacker uses PowerShell to download malware
and creates a scheduled task for persistence.
"""

print(
    map_attack_to_techniques(
        attack
    )
)