# test_autonomous_validation.py

from modules.technique_mapper import (
    map_attack_to_techniques
)

from modules.autonomous_rule_generator import (
    generate_autonomous_rule
)

from modules.rule_validator import (
    validate_rule
)

attack = """
Attacker uses PowerShell
to download malware and
creates a scheduled task
for persistence.
"""

techniques = map_attack_to_techniques(
    attack
)

rule = generate_autonomous_rule(
    techniques
)

validation = validate_rule(
    rule
)

print("\nRULE\n")
print(rule)

print("\nVALIDATION\n")
print(validation)