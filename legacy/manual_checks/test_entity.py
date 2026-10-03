from modules.entity_extractor import extract_entities

attack = """
Attacker uses PowerShell to download
a payload from GitHub and execute it
in memory using IEX.
"""

result = extract_entities(
    attack
)

print(result)