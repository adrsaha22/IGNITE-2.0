from modules.llm_generator import generate_detection

attack = """
Attacker uses PowerShell to download
a payload from GitHub and execute it
in memory.
"""

mitre = {
    "id": "T1059.001",
    "name": "PowerShell"
}

sigma = [
    "Suspicious PowerShell Download",
    "Remote PowerShell Execution",
    "PowerShell Policy Bypass"
]

result = generate_detection(
    attack,
    mitre,
    sigma
)

print(result)