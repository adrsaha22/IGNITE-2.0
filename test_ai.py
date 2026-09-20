from modules.ai_summary import summarize_attack

attack = """
Attacker uses PowerShell to download
a payload from GitHub and execute
it in memory.
"""

print(
    summarize_attack(
        attack
    )
)