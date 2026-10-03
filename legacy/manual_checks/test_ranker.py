from modules.sigma_search import search_sigma_by_attack
from modules.rule_ranker import rank_rules

attack = """
PowerShell downloads a payload
from GitHub and executes it.
"""

rules = search_sigma_by_attack(
    "T1059.001"
)

top_rules = rank_rules(
    rules,
    attack
)

for rule in top_rules:

    print(rule["title"])