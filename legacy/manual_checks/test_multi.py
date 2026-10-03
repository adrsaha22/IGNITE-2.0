from modules.sigma_search import search_sigma_by_attack
from modules.rule_ranker import rank_rules
from modules.sigma_parser import parse_sigma_rule
from modules.sigma_to_splunk import convert_sigma_to_splunk

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

for i, rule_info in enumerate(top_rules, start=1):

    parsed = parse_sigma_rule(
        rule_info["path"]
    )

    spl = convert_sigma_to_splunk(
        parsed
    )

    print("\n")
    print("=" * 60)

    print(
        f"DETECTION {i}"
    )

    print(
        parsed["title"]
    )

    print("\nSPLUNK:")

    print(spl)