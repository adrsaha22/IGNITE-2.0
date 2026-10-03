from modules.context_builder import build_detection_context
from modules.context_ranker import rank_context_rules
from modules.context_formatter import build_llm_context

from modules.llm_generator import generate_detection

attack = """
Attacker uses PowerShell to download
a payload from GitHub and execute it
in memory.
"""

rules = build_detection_context(
    "T1059.001",
    limit=30
)

ranked = rank_context_rules(
    attack,
    rules
)

context = build_llm_context(
    ranked[:2]
)

result = generate_detection(
    attack,
    {
        "id": "T1059.001",
        "name": "PowerShell"
    },
    context
)

print(result)