from modules.context_builder import build_detection_context
from modules.context_ranker import rank_context_rules
from modules.context_formatter import build_llm_context

attack = """
PowerShell downloads a payload
from GitHub and executes it
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
    ranked[:5]
)

print(context)