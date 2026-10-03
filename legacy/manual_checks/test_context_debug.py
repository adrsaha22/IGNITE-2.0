# test_context_debug.py

from modules.reasoning_engine import get_behavior_context

for t in [
    "T1059.001",
    "T1105",
    "T1053.005"
]:

    print("\n")
    print(t)

    context = get_behavior_context(t)

    print(context)