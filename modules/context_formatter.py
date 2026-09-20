def build_llm_context(rules):

    context = ""

    for i, rule in enumerate(rules, start=1):

        context += f"""
Reference Detection {i}

Title:
{rule['title']}

Log Source:
{rule['logsource']}

Detection Logic:
{rule['detection']}

-------------------------------------
"""

    return context