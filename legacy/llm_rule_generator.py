import requests


def generate_custom_rule(
    attack_description,
    mitre_id,
    sigma_examples
):

    prompt = f"""
You are a Senior Splunk Detection Engineer.

Attack Description:
{attack_description}

MITRE Technique:
{mitre_id}

Reference Sigma Examples:
{sigma_examples}

Generate:

1. Detection Title
2. Description
3. Splunk SPL Query
4. Why this detection works

Create a NEW detection rule.
Do not copy the examples.
"""

    response = requests.post(
        "http://localhost:11434/api/generate",
        json={
            "model": "llama3.2:1b",
            "prompt": prompt,
            "stream": False
        },
        timeout=120
    )

    return response.json()["response"]