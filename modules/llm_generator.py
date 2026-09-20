import ollama

from modules.mitre_context import MITRE_CONTEXT

MODEL = "llama3.2:1b"


def generate_detection(
    attack_description,
    mitre,
    detection_context
):

    mitre_data = MITRE_CONTEXT.get(
        mitre["id"],
        {}
    )

    logs = mitre_data.get(
        "logs",
        []
    )

    fields = mitre_data.get(
        "fields",
        []
    )

    indicators = mitre_data.get(
        "indicators",
        []
    )

    prompt = f"""
You are a Senior Cyber Detection Engineer.

Attack Description:
{attack_description}

MITRE Technique:
{mitre['id']} - {mitre['name']}

MITRE Detection Knowledge

Relevant Logs:
{", ".join(logs)}

Relevant Fields:
{", ".join(fields)}

Common Indicators:
{", ".join(indicators)}

Reference Detection Logic:

{detection_context}

Your task:

Generate a NEW Splunk detection rule.

Return EXACTLY:

Detection Title:

Detection Description:

Splunk SPL Query:

Detection Logic:

False Positives:

Requirements:

- Use valid Splunk SPL syntax
- Use realistic fields
- Do not output JSON
- Do not invent data sources
- Learn from the reference detections
- Focus on the attack description
- Prefer Sysmon EventCode=1 for process execution
- Use CommandLine when relevant
- Use Image when relevant
- Use ParentImage when relevant
"""

    response = ollama.chat(
        model=MODEL,
        messages=[
            {
                "role": "system",
                "content": "You are a senior detection engineer specializing in Splunk."
            },
            {
                "role": "user",
                "content": prompt
            }
        ]
    )

    return response["message"]["content"]
