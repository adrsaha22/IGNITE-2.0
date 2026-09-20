import requests


def summarize_attack(description):

    try:

        prompt = f"""
Analyze this attack description.

Return:

1. Behaviors
2. Tools
3. Likely ATT&CK Techniques
4. Keywords

Attack:

{description}

Keep the response concise.
"""

        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "llama3.2:1b",
                "prompt": prompt,
                "stream": False
            },
            timeout=60
        )

        return response.json()["response"]

    except Exception as e:

        return f"AI analysis unavailable: {e}"