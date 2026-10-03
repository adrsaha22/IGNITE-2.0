# test_ollama.py

import ollama

response = ollama.chat(
    model="qwen3:4b",
    messages=[
        {
            "role": "user",
            "content": "Generate a one-line Splunk rule for PowerShell download activity."
        }
    ]
)

print(response["message"]["content"])