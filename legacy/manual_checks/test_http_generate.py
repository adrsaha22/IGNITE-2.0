import requests
import json

payload = {
    "model": "qwen3:4b",
    "messages": [
        {
            "role": "user",
            "content": "Say hello"
        }
    ],
    "stream": False
}

r = requests.post(
    "http://127.0.0.1:11434/api/chat",
    json=payload,
    timeout=120
)

print(r.status_code)
print(r.json())