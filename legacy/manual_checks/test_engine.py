from modules.detection_engine import generate_detections

attack = """
Attacker uses PowerShell to download
a payload from GitHub and execute
it in memory.
"""

result = generate_detections(
    attack
)

print()

print("MITRE")

print(
    result["mitre_id"]
)

print(
    result["mitre_name"]
)

print()

for i, detection in enumerate(
    result["detections"],
    start=1
):

    print(
        "=" * 60
    )

    print(
        f"DETECTION {i}"
    )

    print(
        detection["title"]
    )

    print()

    print(
        detection["spl"]
    )