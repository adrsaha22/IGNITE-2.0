from modules.context_builder import build_detection_context

rules = build_detection_context(
    "T1059.001"
)

for rule in rules:

    print("\nTITLE")
    print(rule["title"])

    print("\nDETECTION")
    print(rule["detection"])

    print("=" * 60)