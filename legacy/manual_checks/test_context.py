from modules.sigma_search import search_sigma_by_attack
from modules.sigma_parser import parse_sigma_rule

matches = search_sigma_by_attack(
    "T1059.001"
)

print("MATCHES:", len(matches))

for rule in matches[:3]:

    print("\nTITLE:")
    print(rule["title"])

    print("\nPATH:")
    print(rule["path"])

    parsed = parse_sigma_rule(
        rule["path"]
    )

    print("\nLOGSOURCE:")
    print(parsed["logsource"])

    print("\nDETECTION:")
    print(parsed["detection"])

    print("=" * 60)