from modules.sigma_search import search_sigma_by_attack
from modules.sigma_parser import parse_sigma_rule

results = search_sigma_by_attack(
    "T1059.001"
)

first_rule = results[0]

print("RULE TITLE:")
print(first_rule["title"])

print("\nPATH:")
print(first_rule["path"])

parsed = parse_sigma_rule(
    first_rule["path"]
)

print("\nPARSED DATA")

print(parsed["title"])

print(parsed["tags"])

print(parsed["logsource"])

print(parsed["detection"])