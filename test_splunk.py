from modules.sigma_search import search_sigma_by_attack
from modules.sigma_parser import parse_sigma_rule
from modules.sigma_to_splunk import convert_sigma_to_splunk

results = search_sigma_by_attack(
    "T1059.001"
)

rule = parse_sigma_rule(
    results[0]["path"]
)

spl = convert_sigma_to_splunk(
    rule
)

print()

print("RULE:")
print(rule["title"])

print()

print("SPLUNK QUERY:")
print(spl)