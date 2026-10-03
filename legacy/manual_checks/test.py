from modules.sigma_search import search_sigma_by_attack

results = search_sigma_by_attack(
    "T1059.001"
)

print()

print(
    "Total Matches:",
    len(results)
)

for rule in results[:10]:

    print(
        rule["title"]
    )