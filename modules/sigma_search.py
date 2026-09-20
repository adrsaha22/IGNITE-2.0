import os
import yaml

SIGMA_PATH = "data/sigma/rules"


def search_sigma_by_attack(attack_id):

    matches = []

    for root, dirs, files in os.walk(SIGMA_PATH):

        for file in files:

            if not file.endswith(".yml"):
                continue

            path = os.path.join(root, file)

            try:

                with open(
                    path,
                    "r",
                    encoding="utf-8"
                ) as f:

                    rule = yaml.safe_load(f)

                tags = rule.get(
                    "tags",
                    []
                )

                for tag in tags:

                    if attack_id.lower() in tag.lower():

                        matches.append(
                            {
                                "title": rule.get(
                                    "title",
                                    "Unknown"
                                ),
                                "path": path
                            }
                        )

                        break

            except:
                pass

    return matches