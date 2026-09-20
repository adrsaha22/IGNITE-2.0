import json
import os

MITRE_FILE = os.path.join(
    "data",
    "mitre.json"
)

def load_mitre():

    with open(MITRE_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    techniques = {}

    for obj in data.get("objects", []):

        if obj.get("type") != "attack-pattern":
            continue

        attack_id = None

        for ref in obj.get(
            "external_references",
            []
        ):

            if ref.get("source_name") == "mitre-attack":

                attack_id = ref.get(
                    "external_id"
                )

                break

        if attack_id:

            techniques[attack_id] = {
                "id": attack_id,
                "name": obj.get("name", ""),
                "description": obj.get(
                    "description",
                    ""
                )
            }

    return techniques


MITRE_DATA = load_mitre()


KEYWORD_MAP = {

    "powershell": "T1059.001",

    "mimikatz": "T1003.001",

    "credential dump": "T1003",

    "credential dumping": "T1003",

    "lsass": "T1003.001",

    "psexec": "T1569.002",

    "scheduled task": "T1053.005",

    "task scheduler": "T1053.005",

    "wmi": "T1047",

    "rundll32": "T1218.011",

    "regsvr32": "T1218.010",

    "remote desktop": "T1021.001",

    "vnc": "T1021.005"
}


def find_technique(description):

    text = description.lower()

    for keyword, technique_id in KEYWORD_MAP.items():

        if keyword in text:

            if technique_id in MITRE_DATA:

                return MITRE_DATA[technique_id]

    return {
        "id": "Unknown",
        "name": "Unknown",
        "description": ""
    }