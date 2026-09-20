from modules.detection_library import SPLUNK_RULES


def generate_rule(technique_id):

    if technique_id in SPLUNK_RULES:

        return SPLUNK_RULES[technique_id]

    return {

        "title": "Generic Detection",

        "severity": "Low",

        "spl": """
index=*
"""
    }