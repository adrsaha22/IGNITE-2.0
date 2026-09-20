# modules/reasoning_engine.py

from modules.behavior_knowledge import BEHAVIOR_DB


def get_behavior_context(mitre_id):

    return BEHAVIOR_DB.get(
        mitre_id,
        {}
    )