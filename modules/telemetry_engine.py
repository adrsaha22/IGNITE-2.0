import json
import os

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")

with open(
    os.path.join(DATA_DIR, "telemetry_catalog.json"),
    "r",
    encoding="utf-8"
) as f:

    TELEMETRY = json.load(f)


def get_telemetry(techniques):

    logs = set()
    fields = set()
    events = set()
    indicators = set()

    for technique in techniques:

        if technique not in TELEMETRY:
            continue

        data = TELEMETRY[technique]

        logs.update(data["logs"])
        fields.update(data["fields"])
        events.update(data["event_ids"])
        indicators.update(data["indicators"])

    return {
        "logs": list(logs),
        "fields": list(fields),
        "events": list(events),
        "indicators": list(indicators)
    }