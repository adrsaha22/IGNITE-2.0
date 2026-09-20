from modules.telemetry_engine import get_telemetry
from modules.telemetry_rule_builder import build_telemetry_rule

telemetry = get_telemetry(
    [
        "T1059.001",
        "T1105",
        "T1053.005"
    ]
)

rule = build_telemetry_rule(
    telemetry
)

print(rule)