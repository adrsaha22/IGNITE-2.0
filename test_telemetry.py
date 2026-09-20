from modules.telemetry_engine import get_telemetry

telemetry = get_telemetry(
    [
        "T1059.001",
        "T1105",
        "T1053.005"
    ]
)

print(telemetry)