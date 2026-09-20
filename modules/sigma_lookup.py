def find_sigma_rules(description):

    description = description.lower()

    sigma_rules = []

    if "powershell" in description:
        sigma_rules.append(
            "Suspicious PowerShell Download"
        )

        sigma_rules.append(
            "Encoded PowerShell Command"
        )

    if "mimikatz" in description:
        sigma_rules.append(
            "Mimikatz Credential Dumping"
        )

    if "psexec" in description:
        sigma_rules.append(
            "PsExec Remote Execution"
        )

    if "scheduled task" in description:
        sigma_rules.append(
            "Scheduled Task Creation"
        )

    return sigma_rules