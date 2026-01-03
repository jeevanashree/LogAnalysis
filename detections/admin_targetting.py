def detect(logs, threshold=3):
    admin_logs = logs[
        (logs["username"].isin(["admin", "root"])) &
        (logs["status"] == "FAILED")
    ]

    if admin_logs.shape[0] < threshold:
        return None

    ips = admin_logs["ip_address"].unique().tolist()

    return {
        "threat": "Privileged Account Targeting",
        "who": {
            "ips": ips,
            "accounts": ["admin", "root"]
        },
        "evidence": admin_logs.groupby("ip_address").size().to_dict(),
        "why": "Repeated failed login attempts on privileged accounts detected",
        "action": [
            "Immediately audit privileged access",
            "Force password rotation",
            "Enable MFA on admin accounts",
            "Review system access logs"
        ]
    }
