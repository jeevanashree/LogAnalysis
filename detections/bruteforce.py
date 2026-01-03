from sklearn.ensemble import IsolationForest

def detect(logs):
    failed = logs[logs["status"] == "FAILED"]
    ip_counts = failed.groupby("ip_address").size()

    if ip_counts.empty:
        return None

    model = IsolationForest(contamination=0.2, random_state=42)
    preds = model.fit_predict(ip_counts.values.reshape(-1, 1))

    malicious = ip_counts[preds == -1]

    if malicious.empty:
        return None

    return {
        "threat": "Brute Force Attack",
        "who": {
            "ips": malicious.index.tolist()
        },
        "evidence": malicious.to_dict(),
        "why": "Unusually high number of failed login attempts detected from the same IP(s)",
        "action": [
            "Block offending IPs",
            "Force password reset for targeted users",
            "Enable MFA",
            "Apply rate limiting"
        ]
    }
