from sklearn.ensemble import IsolationForest

def detect(logs):
    failed = logs[logs["status"] == "FAILED"]
    ip_counts = failed.groupby("ip_address").size()

    if ip_counts.empty:
        return None

    model = IsolationForest(contamination=0.15, random_state=42)
    preds = model.fit_predict(ip_counts.values.reshape(-1, 1))

    anomalies = ip_counts[preds == -1]

    if anomalies.empty:
        return None

    return {
        "threat": "Anomalous Login Behavior",
        "who": {
            "ips": anomalies.index.tolist()
        },
        "evidence": anomalies.to_dict(),
        "why": "Login failure patterns deviate significantly from baseline behavior",
        "action": [
            "Investigate anomalous IPs",
            "Correlate with other security alerts",
            "Monitor system activity closely"
        ]
    }
