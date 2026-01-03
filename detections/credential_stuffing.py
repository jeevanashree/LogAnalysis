from sklearn.cluster import KMeans

def detect(logs):
    failed = logs[logs["status"] == "FAILED"]
    grouped = failed.groupby("ip_address")["username"].nunique()

    if grouped.empty:
        return None

    X = grouped.values.reshape(-1, 1)

    model = KMeans(n_clusters=2, random_state=42)
    labels = model.fit_predict(X)

    suspicious_cluster = grouped.groupby(labels).mean().idxmax()
    suspicious = grouped[labels == suspicious_cluster]

    if suspicious.empty:
        return None

    return {
        "threat": "Credential Stuffing",
        "who": {
            "ips": suspicious.index.tolist()
        },
        "evidence": suspicious.to_dict(),
        "why": "Single IP attempted logins across many different usernames",
        "action": [
            "Block source IPs",
            "Monitor affected accounts",
            "Enable CAPTCHA and MFA",
            "Check for leaked credentials"
        ]
    }
