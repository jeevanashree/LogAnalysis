def detect(logs, threshold=10):
    """
    Detects IP scanning / reconnaissance behavior.
    One IP attempts access to many different usernames.
    """
    grouped = logs.groupby("ip_address")["username"].nunique()

    suspicious = grouped[grouped >= threshold]

    if suspicious.empty:
        return None

    return {
        "threat": "IP Scanning / Reconnaissance",
        "who": {
            "ips": suspicious.index.tolist()
        },
        "evidence": suspicious.to_dict(),
        "why": "Single IP attempted access to many different user accounts",
        "action": [
            "Block scanning IPs",
            "Monitor network activity",
            "Enable IDS/IPS rules",
            "Correlate with firewall logs"
        ]
    }
