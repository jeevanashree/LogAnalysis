import pandas as pd

def preprocess_logs(logs: pd.DataFrame) -> pd.DataFrame:
    """
    Preprocess authentication logs to ensure
    consistency across all detection modules.
    """

    # Normalize column names
    logs.columns = logs.columns.str.strip().str.lower()

    # Required columns check
    required_cols = {"timestamp", "username", "ip_address", "status"}
    if not required_cols.issubset(set(logs.columns)):
        missing = required_cols - set(logs.columns)
        raise ValueError(f"Missing required columns: {missing}")

    # Normalize status values
    logs["status"] = logs["status"].astype(str).str.strip().str.upper()

    # Convert timestamp
    logs["timestamp"] = pd.to_datetime(logs["timestamp"], errors="coerce")

    # Drop rows with invalid timestamps
    logs = logs.dropna(subset=["timestamp"])

    return logs
