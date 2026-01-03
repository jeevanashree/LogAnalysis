from detections import (
    brute_force,
    credential_stuffing,
    admin_targetting,
    ip_scanning,
    anomaly
)

def run_detections(logs):
    """
    Runs all detection modules and returns
    structured threat intelligence reports.
    """

    detections = []

    detectors = [
        brute_force,
        credential_stuffing,
        admin_targetting,
        ip_scanning,
        anomaly
    ]

    for detect in detectors:
        try:
            result = detect(logs)
            if result:
                detections.append(result)
        except Exception as e:
            # Detector failure should not crash the system
            detections.append({
                "threat": "Detection Error",
                "who": {},
                "evidence": {},
                "why": f"Detector {detect.__name__} failed",
                "action": ["Review detection module logs"],
                "error": str(e)
            })

    return detections
