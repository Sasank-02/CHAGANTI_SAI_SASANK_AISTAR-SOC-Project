import math
from sklearn.ensemble import IsolationForest

STANDARD_PORTS = {80, 443, 53, 22, 123}

def extract_features(log):
    """
    Extracts a multi-dimensional numerical feature vector from a normalized log:
    [failed_attempts, log_bytes_out, unusual_port_flag, has_command_flag, payload_length]
    """
    failed = float(log.get("failed_attempts", 0))
    bytes_out = float(log.get("bytes_out", 0))
    log_bytes = math.log10(bytes_out + 1.0)
    
    port = int(log.get("destination_port", 80))
    unusual_port = 0.0 if port in STANDARD_PORTS else 1.0
    
    cmd = log.get("command")
    has_cmd = 1.0 if cmd and len(str(cmd).strip()) > 0 else 0.0
    
    raw_len = float(len(str(log.get("raw_payload", ""))))
    
    return [failed, log_bytes, unusual_port, has_cmd, raw_len]

def train(data):
    """
    Trains an Isolation Forest anomaly detection model.
    Accepts either raw vectors or list of normalized logs.
    """
    if not data:
        # Default baseline training data if none provided
        vectors = [
            [0.0, 2.5, 0.0, 0.0, 50.0],
            [1.0, 3.1, 0.0, 0.0, 70.0],
            [0.0, 3.6, 0.0, 0.0, 60.0],
            [0.0, 2.8, 0.0, 0.0, 45.0],
            [0.0, 4.0, 0.0, 0.0, 120.0]
        ]
    elif isinstance(data[0], dict):
        vectors = [extract_features(log) for log in data]
    else:
        # Backwards compatibility if 1D or raw lists were passed
        vectors = data

    model = IsolationForest(contamination=0.15, random_state=42, n_estimators=100)
    model.fit(vectors)
    return model

def predict(model, data):
    """
    Runs prediction on data. Returns array of 1 (normal) or -1 (anomaly).
    """
    if not data:
        return []
    if isinstance(data[0], dict):
        vectors = [extract_features(log) for log in data]
    else:
        vectors = data
    return model.predict(vectors)

def score_log(model, log):
    """
    Computes an explainable anomaly score (0 - 100%) for a single log entry.
    Higher score indicates higher anomaly confidence.
    """
    vector = extract_features(log)
    try:
        # decision_function gives negative values for anomalies
        raw_score = model.decision_function([vector])[0]
        # Map raw_score (typically -0.5 to 0.5) to a clean 0 - 100 risk score
        normalized = max(0.0, min(100.0, (0.25 - raw_score) * 120.0))
        is_anomaly = bool(model.predict([vector])[0] == -1)
    except Exception:
        # Fallback heuristic if model is not yet fitted
        is_anomaly = bool(log.get("failed_attempts", 0) > 5 or log.get("bytes_out", 0) > 1000000)
        normalized = 85.0 if is_anomaly else 15.0

    contributions = []
    if log.get("failed_attempts", 0) > 5:
        contributions.append("Authentication burst failures")
    if log.get("bytes_out", 0) > 10000000:
        contributions.append("Extreme outbound byte volume")
    if vector[2] == 1.0:
        contributions.append(f"Non-standard destination port {log.get('destination_port')}")
    if vector[3] == 1.0:
        contributions.append("Command-line execution footprint")

    return {
        "is_anomaly": is_anomaly,
        "anomaly_score": round(normalized, 1),
        "feature_vector": vector,
        "reasons": contributions if contributions else ["Standard network baseline"]
    }
