import datetime
import uuid

IST = datetime.timezone(datetime.timedelta(hours=5, minutes=30), name="IST")

# In-memory storage for active and historical alerts
ALERT_STORE = []

def create_alert(title, severity="HIGH", source="SOC-Engine", mitre_id="T0000", indicator=None, log_ref=None, details=None):
    """
    Creates and records a structured cybersecurity alert.
    """
    alert_obj = {
        "id": f"ALT-{uuid.uuid4().hex[:8].upper()}",
        "timestamp": datetime.datetime.now(IST).isoformat(),
        "title": title,
        "severity": severity.upper(),
        "status": "OPEN",  # OPEN, INVESTIGATING, CONTAINED, CLOSED
        "source": source,
        "mitre_id": mitre_id,
        "indicator": indicator,
        "log_ref": log_ref,
        "details": details or {},
        "notes": []
    }
    ALERT_STORE.insert(0, alert_obj)
    # Retain most recent 200 alerts
    if len(ALERT_STORE) > 200:
        ALERT_STORE.pop()
    print(f"[{alert_obj['severity']} ALERT] {alert_obj['id']} | {alert_obj['title']} | IOC: {indicator}")
    return alert_obj

def alert(msg):
    """Backwards-compatible alert logger."""
    print(f"[ALERT] {msg}")
    return create_alert(title=msg, severity="HIGH")

def get_alerts(status=None, limit=50):
    """Retrieves alerts, optionally filtered by status."""
    if not status:
        return ALERT_STORE[:limit]
    return [a for a in ALERT_STORE if a["status"].upper() == status.upper()][:limit]

def update_alert_status(alert_id, new_status, note=None):
    """Updates the status and appends analyst notes."""
    for item in ALERT_STORE:
        if item["id"] == alert_id:
            item["status"] = new_status.upper()
            if note:
                item["notes"].append({
                    "timestamp": datetime.datetime.now(IST).isoformat(),
                    "note": note
                })
            return item
    return None
