from datetime import datetime
from database import insert_alert

def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log_attack(ip, port, attack_type, severity):
    line = f"[{now_str()}] [{severity}] {attack_type} from {ip} port {port}\n"
    with open("attack_logs.txt", "a") as f:
        f.write(line)

def add_alert(state, ip, port, alert_type, severity, details):
    alert = {
        "time": now_str(),
        "ip": ip,
        "port": str(port),
        "type": alert_type,
        "severity": severity,
        "status": "Open",
        "details": details,
    }
    state.alerts_data.append(alert)
    insert_alert(alert)

def compute_threat_level(state):
    high_count = sum(1 for a in state.alerts_data if a["severity"] in ("High", "Critical"))
    blacklist_count = len(state.blacklisted_ips)

    if high_count >= 5 or blacklist_count >= 3:
        return "HIGH"
    if high_count >= 2 or blacklist_count >= 1 or len(state.alerts_data) >= 3:
        return "MEDIUM"
    return "LOW"

