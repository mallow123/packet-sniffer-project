import csv
from datetime import datetime

def save_packets_csv(state):
    if not state.captured_packets:
        return None

    filename = f"packets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    with open(filename, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Time", "Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port", "Size"])
        for p in state.captured_packets:
            writer.writerow([
                p["time"], p["src_ip"], p["dst_ip"], p["protocol"],
                p["src_port"], p["dst_port"], p["size"]
            ])
    return filename

def export_alerts_csv(state):
    if not state.alerts_data:
        return None

    filename = f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    with open(filename, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Time", "IP", "Port", "Type", "Severity", "Status", "Details"])
        for a in state.alerts_data:
            writer.writerow([a["time"], a["ip"], a["port"], a["type"], a["severity"], a["status"], a["details"]])
    return filename
