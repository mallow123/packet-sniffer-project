import threading
import csv
import binascii
import sqlite3
from datetime import datetime
from collections import Counter

from scapy.all import sniff, IP, TCP, UDP, Raw, get_if_list
import tkinter as tk
from tkinter import ttk, messagebox
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation


# =========================
# THEME
# =========================
APP_BG = "#0d1117"
SIDEBAR_BG = "#111827"
CARD_BG = "#161b22"
CARD_ALT = "#1f2937"
TABLE_BG = "#0f1724"

TEXT = "#e6edf3"
MUTED = "#9aa4b2"
ACCENT = "#00ff9c"
GREEN = "#2ea043"
RED = "#f85149"
BLUE = "#1f6feb"
PURPLE = "#8957e5"
GRAY = "#6e7681"
YELLOW = "#d2a8ff"
CYAN = "#79c0ff"
MINT = "#7ee3b8"
WARNING = "#ff7b72"
ORANGE = "#ff9e64"


# =========================
# GLOBAL STATE
# =========================
sniffing = False
packet_count = 0
captured_packets = []
filtered_packets = []

tcp_count = 0
udp_count = 0
other_count = 0
total_bytes = 0

traffic_counter = {}
blacklisted_ips = set()
alerts_data = []

root = None
login_window = None
anim = None

# runtime settings
settings = {
    "default_interface": "",
    "alert_threshold": 50,
    "suspicious_ports": "21,22,23,3389,4444,8080",
    "auto_save_packets": "False",
    "theme_mode": "Dark",
    "show_toasts": "True",
}

# ui refs
status_value = None
footer_status = None
footer_interface = None
footer_packets = None
footer_alerts = None
footer_lastsave = None

total_packets_value = None
active_ips_value = None
blacklisted_value = None
alerts_value = None
threat_value = None
protocol_value = None
bandwidth_value = None

packets_table = None
alerts_table = None
analytics_text = None
blacklist_box = None
recent_alerts_list = None

search_var = None
packet_filter_var = None
interface_var = None

dashboard_page = None
packets_page = None
alerts_page = None
analytics_page = None
settings_page = None

theme_var = None
threshold_var = None
ports_var = None
autosave_var = None
toast_var = None


# =========================
# DATABASE
# =========================
def db_connect():
    return sqlite3.connect("users.db")


def init_db():
    conn = db_connect()
    cur = conn.cursor()

    cur.execute("CREATE TABLE IF NOT EXISTS users (username TEXT UNIQUE, password TEXT)")
    cur.execute("INSERT OR IGNORE INTO users VALUES (?, ?)", ("admin", "password"))

    cur.execute("""
        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time TEXT,
            ip TEXT,
            port TEXT,
            type TEXT,
            severity TEXT,
            status TEXT,
            details TEXT
        )
    """)

    conn.commit()
    conn.close()
    load_settings()


def load_settings():
    global settings
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT key, value FROM app_settings")
    rows = cur.fetchall()
    conn.close()

    for k, v in rows:
        settings[k] = v


def save_setting(key, value):
    settings[key] = str(value)
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO app_settings(key, value)
        VALUES(?, ?)
        ON CONFLICT(key) DO UPDATE SET value=excluded.value
    """, (key, str(value)))
    conn.commit()
    conn.close()


def get_suspicious_ports():
    try:
        return [int(x.strip()) for x in settings["suspicious_ports"].split(",") if x.strip()]
    except ValueError:
        return [21, 22, 23, 3389, 4444, 8080]


def get_alert_threshold():
    try:
        return int(settings["alert_threshold"])
    except ValueError:
        return 50


# =========================
# HELPERS
# =========================
def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def short_time():
    return datetime.now().strftime("%H:%M:%S")


def show_toast(title, message, color=BLUE):
    if settings.get("show_toasts", "True") != "True" or root is None:
        return

    toast = tk.Toplevel(root)
    toast.overrideredirect(True)
    toast.configure(bg=CARD_BG)
    toast.attributes("-topmost", True)

    width = 320
    height = 90
    x = root.winfo_x() + root.winfo_width() - width - 20
    y = root.winfo_y() + root.winfo_height() - height - 60
    toast.geometry(f"{width}x{height}+{x}+{y}")

    frame = tk.Frame(toast, bg=CARD_BG, highlightthickness=1, highlightbackground=color)
    frame.pack(fill="both", expand=True)

    tk.Label(frame, text=title, bg=CARD_BG, fg=color, font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=12, pady=(10, 2))
    tk.Label(frame, text=message, bg=CARD_BG, fg=TEXT, font=("Segoe UI", 9), wraplength=290, justify="left").pack(anchor="w", padx=12)

    toast.after(2600, toast.destroy)


def log_attack(ip, port, attack_type, severity):
    line = f"[{now_str()}] [{severity}] {attack_type} from {ip} port {port}\n"
    with open("attack_logs.txt", "a") as f:
        f.write(line)


def update_footer(last_save_text=None):
    if footer_status:
        footer_status.config(text=f"Status: {'Running' if sniffing else 'Stopped'}")
    if footer_interface and interface_var is not None:
        footer_interface.config(text=f"Interface: {interface_var.get()}")
    if footer_packets:
        footer_packets.config(text=f"Packets: {packet_count}")
    if footer_alerts:
        footer_alerts.config(text=f"Alerts: {len(alerts_data)}")
    if footer_lastsave and last_save_text is not None:
        footer_lastsave.config(text=f"Last Save: {last_save_text}")


def compute_threat_level():
    high_count = sum(1 for a in alerts_data if a["severity"] in ("High", "Critical"))
    blacklist_count = len(blacklisted_ips)

    if high_count >= 5 or blacklist_count >= 3:
        return "HIGH", RED
    if high_count >= 2 or blacklist_count >= 1 or len(alerts_data) >= 3:
        return "MEDIUM", ORANGE
    return "LOW", GREEN


def make_button(parent, text, command, bg, fg="white", width=12):
    return tk.Button(
        parent,
        text=text,
        command=command,
        bg=bg,
        fg=fg,
        activebackground=bg,
        activeforeground=fg,
        relief="flat",
        bd=0,
        font=("Segoe UI", 10, "bold"),
        width=width,
        pady=8,
        cursor="hand2",
    )


def make_card(parent):
    return tk.Frame(parent, bg=CARD_BG, highlightthickness=1, highlightbackground="#222b36")


# =========================
# LOGIN
# =========================
def check_login():
    user = username_entry.get().strip()
    pwd = password_entry.get().strip()

    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username=? AND password=?", (user, pwd))
    result = cur.fetchone()
    conn.close()

    if result:
        login_window.destroy()
        launch_app()
    else:
        messagebox.showerror("Login Failed", "Invalid credentials")


# =========================
# ALERTS
# =========================
def add_alert(ip, port, alert_type, severity, details):
    alert = {
        "time": now_str(),
        "ip": ip,
        "port": str(port),
        "type": alert_type,
        "severity": severity,
        "status": "Open",
        "details": details,
    }
    alerts_data.append(alert)

    conn = db_connect()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO alerts_log(time, ip, port, type, severity, status, details)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        alert["time"], alert["ip"], alert["port"],
        alert["type"], alert["severity"], alert["status"], alert["details"]
    ))
    conn.commit()
    conn.close()

    root.after(0, refresh_alerts_table)
    root.after(0, refresh_dashboard)
    root.after(0, refresh_analytics)
    root.after(0, lambda: update_footer())


def load_saved_alerts():
    alerts_data.clear()
    conn = db_connect()
    cur = conn.cursor()
    cur.execute("SELECT time, ip, port, type, severity, status, details FROM alerts_log ORDER BY id ASC")
    rows = cur.fetchall()
    conn.close()

    for row in rows:
        alerts_data.append({
            "time": row[0],
            "ip": row[1],
            "port": row[2],
            "type": row[3],
            "severity": row[4],
            "status": row[5],
            "details": row[6],
        })


# =========================
# SNIFFER
# =========================
def start_sniff():
    global sniffing
    if sniffing:
        return

    sniffing = True
    status_value.config(text="Running", fg=GREEN)
    update_footer()
    save_setting("default_interface", interface_var.get())
    show_toast("Capture Started", f"Listening on {interface_var.get()}", GREEN)
    threading.Thread(target=sniff_packets, daemon=True).start()


def stop_sniff():
    global sniffing
    sniffing = False
    status_value.config(text="Stopped", fg=RED)
    update_footer()
    show_toast("Capture Stopped", "Packet capture has been stopped.", RED)


def sniff_packets():
    iface = interface_var.get()
    sniff(prn=process_packet, iface=iface, store=False)


def process_packet(packet):
    global packet_count, tcp_count, udp_count, other_count, total_bytes

    if not sniffing or IP not in packet:
        return

    total_bytes += len(packet)

    protocol = "OTHER"
    src_port = "-"
    dst_port = "-"

    if TCP in packet:
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        tcp_count += 1
    elif UDP in packet:
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        udp_count += 1
    else:
        other_count += 1

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    traffic_counter[src_ip] = traffic_counter.get(src_ip, 0) + 1
    threshold = get_alert_threshold()
    suspicious_ports = get_suspicious_ports()

    if traffic_counter[src_ip] == threshold:
        blacklisted_ips.add(src_ip)
        log_attack(src_ip, "-", "Possible DoS / Port Scan", "High")
        add_alert(
            src_ip,
            "-",
            "Possible DoS / Port Scan",
            "High",
            f"{src_ip} crossed threshold {threshold} and was blacklisted."
        )
        root.after(0, refresh_blacklist_panel)
        root.after(0, lambda: show_toast("High Threat Detected", f"{src_ip} added to blacklist.", RED))

    if src_port in suspicious_ports or dst_port in suspicious_ports:
        attack_port = src_port if src_port in suspicious_ports else dst_port
        log_attack(src_ip, attack_port, "Suspicious Port Activity", "Medium")
        add_alert(
            src_ip,
            attack_port,
            "Suspicious Port Activity",
            "Medium",
            f"Traffic detected on suspicious port {attack_port} from {src_ip}."
        )
        root.after(0, lambda: show_toast("Suspicious Port Activity", f"{src_ip} used port {attack_port}.", ORANGE))

    packet_info = {
        "time": now_str(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "src_port": str(src_port),
        "dst_port": str(dst_port),
        "size": len(packet),
        "packet": packet,
    }

    captured_packets.append(packet_info)
    packet_count += 1

    if settings.get("auto_save_packets", "False") == "True" and packet_count % 100 == 0:
        root.after(0, auto_save_snapshot)

    root.after(0, refresh_dashboard)
    root.after(0, refresh_packets_table)
    root.after(0, refresh_analytics)
    root.after(0, lambda: update_footer())


# =========================
# DASHBOARD
# =========================
def refresh_dashboard():
    total_packets_value.config(text=str(packet_count))
    active_ips_value.config(text=str(len(traffic_counter)))
    blacklisted_value.config(text=str(len(blacklisted_ips)))
    alerts_value.config(text=str(len(alerts_data)))
    protocol_value.config(text=f"TCP: {tcp_count} | UDP: {udp_count} | OTHER: {other_count}")

    level, color = compute_threat_level()
    threat_value.config(text=level, fg=color)

    refresh_recent_alerts()


def update_speed():
    global total_bytes
    speed = total_bytes / 1024
    bandwidth_value.config(text=f"{speed:.2f} KB/s")
    total_bytes = 0
    root.after(1000, update_speed)


def refresh_recent_alerts():
    recent_alerts_list.delete(0, tk.END)
    for alert in alerts_data[-10:][::-1]:
        recent_alerts_list.insert(tk.END, f"{alert['time']} | {alert['severity']} | {alert['ip']}")


# =========================
# PACKETS
# =========================
def refresh_packets_table():
    query = search_var.get().strip().lower()
    proto_filter = packet_filter_var.get()

    for item in packets_table.get_children():
        packets_table.delete(item)

    filtered_packets.clear()

    for p in captured_packets:
        if query:
            haystack = " ".join([
                p["time"], p["src_ip"], p["dst_ip"],
                p["protocol"], p["src_port"], p["dst_port"]
            ]).lower()
            if query not in haystack:
                continue

        if proto_filter != "ALL" and p["protocol"] != proto_filter:
            continue

        filtered_packets.append(p)
        packets_table.insert(
            "",
            tk.END,
            values=(
                p["time"], p["src_ip"], p["dst_ip"],
                p["protocol"], p["src_port"], p["dst_port"], p["size"]
            ),
        )


def show_packet_details(event=None):
    selected = packets_table.focus()
    if not selected:
        return

    index = packets_table.index(selected)
    if index >= len(filtered_packets):
        return

    packet_row = filtered_packets[index]
    packet = packet_row["packet"]

    detail = tk.Toplevel(root)
    detail.title("Packet Inspection")
    detail.geometry("820x620")
    detail.configure(bg=APP_BG)

    notebook = ttk.Notebook(detail)
    notebook.pack(fill="both", expand=True, padx=12, pady=12)

    summary_tab = tk.Frame(notebook, bg=CARD_BG)
    payload_tab = tk.Frame(notebook, bg=CARD_BG)
    raw_tab = tk.Frame(notebook, bg=CARD_BG)

    notebook.add(summary_tab, text="Summary")
    notebook.add(payload_tab, text="Payload")
    notebook.add(raw_tab, text="Raw View")

    fields = [
        ("Time", packet_row["time"]),
        ("Source IP", packet_row["src_ip"]),
        ("Destination IP", packet_row["dst_ip"]),
        ("Protocol", packet_row["protocol"]),
        ("Source Port", packet_row["src_port"]),
        ("Destination Port", packet_row["dst_port"]),
        ("Packet Size", str(packet_row["size"])),
    ]

    for key, value in fields:
        row = tk.Frame(summary_tab, bg=CARD_BG)
        row.pack(fill="x", padx=14, pady=5)
        tk.Label(row, text=f"{key}:", bg=CARD_BG, fg=ACCENT, font=("Segoe UI", 10, "bold")).pack(side="left")
        tk.Label(row, text=f"  {value}", bg=CARD_BG, fg=TEXT, font=("Segoe UI", 10)).pack(side="left")

    payload_text = tk.Text(payload_tab, bg=TABLE_BG, fg=CYAN, font=("Consolas", 10), relief="flat", wrap="word")
    payload_text.pack(fill="both", expand=True, padx=12, pady=12)

    raw_text = tk.Text(raw_tab, bg=TABLE_BG, fg=TEXT, font=("Consolas", 10), relief="flat", wrap="word")
    raw_text.pack(fill="both", expand=True, padx=12, pady=12)

    if Raw in packet:
        payload_text.insert("end", binascii.hexlify(bytes(packet[Raw].load)).decode())
    else:
        payload_text.insert("end", "No Raw Payload")

    raw_text.insert("end", packet.summary())

    payload_text.config(state="disabled")
    raw_text.config(state="disabled")


# =========================
# ALERTS TABLE
# =========================
def refresh_alerts_table():
    for item in alerts_table.get_children():
        alerts_table.delete(item)

    for alert in alerts_data:
        alerts_table.insert(
            "",
            tk.END,
            values=(
                alert["time"],
                alert["ip"],
                alert["port"],
                alert["type"],
                alert["severity"],
                alert["status"],
            ),
        )


# =========================
# ANALYTICS
# =========================
def refresh_analytics():
    top_sources = Counter()
    top_ports = Counter()

    for p in captured_packets:
        top_sources[p["src_ip"]] += 1
        if p["dst_port"] != "-":
            top_ports[p["dst_port"]] += 1

    analytics_text.config(state="normal")
    analytics_text.delete("1.0", tk.END)

    analytics_text.insert("end", "Top Source IPs\n", "heading")
    for ip, count in top_sources.most_common(5):
        analytics_text.insert("end", f"• {ip}  ->  {count} packets\n")

    analytics_text.insert("end", "\nTop Destination Ports\n", "heading")
    for port, count in top_ports.most_common(5):
        analytics_text.insert("end", f"• Port {port}  ->  {count} packets\n")

    analytics_text.insert("end", "\nSummary\n", "heading")
    analytics_text.insert("end", f"• Total Packets: {packet_count}\n")
    analytics_text.insert("end", f"• Alerts: {len(alerts_data)}\n")
    analytics_text.insert("end", f"• Blacklisted IPs: {len(blacklisted_ips)}\n")

    analytics_text.config(state="disabled")


def show_traffic_graph():
    global anim
    fig, ax = plt.subplots(figsize=(8, 4))
    x_data = []
    y_data = []

    def update(frame):
        x_data.append(len(x_data))
        y_data.append(packet_count)
        ax.clear()
        ax.plot(x_data, y_data, linewidth=2)
        ax.set_title("Live Traffic Graph")
        ax.set_xlabel("Time")
        ax.set_ylabel("Packets")

    anim = FuncAnimation(fig, update, interval=1000, cache_frame_data=False)
    plt.show()


def show_protocol_chart():
    sizes = [tcp_count, udp_count, other_count]
    labels = ["TCP", "UDP", "OTHER"]

    if packet_count == 0:
        messagebox.showinfo("No Data", "No packets captured yet")
        return

    plt.figure(figsize=(6, 6))
    plt.pie(sizes, labels=labels, autopct="%1.1f%%")
    plt.title("Protocol Distribution")
    plt.show()


# =========================
# EXPORT / SAVE / CLEAR
# =========================
def save_to_csv():
    if not captured_packets:
        messagebox.showinfo("Info", "No packets to save")
        return

    filename = f"packets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    with open(filename, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Time", "Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port", "Size"])
        for p in captured_packets:
            writer.writerow([
                p["time"], p["src_ip"], p["dst_ip"], p["protocol"],
                p["src_port"], p["dst_port"], p["size"]
            ])

    update_footer(short_time())
    show_toast("Packets Saved", f"Saved to {filename}", GREEN)


def auto_save_snapshot():
    filename = "autosave_packets.csv"
    with open(filename, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Time", "Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port", "Size"])
        for p in captured_packets[-500:]:
            writer.writerow([
                p["time"], p["src_ip"], p["dst_ip"], p["protocol"],
                p["src_port"], p["dst_port"], p["size"]
            ])
    update_footer(short_time())


def export_alerts_csv():
    if not alerts_data:
        messagebox.showinfo("Info", "No alerts to export")
        return

    filename = f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    with open(filename, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Time", "IP", "Port", "Type", "Severity", "Status", "Details"])
        for a in alerts_data:
            writer.writerow([a["time"], a["ip"], a["port"], a["type"], a["severity"], a["status"], a["details"]])

    update_footer(short_time())
    show_toast("Alerts Exported", f"Saved to {filename}", PURPLE)


def clear_all_data():
    global packet_count, tcp_count, udp_count, other_count, total_bytes
    captured_packets.clear()
    filtered_packets.clear()
    alerts_data.clear()
    blacklisted_ips.clear()
    traffic_counter.clear()

    packet_count = 0
    tcp_count = 0
    udp_count = 0
    other_count = 0
    total_bytes = 0

    conn = db_connect()
    cur = conn.cursor()
    cur.execute("DELETE FROM alerts_log")
    conn.commit()
    conn.close()

    refresh_packets_table()
    refresh_alerts_table()
    refresh_blacklist_panel()
    refresh_dashboard()
    refresh_analytics()
    update_footer()
    show_toast("Workspace Cleared", "All runtime data has been cleared.", RED)


def refresh_blacklist_panel():
    blacklist_box.delete(0, tk.END)
    for ip in sorted(blacklisted_ips):
        blacklist_box.insert(tk.END, ip)


# =========================
# SETTINGS
# =========================
def save_preferences():
    save_setting("alert_threshold", threshold_var.get().strip())
    save_setting("suspicious_ports", ports_var.get().strip())
    save_setting("auto_save_packets", str(autosave_var.get()))
    save_setting("theme_mode", theme_var.get())
    save_setting("show_toasts", str(toast_var.get()))
    save_setting("default_interface", interface_var.get())

    show_toast("Settings Saved", "Your preferences have been updated.", GREEN)


# =========================
# NAVIGATION
# =========================
def show_page(name):
    dashboard_page.pack_forget()
    packets_page.pack_forget()
    alerts_page.pack_forget()
    analytics_page.pack_forget()
    settings_page.pack_forget()

    {
        "Dashboard": dashboard_page,
        "Packets": packets_page,
        "Alerts": alerts_page,
        "Analytics": analytics_page,
        "Settings": settings_page,
    }[name].pack(fill="both", expand=True)


# =========================
# APP UI
# =========================
def launch_app():
    global root
    global interface_var, search_var, packet_filter_var
    global status_value, footer_status, footer_interface, footer_packets, footer_alerts, footer_lastsave
    global total_packets_value, active_ips_value, blacklisted_value, alerts_value
    global threat_value, protocol_value, bandwidth_value
    global packets_table, alerts_table, analytics_text, blacklist_box, recent_alerts_list
    global dashboard_page, packets_page, alerts_page, analytics_page, settings_page
    global theme_var, threshold_var, ports_var, autosave_var, toast_var

    root = tk.Tk()
    root.title("Cyber Packet Analyzer")
    root.geometry("1400x860")
    root.minsize(1200, 760)
    root.configure(bg=APP_BG)

    interfaces = get_if_list()
    if not interfaces:
        messagebox.showerror("Error", "No network interfaces found!")
        return

    default_iface = settings["default_interface"] if settings["default_interface"] in interfaces else interfaces[0]

    interface_var = tk.StringVar(value=default_iface)
    search_var = tk.StringVar()
    packet_filter_var = tk.StringVar(value="ALL")

    theme_var = tk.StringVar(value=settings.get("theme_mode", "Dark"))
    threshold_var = tk.StringVar(value=settings.get("alert_threshold", "50"))
    ports_var = tk.StringVar(value=settings.get("suspicious_ports", "21,22,23,3389,4444,8080"))
    autosave_var = tk.BooleanVar(value=settings.get("auto_save_packets", "False") == "True")
    toast_var = tk.BooleanVar(value=settings.get("show_toasts", "True") == "True")

    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Treeview", background=TABLE_BG, foreground=TEXT, fieldbackground=TABLE_BG, rowheight=28, font=("Segoe UI", 10))
    style.configure("Treeview.Heading", background=CARD_ALT, foreground=ACCENT, font=("Segoe UI", 10, "bold"))
    style.map("Treeview", background=[("selected", GREEN)])

    shell = tk.Frame(root, bg=APP_BG)
    shell.pack(fill="both", expand=True)

    # Sidebar
    sidebar = tk.Frame(shell, bg=SIDEBAR_BG, width=220)
    sidebar.pack(side="left", fill="y")
    sidebar.pack_propagate(False)

    tk.Label(sidebar, text="Packet Analyzer", bg=SIDEBAR_BG, fg=ACCENT, font=("Segoe UI", 16, "bold")).pack(anchor="w", padx=18, pady=(18, 4))
    tk.Label(sidebar, text="Security Monitoring Platform", bg=SIDEBAR_BG, fg=MUTED, font=("Segoe UI", 9)).pack(anchor="w", padx=18, pady=(0, 18))

    def nav_btn(text):
        return tk.Button(
            sidebar, text=text, command=lambda t=text: show_page(t),
            bg=SIDEBAR_BG, fg=TEXT, activebackground=CARD_ALT, activeforeground=TEXT,
            relief="flat", bd=0, anchor="w", padx=18, pady=10,
            font=("Segoe UI", 10, "bold"), cursor="hand2"
        )

    nav_btn("Dashboard").pack(fill="x")
    nav_btn("Packets").pack(fill="x")
    nav_btn("Alerts").pack(fill="x")
    nav_btn("Analytics").pack(fill="x")
    nav_btn("Settings").pack(fill="x")

    tk.Label(sidebar, text="", bg=SIDEBAR_BG).pack(fill="x", pady=8)
    tk.Label(sidebar, text="Interface", bg=SIDEBAR_BG, fg=MUTED, font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=18, pady=(10, 4))

    interface_menu = tk.OptionMenu(sidebar, interface_var, *interfaces)
    interface_menu.config(bg=CARD_ALT, fg=TEXT, activebackground=CARD_ALT, activeforeground=TEXT, highlightthickness=0, bd=0, width=16)
    interface_menu["menu"].config(bg=CARD_ALT, fg=TEXT)
    interface_menu.pack(anchor="w", padx=18)

    make_button(sidebar, "▶ Start", start_sniff, GREEN, width=16).pack(padx=18, pady=(20, 8))
    make_button(sidebar, "■ Stop", stop_sniff, RED, width=16).pack(padx=18, pady=4)
    make_button(sidebar, "💾 Save Packets", save_to_csv, BLUE, width=16).pack(padx=18, pady=4)
    make_button(sidebar, "📤 Export Alerts", export_alerts_csv, PURPLE, width=16).pack(padx=18, pady=4)

    # Main content
    content = tk.Frame(shell, bg=APP_BG)
    content.pack(side="left", fill="both", expand=True)

    # Top bar
    topbar = tk.Frame(content, bg=APP_BG)
    topbar.pack(fill="x", padx=18, pady=(18, 8))

    title_wrap = tk.Frame(topbar, bg=APP_BG)
    title_wrap.pack(side="left")

    tk.Label(title_wrap, text="Cyber Packet Analyzer", bg=APP_BG, fg=TEXT, font=("Segoe UI", 20, "bold")).pack(anchor="w")
    tk.Label(title_wrap, text="Enterprise-style endpoint packet monitoring and threat visibility", bg=APP_BG, fg=MUTED, font=("Segoe UI", 10)).pack(anchor="w", pady=(2, 0))

    top_actions = tk.Frame(topbar, bg=APP_BG)
    top_actions.pack(side="right")

    status_value = tk.Label(top_actions, text="Stopped", bg=APP_BG, fg=RED, font=("Segoe UI", 11, "bold"))
    status_value.pack(side="left", padx=10)

    user_badge = tk.Label(top_actions, text="User: admin", bg=CARD_ALT, fg=TEXT, font=("Segoe UI", 9, "bold"), padx=10, pady=6)
    user_badge.pack(side="left", padx=4)

    # Pages container
    pages = tk.Frame(content, bg=APP_BG)
    pages.pack(fill="both", expand=True, padx=18, pady=(0, 8))

    dashboard_page = tk.Frame(pages, bg=APP_BG)
    packets_page = tk.Frame(pages, bg=APP_BG)
    alerts_page = tk.Frame(pages, bg=APP_BG)
    analytics_page = tk.Frame(pages, bg=APP_BG)
    settings_page = tk.Frame(pages, bg=APP_BG)

    # DASHBOARD
    cards_row = tk.Frame(dashboard_page, bg=APP_BG)
    cards_row.pack(fill="x", pady=(0, 12))

    def dashboard_card(parent, title, value_color):
        card = make_card(parent)
        card.pack(side="left", fill="x", expand=True, padx=6)
        tk.Label(card, text=title, bg=CARD_BG, fg=MUTED, font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=14, pady=(12, 4))
        val = tk.Label(card, text="0", bg=CARD_BG, fg=value_color, font=("Segoe UI", 18, "bold"))
        val.pack(anchor="w", padx=14, pady=(0, 12))
        return val

    total_packets_value = dashboard_card(cards_row, "Total Packets", CYAN)
    active_ips_value = dashboard_card(cards_row, "Active Source IPs", ACCENT)
    blacklisted_value = dashboard_card(cards_row, "Blacklisted IPs", WARNING)
    alerts_value = dashboard_card(cards_row, "Alerts Today", ORANGE)

    cards_row2 = tk.Frame(dashboard_page, bg=APP_BG)
    cards_row2.pack(fill="x", pady=(0, 12))

    def info_card(parent, title, value, color):
        card = make_card(parent)
        card.pack(side="left", fill="x", expand=True, padx=6)
        tk.Label(card, text=title, bg=CARD_BG, fg=MUTED, font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=14, pady=(12, 4))
        lbl = tk.Label(card, text=value, bg=CARD_BG, fg=color, font=("Segoe UI", 15, "bold"))
        lbl.pack(anchor="w", padx=14, pady=(0, 12))
        return lbl

    threat_value = info_card(cards_row2, "Threat Level", "LOW", GREEN)
    protocol_value = info_card(cards_row2, "Protocol Mix", "TCP: 0 | UDP: 0 | OTHER: 0", YELLOW)
    bandwidth_value = info_card(cards_row2, "Bandwidth", "0.00 KB/s", MINT)

    dash_lower = tk.Frame(dashboard_page, bg=APP_BG)
    dash_lower.pack(fill="both", expand=True)

    recent_card = make_card(dash_lower)
    recent_card.pack(side="left", fill="both", expand=True, padx=6)
    tk.Label(recent_card, text="Recent Alerts", bg=CARD_BG, fg=ACCENT, font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=12, pady=(12, 8))
    recent_alerts_list = tk.Listbox(recent_card, bg=TABLE_BG, fg=TEXT, selectbackground=RED, selectforeground="white", relief="flat", bd=0, font=("Consolas", 10))
    recent_alerts_list.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    blacklist_card = make_card(dash_lower)
    blacklist_card.pack(side="left", fill="both", expand=True, padx=6)
    tk.Label(blacklist_card, text="Blacklisted IPs", bg=CARD_BG, fg=WARNING, font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=12, pady=(12, 8))
    blacklist_box = tk.Listbox(blacklist_card, bg=TABLE_BG, fg=WARNING, selectbackground=RED, selectforeground="white", relief="flat", bd=0, font=("Consolas", 10))
    blacklist_box.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    # PACKETS
    packets_top = make_card(packets_page)
    packets_top.pack(fill="x", pady=(0, 12))

    ctrl = tk.Frame(packets_top, bg=CARD_BG)
    ctrl.pack(fill="x", padx=12, pady=12)

    tk.Label(ctrl, text="Search", bg=CARD_BG, fg=MUTED, font=("Segoe UI", 10, "bold")).grid(row=0, column=0, padx=(0, 6))
    tk.Entry(ctrl, textvariable=search_var, bg=TABLE_BG, fg=TEXT, insertbackground="white", relief="flat", font=("Segoe UI", 10), width=30).grid(row=0, column=1, padx=(0, 12), ipady=5)

    tk.Label(ctrl, text="Protocol", bg=CARD_BG, fg=MUTED, font=("Segoe UI", 10, "bold")).grid(row=0, column=2, padx=(0, 6))
    filt = tk.OptionMenu(ctrl, packet_filter_var, "ALL", "TCP", "UDP", "OTHER")
    filt.config(bg=TABLE_BG, fg=TEXT, activebackground=TABLE_BG, activeforeground=TEXT, highlightthickness=0, bd=0, width=10)
    filt["menu"].config(bg=TABLE_BG, fg=TEXT)
    filt.grid(row=0, column=3, padx=(0, 12))

    make_button(ctrl, "Apply Filter", refresh_packets_table, BLUE, width=12).grid(row=0, column=4, padx=4)

    packets_card = make_card(packets_page)
    packets_card.pack(fill="both", expand=True)

    tk.Label(packets_card, text="Captured Packets", bg=CARD_BG, fg=ACCENT, font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=12, pady=(12, 8))

    packets_frame = tk.Frame(packets_card, bg=CARD_BG)
    packets_frame.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    packet_cols = ("Time", "Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port", "Size")
    packets_table = ttk.Treeview(packets_frame, columns=packet_cols, show="headings")

    for col in packet_cols:
        packets_table.heading(col, text=col)
        packets_table.column(col, width=140, anchor="center")

    pscroll = ttk.Scrollbar(packets_frame, orient="vertical", command=packets_table.yview)
    packets_table.configure(yscrollcommand=pscroll.set)
    packets_table.pack(side="left", fill="both", expand=True)
    pscroll.pack(side="right", fill="y")
    packets_table.bind("<Double-1>", show_packet_details)

    # ALERTS
    alerts_top = make_card(alerts_page)
    alerts_top.pack(fill="x", pady=(0, 12))

    atop = tk.Frame(alerts_top, bg=CARD_BG)
    atop.pack(fill="x", padx=12, pady=12)
    tk.Label(atop, text="Alerts Center", bg=CARD_BG, fg=ACCENT, font=("Segoe UI", 12, "bold")).pack(side="left")
    make_button(atop, "Export Alerts", export_alerts_csv, PURPLE, width=12).pack(side="right")

    alerts_card = make_card(alerts_page)
    alerts_card.pack(fill="both", expand=True)

    alerts_frame = tk.Frame(alerts_card, bg=CARD_BG)
    alerts_frame.pack(fill="both", expand=True, padx=12, pady=12)

    alert_cols = ("Time", "IP", "Port", "Type", "Severity", "Status")
    alerts_table = ttk.Treeview(alerts_frame, columns=alert_cols, show="headings")
    for col in alert_cols:
        alerts_table.heading(col, text=col)
        alerts_table.column(col, width=150, anchor="center")
    ascroll = ttk.Scrollbar(alerts_frame, orient="vertical", command=alerts_table.yview)
    alerts_table.configure(yscrollcommand=ascroll.set)
    alerts_table.pack(side="left", fill="both", expand=True)
    ascroll.pack(side="right", fill="y")

    # ANALYTICS
    analytics_controls = make_card(analytics_page)
    analytics_controls.pack(fill="x", pady=(0, 12))

    ac = tk.Frame(analytics_controls, bg=CARD_BG)
    ac.pack(fill="x", padx=12, pady=12)

    tk.Label(ac, text="Analytics & Visualization", bg=CARD_BG, fg=ACCENT, font=("Segoe UI", 12, "bold")).pack(side="left")
    make_button(ac, "Traffic Graph", show_traffic_graph, PURPLE, width=12).pack(side="right", padx=4)
    make_button(ac, "Protocol Chart", show_protocol_chart, BLUE, width=12).pack(side="right", padx=4)

    analytics_card = make_card(analytics_page)
    analytics_card.pack(fill="both", expand=True)

    analytics_text = tk.Text(analytics_card, bg=TABLE_BG, fg=TEXT, insertbackground="white", relief="flat", font=("Consolas", 11), wrap="word")
    analytics_text.tag_config("heading", foreground=ACCENT, font=("Consolas", 11, "bold"))
    analytics_text.pack(fill="both", expand=True, padx=12, pady=12)
    analytics_text.config(state="disabled")

    # SETTINGS
    settings_card = make_card(settings_page)
    settings_card.pack(fill="x", pady=(0, 12))

    tk.Label(settings_card, text="Preferences", bg=CARD_BG, fg=ACCENT, font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=12, pady=(12, 8))

    form = tk.Frame(settings_card, bg=CARD_BG)
    form.pack(fill="x", padx=12, pady=(0, 12))

    tk.Label(form, text="Theme Mode", bg=CARD_BG, fg=MUTED, font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky="w", pady=6)
    tk.OptionMenu(form, theme_var, "Dark").grid(row=0, column=1, sticky="w", pady=6)

    tk.Label(form, text="Alert Threshold", bg=CARD_BG, fg=MUTED, font=("Segoe UI", 10, "bold")).grid(row=1, column=0, sticky="w", pady=6)
    tk.Entry(form, textvariable=threshold_var, bg=TABLE_BG, fg=TEXT, insertbackground="white", relief="flat", width=24).grid(row=1, column=1, sticky="w", pady=6, ipady=5)

    tk.Label(form, text="Suspicious Ports", bg=CARD_BG, fg=MUTED, font=("Segoe UI", 10, "bold")).grid(row=2, column=0, sticky="w", pady=6)
    tk.Entry(form, textvariable=ports_var, bg=TABLE_BG, fg=TEXT, insertbackground="white", relief="flat", width=32).grid(row=2, column=1, sticky="w", pady=6, ipady=5)

    tk.Checkbutton(form, text="Auto-save packet snapshots", variable=autosave_var, bg=CARD_BG, fg=TEXT, selectcolor=CARD_BG, activebackground=CARD_BG).grid(row=3, column=0, columnspan=2, sticky="w", pady=6)
    tk.Checkbutton(form, text="Show in-app toast notifications", variable=toast_var, bg=CARD_BG, fg=TEXT, selectcolor=CARD_BG, activebackground=CARD_BG).grid(row=4, column=0, columnspan=2, sticky="w", pady=6)

    make_button(settings_card, "Save Preferences", save_preferences, GREEN, width=16).pack(anchor="w", padx=12, pady=(0, 14))

    actions_card = make_card(settings_page)
    actions_card.pack(fill="x", pady=(0, 12))
    tk.Label(actions_card, text="Workspace Actions", bg=CARD_BG, fg=ACCENT, font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=12, pady=(12, 8))

    actions = tk.Frame(actions_card, bg=CARD_BG)
    actions.pack(anchor="w", padx=12, pady=(0, 14))
    make_button(actions, "Clear All Data", clear_all_data, RED, width=14).grid(row=0, column=0, padx=4, pady=4)
    make_button(actions, "Save Packets", save_to_csv, BLUE, width=14).grid(row=0, column=1, padx=4, pady=4)
    make_button(actions, "Export Alerts", export_alerts_csv, PURPLE, width=14).grid(row=0, column=2, padx=4, pady=4)

    # Footer
    footer = tk.Frame(content, bg=CARD_ALT, height=36)
    footer.pack(fill="x", padx=18, pady=(0, 18))
    footer.pack_propagate(False)

    footer_status = tk.Label(footer, text="Status: Stopped", bg=CARD_ALT, fg=TEXT, font=("Segoe UI", 9))
    footer_status.pack(side="left", padx=10)

    footer_interface = tk.Label(footer, text=f"Interface: {interface_var.get()}", bg=CARD_ALT, fg=TEXT, font=("Segoe UI", 9))
    footer_interface.pack(side="left", padx=10)

    footer_packets = tk.Label(footer, text="Packets: 0", bg=CARD_ALT, fg=TEXT, font=("Segoe UI", 9))
    footer_packets.pack(side="left", padx=10)

    footer_alerts = tk.Label(footer, text="Alerts: 0", bg=CARD_ALT, fg=TEXT, font=("Segoe UI", 9))
    footer_alerts.pack(side="left", padx=10)

    footer_lastsave = tk.Label(footer, text="Last Save: -", bg=CARD_ALT, fg=TEXT, font=("Segoe UI", 9))
    footer_lastsave.pack(side="right", padx=10)

    show_page("Dashboard")
    load_saved_alerts()
    refresh_dashboard()
    refresh_packets_table()
    refresh_alerts_table()
    refresh_analytics()
    refresh_blacklist_panel()
    update_footer()
    update_speed()

    root.mainloop()


# =========================
# MAIN
# =========================
if __name__ == "__main__":
    init_db()

    login_window = tk.Tk()
    login_window.title("Secure Login")
    login_window.geometry("420x300")
    login_window.configure(bg=APP_BG)
    login_window.resizable(False, False)
    login_window.eval("tk::PlaceWindow . center")

    login_card = tk.Frame(login_window, bg=CARD_BG, highlightthickness=1, highlightbackground="#222b36")
    login_card.pack(fill="both", expand=True, padx=18, pady=18)

    tk.Label(login_card, text="Packet Analyzer Login", fg=ACCENT, bg=CARD_BG, font=("Segoe UI", 17, "bold")).pack(pady=(22, 6))
    tk.Label(login_card, text="Sign in to access the security monitoring dashboard", fg=MUTED, bg=CARD_BG, font=("Segoe UI", 10)).pack(pady=(0, 14))

    user_wrap = tk.Frame(login_card, bg=CARD_BG)
    user_wrap.pack(fill="x", padx=28, pady=(0, 10))
    tk.Label(user_wrap, text="Username", fg=ACCENT, bg=CARD_BG, font=("Segoe UI", 10, "bold")).pack(anchor="w")
    username_entry = tk.Entry(user_wrap, bg=TABLE_BG, fg=TEXT, insertbackground="white", relief="flat", font=("Segoe UI", 11), width=26)
    username_entry.pack(fill="x", ipady=6, pady=(6, 0))

    pass_wrap = tk.Frame(login_card, bg=CARD_BG)
    pass_wrap.pack(fill="x", padx=28, pady=(0, 10))
    tk.Label(pass_wrap, text="Password", fg=ACCENT, bg=CARD_BG, font=("Segoe UI", 10, "bold")).pack(anchor="w")
    password_entry = tk.Entry(pass_wrap, show="*", bg=TABLE_BG, fg=TEXT, insertbackground="white", relief="flat", font=("Segoe UI", 11), width=26)
    password_entry.pack(fill="x", ipady=6, pady=(6, 0))

    tk.Button(
        login_card,
        text="Login",
        command=check_login,
        bg=GREEN,
        fg="white",
        activebackground=GREEN,
        activeforeground="white",
        relief="flat",
        bd=0,
        width=16,
        pady=8,
        font=("Segoe UI", 10, "bold"),
        cursor="hand2"
    ).pack(pady=18)

    password_entry.bind("<Return>", lambda event: check_login())
    username_entry.bind("<Return>", lambda event: password_entry.focus())

    login_window.mainloop()
