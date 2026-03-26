import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
import threading
import csv

from scapy.all import get_if_list

from config import (
    APP_BG, SIDEBAR_BG, CARD_BG, CARD_ALT, TABLE_BG,
    TEXT, MUTED, ACCENT, GREEN, RED, BLUE, PURPLE,
    GRAY, YELLOW, CYAN, MINT, WARNING, ORANGE
)
from database import load_settings, save_setting
from services.export_service import save_packets_csv, export_alerts_csv
from services.alert_service import compute_threat_level
from services.sniffer_service import sniff_packets

from ui.packets import refresh_packets_table, show_packet_details
from ui.alerts import refresh_alerts_table
from ui.analytics import refresh_analytics, show_traffic_graph, show_protocol_chart
from ui.settings import save_preferences
from ui.dashboard_layout import (
    build_sidebar,
    build_topbar,
    build_dashboard_page,
    build_packets_page,
    build_alerts_page,
    build_analytics_page,
    build_settings_page,
    build_footer,
)


class DashboardApp:
    def __init__(self, state):
        self.state = state
        self.settings = load_settings()

        self.root = None
        self.anim = None

        self.interface_var = None
        self.search_var = None
        self.packet_filter_var = None

        self.theme_var = None
        self.threshold_var = None
        self.ports_var = None
        self.autosave_var = None
        self.toast_var = None

        self.status_value = None
        self.footer_status = None
        self.footer_interface = None
        self.footer_packets = None
        self.footer_alerts = None
        self.footer_lastsave = None

        self.total_packets_value = None
        self.active_ips_value = None
        self.blacklisted_value = None
        self.alerts_value = None
        self.threat_value = None
        self.protocol_value = None
        self.bandwidth_value = None

        self.packets_table = None
        self.alerts_table = None
        self.analytics_text = None
        self.blacklist_box = None
        self.recent_alerts_list = None

        self.dashboard_page = None
        self.packets_page = None
        self.alerts_page = None
        self.analytics_page = None
        self.settings_page = None

        self.filtered_packets = []

        self.APP_BG = APP_BG
        self.SIDEBAR_BG = SIDEBAR_BG
        self.CARD_BG = CARD_BG
        self.CARD_ALT = CARD_ALT
        self.TABLE_BG = TABLE_BG
        self.TEXT = TEXT
        self.MUTED = MUTED
        self.ACCENT = ACCENT
        self.GREEN = GREEN
        self.RED = RED
        self.BLUE = BLUE
        self.PURPLE = PURPLE
        self.GRAY = GRAY
        self.YELLOW = YELLOW
        self.CYAN = CYAN
        self.MINT = MINT
        self.WARNING = WARNING
        self.ORANGE = ORANGE

    def now_str(self):
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def short_time(self):
        return datetime.now().strftime("%H:%M:%S")

    def show_toast(self, title, message, color=BLUE):
        if self.settings.get("show_toasts", "True") != "True" or self.root is None:
            return

        toast = tk.Toplevel(self.root)
        toast.overrideredirect(True)
        toast.configure(bg=self.CARD_BG)
        toast.attributes("-topmost", True)

        width = 320
        height = 90
        x = self.root.winfo_x() + self.root.winfo_width() - width - 20
        y = self.root.winfo_y() + self.root.winfo_height() - height - 60
        toast.geometry(f"{width}x{height}+{x}+{y}")

        frame = tk.Frame(toast, bg=self.CARD_BG, highlightthickness=1, highlightbackground=color)
        frame.pack(fill="both", expand=True)

        tk.Label(frame, text=title, bg=self.CARD_BG, fg=color, font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=12, pady=(10, 2))
        tk.Label(frame, text=message, bg=self.CARD_BG, fg=self.TEXT, font=("Segoe UI", 9), wraplength=290, justify="left").pack(anchor="w", padx=12)

        toast.after(2600, toast.destroy)

    def start_sniff(self):
        if self.state.sniffing:
            return

        self.state.sniffing = True
        self.status_value.config(text="Running", fg=self.GREEN)
        self.update_footer()
        save_setting("default_interface", self.interface_var.get())
        self.show_toast("Capture Started", f"Listening on {self.interface_var.get()}", self.GREEN)

        threading.Thread(target=lambda: sniff_packets(self), daemon=True).start()

    def stop_sniff(self):
        self.state.sniffing = False
        self.status_value.config(text="Stopped", fg=self.RED)
        self.update_footer()
        self.show_toast("Capture Stopped", "Packet capture has been stopped.", self.RED)

    def update_footer(self, last_save_text=None):
        if self.footer_status:
            self.footer_status.config(text=f"Status: {'Running' if self.state.sniffing else 'Stopped'}")
        if self.footer_interface and self.interface_var is not None:
            self.footer_interface.config(text=f"Interface: {self.interface_var.get()}")
        if self.footer_packets:
            self.footer_packets.config(text=f"Packets: {self.state.packet_count}")
        if self.footer_alerts:
            self.footer_alerts.config(text=f"Alerts: {len(self.state.alerts_data)}")
        if self.footer_lastsave and last_save_text is not None:
            self.footer_lastsave.config(text=f"Last Save: {last_save_text}")

    def refresh_dashboard(self):
        self.total_packets_value.config(text=str(self.state.packet_count))
        self.active_ips_value.config(text=str(len(self.state.traffic_counter)))
        self.blacklisted_value.config(text=str(len(self.state.blacklisted_ips)))
        self.alerts_value.config(text=str(len(self.state.alerts_data)))
        self.protocol_value.config(
            text=f"TCP: {self.state.tcp_count} | UDP: {self.state.udp_count} | OTHER: {self.state.other_count}"
        )

        level = compute_threat_level(self.state)
        color = self.GREEN if level == "LOW" else self.ORANGE if level == "MEDIUM" else self.RED
        self.threat_value.config(text=level, fg=color)

        self.refresh_recent_alerts()

    def refresh_recent_alerts(self):
        self.recent_alerts_list.delete(0, tk.END)
        for alert in self.state.alerts_data[-10:][::-1]:
            self.recent_alerts_list.insert(tk.END, f"{alert['time']} | {alert['severity']} | {alert['ip']}")

    def update_speed(self):
        speed = self.state.total_bytes / 1024
        self.bandwidth_value.config(text=f"{speed:.2f} KB/s")
        self.state.total_bytes = 0
        self.root.after(1000, self.update_speed)

    def refresh_packets_table(self):
        refresh_packets_table(self)

    def show_packet_details(self, event=None):
        show_packet_details(self, event)

    def refresh_alerts_table(self):
        refresh_alerts_table(self)

    def refresh_analytics(self):
        refresh_analytics(self)

    def show_traffic_graph(self):
        show_traffic_graph(self)

    def show_protocol_chart(self):
        show_protocol_chart(self)

    def save_to_csv(self):
        filename = save_packets_csv(self.state)
        if not filename:
            messagebox.showinfo("Info", "No packets to save")
            return
        self.update_footer(self.short_time())
        self.show_toast("Packets Saved", f"Saved to {filename}", self.GREEN)

    def auto_save_snapshot(self):
        filename = "autosave_packets.csv"
        with open(filename, "w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["Time", "Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port", "Size"])
            for p in self.state.captured_packets[-500:]:
                writer.writerow([
                    p["time"], p["src_ip"], p["dst_ip"], p["protocol"],
                    p["src_port"], p["dst_port"], p["size"]
                ])
        self.update_footer(self.short_time())

    def export_alerts_csv(self):
        filename = export_alerts_csv(self.state)
        if not filename:
            messagebox.showinfo("Info", "No alerts to export")
            return
        self.update_footer(self.short_time())
        self.show_toast("Alerts Exported", f"Saved to {filename}", self.PURPLE)

    def clear_all_data(self):
        self.state.packet_count = 0
        self.state.captured_packets.clear()
        self.filtered_packets.clear()
        self.state.tcp_count = 0
        self.state.udp_count = 0
        self.state.other_count = 0
        self.state.total_bytes = 0
        self.state.traffic_counter.clear()
        self.state.blacklisted_ips.clear()
        self.state.alerts_data.clear()

        self.refresh_packets_table()
        self.refresh_alerts_table()
        self.refresh_blacklist_panel()
        self.refresh_dashboard()
        self.refresh_analytics()
        self.update_footer()
        self.show_toast("Workspace Cleared", "All runtime data has been cleared.", self.RED)

    def refresh_blacklist_panel(self):
        self.blacklist_box.delete(0, tk.END)
        for ip in sorted(self.state.blacklisted_ips):
            self.blacklist_box.insert(tk.END, ip)

    def save_preferences(self):
        save_preferences(self)

    def show_page(self, name):
        self.dashboard_page.pack_forget()
        self.packets_page.pack_forget()
        self.alerts_page.pack_forget()
        self.analytics_page.pack_forget()
        self.settings_page.pack_forget()

        {
            "Dashboard": self.dashboard_page,
            "Packets": self.packets_page,
            "Alerts": self.alerts_page,
            "Analytics": self.analytics_page,
            "Settings": self.settings_page,
        }[name].pack(fill="both", expand=True)

    def launch(self):
        self.root = tk.Tk()
        self.root.title("Cyber Packet Analyzer")
        self.root.geometry("1400x860")
        self.root.minsize(1200, 760)
        self.root.configure(bg=self.APP_BG)

        interfaces = get_if_list()
        if not interfaces:
            messagebox.showerror("Error", "No network interfaces found!")
            return

        default_iface = self.settings["default_interface"] if self.settings["default_interface"] in interfaces else interfaces[0]

        self.interface_var = tk.StringVar(value=default_iface)
        self.search_var = tk.StringVar()
        self.packet_filter_var = tk.StringVar(value="ALL")

        self.theme_var = tk.StringVar(value=self.settings.get("theme_mode", "Dark"))
        self.threshold_var = tk.StringVar(value=self.settings.get("alert_threshold", "50"))
        self.ports_var = tk.StringVar(value=self.settings.get("suspicious_ports", "21,22,23,3389,4444,8080"))
        self.autosave_var = tk.BooleanVar(value=self.settings.get("auto_save_packets", "False") == "True")
        self.toast_var = tk.BooleanVar(value=self.settings.get("show_toasts", "True") == "True")

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background=self.TABLE_BG, foreground=self.TEXT, fieldbackground=self.TABLE_BG, rowheight=28, font=("Segoe UI", 10))
        style.configure("Treeview.Heading", background=self.CARD_ALT, foreground=self.ACCENT, font=("Segoe UI", 10, "bold"))
        style.map("Treeview", background=[("selected", self.GREEN)])

        shell = tk.Frame(self.root, bg=self.APP_BG)
        shell.pack(fill="both", expand=True)

        build_sidebar(self, shell, interfaces)

        content = tk.Frame(shell, bg=self.APP_BG)
        content.pack(side="left", fill="both", expand=True)

        build_topbar(self, content)

        pages = tk.Frame(content, bg=self.APP_BG)
        pages.pack(fill="both", expand=True, padx=18, pady=(0, 8))

        build_dashboard_page(self, pages)
        build_packets_page(self, pages)
        build_alerts_page(self, pages)
        build_analytics_page(self, pages)
        build_settings_page(self, pages)
        build_footer(self, content)

        self.show_page("Dashboard")
        self.refresh_dashboard()
        self.refresh_packets_table()
        self.refresh_alerts_table()
        self.refresh_analytics()
        self.refresh_blacklist_panel()
        self.update_footer()
        self.update_speed()

        self.root.mainloop()


def launch_dashboard_ui(state):
    app = DashboardApp(state)
    app.launch()
