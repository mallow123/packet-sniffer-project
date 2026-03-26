from collections import Counter
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation


def refresh_analytics(app):
    top_sources = Counter()
    top_ports = Counter()

    for p in app.state.captured_packets:
        top_sources[p["src_ip"]] += 1
        if p["dst_port"] != "-":
            top_ports[p["dst_port"]] += 1

    app.analytics_text.config(state="normal")
    app.analytics_text.delete("1.0", "end")

    app.analytics_text.insert("end", "Top Source IPs\n", "heading")
    for ip, count in top_sources.most_common(5):
        app.analytics_text.insert("end", f"• {ip}  ->  {count} packets\n")

    app.analytics_text.insert("end", "\nTop Destination Ports\n", "heading")
    for port, count in top_ports.most_common(5):
        app.analytics_text.insert("end", f"• Port {port}  ->  {count} packets\n")

    app.analytics_text.insert("end", "\nSummary\n", "heading")
    app.analytics_text.insert("end", f"• Total Packets: {app.state.packet_count}\n")
    app.analytics_text.insert("end", f"• Alerts: {len(app.state.alerts_data)}\n")
    app.analytics_text.insert("end", f"• Blacklisted IPs: {len(app.state.blacklisted_ips)}\n")

    app.analytics_text.config(state="disabled")


def show_traffic_graph(app):
    fig, ax = plt.subplots(figsize=(8, 4))
    x_data = []
    y_data = []

    def update(frame):
        x_data.append(len(x_data))
        y_data.append(app.state.packet_count)
        ax.clear()
        ax.plot(x_data, y_data, linewidth=2)
        ax.set_title("Live Traffic Graph")
        ax.set_xlabel("Time")
        ax.set_ylabel("Packets")

    app.anim = FuncAnimation(fig, update, interval=1000, cache_frame_data=False)
    plt.show()


def show_protocol_chart(app):
    sizes = [app.state.tcp_count, app.state.udp_count, app.state.other_count]
    labels = ["TCP", "UDP", "OTHER"]

    if app.state.packet_count == 0:
        from tkinter import messagebox
        messagebox.showinfo("No Data", "No packets captured yet")
        return

    plt.figure(figsize=(6, 6))
    plt.pie(sizes, labels=labels, autopct="%1.1f%%")
    plt.title("Protocol Distribution")
    plt.show()
