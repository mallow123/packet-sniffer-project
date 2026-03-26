import tkinter as tk
from tkinter import ttk
import binascii
from scapy.all import Raw


def refresh_packets_table(app):
    query = app.search_var.get().strip().lower()
    proto_filter = app.packet_filter_var.get()

    for item in app.packets_table.get_children():
        app.packets_table.delete(item)

    app.filtered_packets.clear()

    for p in app.state.captured_packets:
        if query:
            haystack = " ".join([
                p["time"],
                p["src_ip"],
                p["dst_ip"],
                p["protocol"],
                p["src_port"],
                p["dst_port"],
            ]).lower()
            if query not in haystack:
                continue

        if proto_filter != "ALL" and p["protocol"] != proto_filter:
            continue

        app.filtered_packets.append(p)
        app.packets_table.insert(
            "",
            tk.END,
            values=(
                p["time"],
                p["src_ip"],
                p["dst_ip"],
                p["protocol"],
                p["src_port"],
                p["dst_port"],
                p["size"],
            ),
        )


def show_packet_details(app, event=None):
    selected = app.packets_table.focus()
    if not selected:
        return

    index = app.packets_table.index(selected)
    if index >= len(app.filtered_packets):
        return

    packet_row = app.filtered_packets[index]
    packet = packet_row["packet"]

    detail = tk.Toplevel(app.root)
    detail.title("Packet Inspection")
    detail.geometry("820x620")
    detail.configure(bg=app.APP_BG)

    notebook = ttk.Notebook(detail)
    notebook.pack(fill="both", expand=True, padx=12, pady=12)

    summary_tab = tk.Frame(notebook, bg=app.CARD_BG)
    payload_tab = tk.Frame(notebook, bg=app.CARD_BG)
    raw_tab = tk.Frame(notebook, bg=app.CARD_BG)

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
        row = tk.Frame(summary_tab, bg=app.CARD_BG)
        row.pack(fill="x", padx=14, pady=5)
        tk.Label(
            row,
            text=f"{key}:",
            bg=app.CARD_BG,
            fg=app.ACCENT,
            font=("Segoe UI", 10, "bold")
        ).pack(side="left")
        tk.Label(
            row,
            text=f"  {value}",
            bg=app.CARD_BG,
            fg=app.TEXT,
            font=("Segoe UI", 10)
        ).pack(side="left")

    payload_text = tk.Text(
        payload_tab,
        bg=app.TABLE_BG,
        fg=app.CYAN,
        font=("Consolas", 10),
        relief="flat",
        wrap="word"
    )
    payload_text.pack(fill="both", expand=True, padx=12, pady=12)

    raw_text = tk.Text(
        raw_tab,
        bg=app.TABLE_BG,
        fg=app.TEXT,
        font=("Consolas", 10),
        relief="flat",
        wrap="word"
    )
    raw_text.pack(fill="both", expand=True, padx=12, pady=12)

    if Raw in packet:
        payload_text.insert("end", binascii.hexlify(bytes(packet[Raw].load)).decode())
    else:
        payload_text.insert("end", "No Raw Payload")

    raw_text.insert("end", packet.summary())

    payload_text.config(state="disabled")
    raw_text.config(state="disabled")
