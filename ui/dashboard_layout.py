import tkinter as tk
from tkinter import ttk

from ui.components import make_button, make_card, make_title, make_stat_card, make_info_card


def build_sidebar(app, parent, interfaces):
    sidebar = tk.Frame(parent, bg=app.SIDEBAR_BG, width=220)
    sidebar.pack(side="left", fill="y")
    sidebar.pack_propagate(False)

    tk.Label(
        sidebar,
        text="Packet Analyzer",
        bg=app.SIDEBAR_BG,
        fg=app.ACCENT,
        font=("Segoe UI", 16, "bold")
    ).pack(anchor="w", padx=18, pady=(18, 4))

    tk.Label(
        sidebar,
        text="Security Monitoring Platform",
        bg=app.SIDEBAR_BG,
        fg=app.MUTED,
        font=("Segoe UI", 9)
    ).pack(anchor="w", padx=18, pady=(0, 18))

    def nav_btn(text):
        return tk.Button(
            sidebar,
            text=text,
            command=lambda t=text: app.show_page(t),
            bg=app.SIDEBAR_BG,
            fg=app.TEXT,
            activebackground=app.CARD_ALT,
            activeforeground=app.TEXT,
            relief="flat",
            bd=0,
            anchor="w",
            padx=18,
            pady=10,
            font=("Segoe UI", 10, "bold"),
            cursor="hand2"
        )

    nav_btn("Dashboard").pack(fill="x")
    nav_btn("Packets").pack(fill="x")
    nav_btn("Alerts").pack(fill="x")
    nav_btn("Analytics").pack(fill="x")
    nav_btn("Settings").pack(fill="x")

    tk.Label(sidebar, text="", bg=app.SIDEBAR_BG).pack(fill="x", pady=8)

    tk.Label(
        sidebar,
        text="Interface",
        bg=app.SIDEBAR_BG,
        fg=app.MUTED,
        font=("Segoe UI", 9, "bold")
    ).pack(anchor="w", padx=18, pady=(10, 4))

    interface_menu = tk.OptionMenu(sidebar, app.interface_var, *interfaces)
    interface_menu.config(
        bg=app.CARD_ALT,
        fg=app.TEXT,
        activebackground=app.CARD_ALT,
        activeforeground=app.TEXT,
        highlightthickness=0,
        bd=0,
        width=16
    )
    interface_menu["menu"].config(bg=app.CARD_ALT, fg=app.TEXT)
    interface_menu.pack(anchor="w", padx=18)

    make_button(sidebar, "▶ Start", app.start_sniff, app.GREEN, width=16).pack(padx=18, pady=(20, 8))
    make_button(sidebar, "■ Stop", app.stop_sniff, app.RED, width=16).pack(padx=18, pady=4)
    make_button(sidebar, "💾 Save Packets", app.save_to_csv, app.BLUE, width=16).pack(padx=18, pady=4)
    make_button(sidebar, "📤 Export Alerts", app.export_alerts_csv, app.PURPLE, width=16).pack(padx=18, pady=4)

    return sidebar


def build_topbar(app, parent):
    topbar = tk.Frame(parent, bg=app.APP_BG)
    topbar.pack(fill="x", padx=18, pady=(18, 8))

    make_title(
        topbar,
        "Cyber Packet Analyzer",
        "Enterprise-style endpoint packet monitoring and threat visibility",
        app.APP_BG,
        app.TEXT,
        app.MUTED
    )

    top_actions = tk.Frame(topbar, bg=app.APP_BG)
    top_actions.pack(side="right")

    app.status_value = tk.Label(
        top_actions,
        text="Stopped",
        bg=app.APP_BG,
        fg=app.RED,
        font=("Segoe UI", 11, "bold")
    )
    app.status_value.pack(side="left", padx=10)

    user_badge = tk.Label(
        top_actions,
        text="User: admin",
        bg=app.CARD_ALT,
        fg=app.TEXT,
        font=("Segoe UI", 9, "bold"),
        padx=10,
        pady=6
    )
    user_badge.pack(side="left", padx=4)


def build_dashboard_page(app, parent):
    app.dashboard_page = tk.Frame(parent, bg=app.APP_BG)

    cards_row = tk.Frame(app.dashboard_page, bg=app.APP_BG)
    cards_row.pack(fill="x", pady=(0, 12))

    app.total_packets_value = make_stat_card(cards_row, "Total Packets", app.CYAN, app.CARD_BG, app.MUTED)
    app.active_ips_value = make_stat_card(cards_row, "Active Source IPs", app.ACCENT, app.CARD_BG, app.MUTED)
    app.blacklisted_value = make_stat_card(cards_row, "Blacklisted IPs", app.WARNING, app.CARD_BG, app.MUTED)
    app.alerts_value = make_stat_card(cards_row, "Alerts Today", app.ORANGE, app.CARD_BG, app.MUTED)

    cards_row2 = tk.Frame(app.dashboard_page, bg=app.APP_BG)
    cards_row2.pack(fill="x", pady=(0, 12))

    app.threat_value = make_info_card(cards_row2, "Threat Level", "LOW", app.GREEN, app.CARD_BG, app.MUTED)
    app.protocol_value = make_info_card(cards_row2, "Protocol Mix", "TCP: 0 | UDP: 0 | OTHER: 0", app.YELLOW, app.CARD_BG, app.MUTED)
    app.bandwidth_value = make_info_card(cards_row2, "Bandwidth", "0.00 KB/s", app.MINT, app.CARD_BG, app.MUTED)

    dash_lower = tk.Frame(app.dashboard_page, bg=app.APP_BG)
    dash_lower.pack(fill="both", expand=True)

    recent_card = make_card(dash_lower, app.CARD_BG)
    recent_card.pack(side="left", fill="both", expand=True, padx=6)
    tk.Label(
        recent_card,
        text="Recent Alerts",
        bg=app.CARD_BG,
        fg=app.ACCENT,
        font=("Segoe UI", 12, "bold")
    ).pack(anchor="w", padx=12, pady=(12, 8))

    app.recent_alerts_list = tk.Listbox(
        recent_card,
        bg=app.TABLE_BG,
        fg=app.TEXT,
        selectbackground=app.RED,
        selectforeground="white",
        relief="flat",
        bd=0,
        font=("Consolas", 10)
    )
    app.recent_alerts_list.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    blacklist_card = make_card(dash_lower, app.CARD_BG)
    blacklist_card.pack(side="left", fill="both", expand=True, padx=6)
    tk.Label(
        blacklist_card,
        text="Blacklisted IPs",
        bg=app.CARD_BG,
        fg=app.WARNING,
        font=("Segoe UI", 12, "bold")
    ).pack(anchor="w", padx=12, pady=(12, 8))

    app.blacklist_box = tk.Listbox(
        blacklist_card,
        bg=app.TABLE_BG,
        fg=app.WARNING,
        selectbackground=app.RED,
        selectforeground="white",
        relief="flat",
        bd=0,
        font=("Consolas", 10)
    )
    app.blacklist_box.pack(fill="both", expand=True, padx=12, pady=(0, 12))


def build_packets_page(app, parent):
    app.packets_page = tk.Frame(parent, bg=app.APP_BG)

    packets_top = make_card(app.packets_page, app.CARD_BG)
    packets_top.pack(fill="x", pady=(0, 12))

    ctrl = tk.Frame(packets_top, bg=app.CARD_BG)
    ctrl.pack(fill="x", padx=12, pady=12)

    tk.Label(ctrl, text="Search", bg=app.CARD_BG, fg=app.MUTED, font=("Segoe UI", 10, "bold")).grid(row=0, column=0, padx=(0, 6))
    tk.Entry(
        ctrl,
        textvariable=app.search_var,
        bg=app.TABLE_BG,
        fg=app.TEXT,
        insertbackground="white",
        relief="flat",
        font=("Segoe UI", 10),
        width=30
    ).grid(row=0, column=1, padx=(0, 12), ipady=5)

    tk.Label(ctrl, text="Protocol", bg=app.CARD_BG, fg=app.MUTED, font=("Segoe UI", 10, "bold")).grid(row=0, column=2, padx=(0, 6))

    filt = tk.OptionMenu(ctrl, app.packet_filter_var, "ALL", "TCP", "UDP", "OTHER")
    filt.config(
        bg=app.TABLE_BG,
        fg=app.TEXT,
        activebackground=app.TABLE_BG,
        activeforeground=app.TEXT,
        highlightthickness=0,
        bd=0,
        width=10
    )
    filt["menu"].config(bg=app.TABLE_BG, fg=app.TEXT)
    filt.grid(row=0, column=3, padx=(0, 12))

    make_button(ctrl, "Apply Filter", app.refresh_packets_table, app.BLUE, width=12).grid(row=0, column=4, padx=4)

    packets_card = make_card(app.packets_page, app.CARD_BG)
    packets_card.pack(fill="both", expand=True)

    tk.Label(
        packets_card,
        text="Captured Packets",
        bg=app.CARD_BG,
        fg=app.ACCENT,
        font=("Segoe UI", 12, "bold")
    ).pack(anchor="w", padx=12, pady=(12, 8))

    packets_frame = tk.Frame(packets_card, bg=app.CARD_BG)
    packets_frame.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    packet_cols = ("Time", "Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port", "Size")
    app.packets_table = ttk.Treeview(packets_frame, columns=packet_cols, show="headings")

    for col in packet_cols:
        app.packets_table.heading(col, text=col)
        app.packets_table.column(col, width=140, anchor="center")

    pscroll = ttk.Scrollbar(packets_frame, orient="vertical", command=app.packets_table.yview)
    app.packets_table.configure(yscrollcommand=pscroll.set)
    app.packets_table.pack(side="left", fill="both", expand=True)
    pscroll.pack(side="right", fill="y")

    app.packets_table.bind("<Double-1>", app.show_packet_details)


def build_alerts_page(app, parent):
    app.alerts_page = tk.Frame(parent, bg=app.APP_BG)

    alerts_top = make_card(app.alerts_page, app.CARD_BG)
    alerts_top.pack(fill="x", pady=(0, 12))

    atop = tk.Frame(alerts_top, bg=app.CARD_BG)
    atop.pack(fill="x", padx=12, pady=12)

    tk.Label(
        atop,
        text="Alerts Center",
        bg=app.CARD_BG,
        fg=app.ACCENT,
        font=("Segoe UI", 12, "bold")
    ).pack(side="left")

    make_button(atop, "Export Alerts", app.export_alerts_csv, app.PURPLE, width=12).pack(side="right")

    alerts_card = make_card(app.alerts_page, app.CARD_BG)
    alerts_card.pack(fill="both", expand=True)

    alerts_frame = tk.Frame(alerts_card, bg=app.CARD_BG)
    alerts_frame.pack(fill="both", expand=True, padx=12, pady=12)

    alert_cols = ("Time", "IP", "Port", "Type", "Severity", "Status")
    app.alerts_table = ttk.Treeview(alerts_frame, columns=alert_cols, show="headings")

    for col in alert_cols:
        app.alerts_table.heading(col, text=col)
        app.alerts_table.column(col, width=150, anchor="center")

    ascroll = ttk.Scrollbar(alerts_frame, orient="vertical", command=app.alerts_table.yview)
    app.alerts_table.configure(yscrollcommand=ascroll.set)
    app.alerts_table.pack(side="left", fill="both", expand=True)
    ascroll.pack(side="right", fill="y")


def build_analytics_page(app, parent):
    app.analytics_page = tk.Frame(parent, bg=app.APP_BG)

    analytics_controls = make_card(app.analytics_page, app.CARD_BG)
    analytics_controls.pack(fill="x", pady=(0, 12))

    ac = tk.Frame(analytics_controls, bg=app.CARD_BG)
    ac.pack(fill="x", padx=12, pady=12)

    tk.Label(
        ac,
        text="Analytics & Visualization",
        bg=app.CARD_BG,
        fg=app.ACCENT,
        font=("Segoe UI", 12, "bold")
    ).pack(side="left")

    make_button(ac, "Traffic Graph", app.show_traffic_graph, app.PURPLE, width=12).pack(side="right", padx=4)
    make_button(ac, "Protocol Chart", app.show_protocol_chart, app.BLUE, width=12).pack(side="right", padx=4)

    analytics_card = make_card(app.analytics_page, app.CARD_BG)
    analytics_card.pack(fill="both", expand=True)

    app.analytics_text = tk.Text(
        analytics_card,
        bg=app.TABLE_BG,
        fg=app.TEXT,
        insertbackground="white",
        relief="flat",
        font=("Consolas", 11),
        wrap="word"
    )
    app.analytics_text.tag_config("heading", foreground=app.ACCENT, font=("Consolas", 11, "bold"))
    app.analytics_text.pack(fill="both", expand=True, padx=12, pady=12)
    app.analytics_text.config(state="disabled")


def build_settings_page(app, parent):
    app.settings_page = tk.Frame(parent, bg=app.APP_BG)

    settings_card = make_card(app.settings_page, app.CARD_BG)
    settings_card.pack(fill="x", pady=(0, 12))

    tk.Label(
        settings_card,
        text="Preferences",
        bg=app.CARD_BG,
        fg=app.ACCENT,
        font=("Segoe UI", 12, "bold")
    ).pack(anchor="w", padx=12, pady=(12, 8))

    form = tk.Frame(settings_card, bg=app.CARD_BG)
    form.pack(fill="x", padx=12, pady=(0, 12))

    tk.Label(form, text="Theme Mode", bg=app.CARD_BG, fg=app.MUTED, font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky="w", pady=6)
    tk.OptionMenu(form, app.theme_var, "Dark").grid(row=0, column=1, sticky="w", pady=6)

    tk.Label(form, text="Alert Threshold", bg=app.CARD_BG, fg=app.MUTED, font=("Segoe UI", 10, "bold")).grid(row=1, column=0, sticky="w", pady=6)
    tk.Entry(
        form,
        textvariable=app.threshold_var,
        bg=app.TABLE_BG,
        fg=app.TEXT,
        insertbackground="white",
        relief="flat",
        width=24
    ).grid(row=1, column=1, sticky="w", pady=6, ipady=5)

    tk.Label(form, text="Suspicious Ports", bg=app.CARD_BG, fg=app.MUTED, font=("Segoe UI", 10, "bold")).grid(row=2, column=0, sticky="w", pady=6)
    tk.Entry(
        form,
        textvariable=app.ports_var,
        bg=app.TABLE_BG,
        fg=app.TEXT,
        insertbackground="white",
        relief="flat",
        width=32
    ).grid(row=2, column=1, sticky="w", pady=6, ipady=5)

    tk.Checkbutton(
        form,
        text="Auto-save packet snapshots",
        variable=app.autosave_var,
        bg=app.CARD_BG,
        fg=app.TEXT,
        selectcolor=app.CARD_BG,
        activebackground=app.CARD_BG
    ).grid(row=3, column=0, columnspan=2, sticky="w", pady=6)

    tk.Checkbutton(
        form,
        text="Show in-app toast notifications",
        variable=app.toast_var,
        bg=app.CARD_BG,
        fg=app.TEXT,
        selectcolor=app.CARD_BG,
        activebackground=app.CARD_BG
    ).grid(row=4, column=0, columnspan=2, sticky="w", pady=6)

    make_button(settings_card, "Save Preferences", app.save_preferences, app.GREEN, width=16).pack(anchor="w", padx=12, pady=(0, 14))

    actions_card = make_card(app.settings_page, app.CARD_BG)
    actions_card.pack(fill="x", pady=(0, 12))

    tk.Label(
        actions_card,
        text="Workspace Actions",
        bg=app.CARD_BG,
        fg=app.ACCENT,
        font=("Segoe UI", 12, "bold")
    ).pack(anchor="w", padx=12, pady=(12, 8))

    actions = tk.Frame(actions_card, bg=app.CARD_BG)
    actions.pack(anchor="w", padx=12, pady=(0, 14))

    make_button(actions, "Clear All Data", app.clear_all_data, app.RED, width=14).grid(row=0, column=0, padx=4, pady=4)
    make_button(actions, "Save Packets", app.save_to_csv, app.BLUE, width=14).grid(row=0, column=1, padx=4, pady=4)
    make_button(actions, "Export Alerts", app.export_alerts_csv, app.PURPLE, width=14).grid(row=0, column=2, padx=4, pady=4)


def build_footer(app, parent):
    footer = tk.Frame(parent, bg=app.CARD_ALT, height=36)
    footer.pack(fill="x", padx=18, pady=(0, 18))
    footer.pack_propagate(False)

    app.footer_status = tk.Label(footer, text="Status: Stopped", bg=app.CARD_ALT, fg=app.TEXT, font=("Segoe UI", 9))
    app.footer_status.pack(side="left", padx=10)

    app.footer_interface = tk.Label(footer, text=f"Interface: {app.interface_var.get()}", bg=app.CARD_ALT, fg=app.TEXT, font=("Segoe UI", 9))
    app.footer_interface.pack(side="left", padx=10)

    app.footer_packets = tk.Label(footer, text="Packets: 0", bg=app.CARD_ALT, fg=app.TEXT, font=("Segoe UI", 9))
    app.footer_packets.pack(side="left", padx=10)

    app.footer_alerts = tk.Label(footer, text="Alerts: 0", bg=app.CARD_ALT, fg=app.TEXT, font=("Segoe UI", 9))
    app.footer_alerts.pack(side="left", padx=10)

    app.footer_lastsave = tk.Label(footer, text="Last Save: -", bg=app.CARD_ALT, fg=app.TEXT, font=("Segoe UI", 9))
    app.footer_lastsave.pack(side="right", padx=10)
