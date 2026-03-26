from scapy.all import sniff, IP, TCP, UDP

from services.alert_service import add_alert, log_attack


def get_alert_threshold(settings: dict) -> int:
    try:
        return int(settings.get("alert_threshold", 50))
    except ValueError:
        return 50


def get_suspicious_ports(settings: dict) -> list[int]:
    try:
        return [
            int(x.strip())
            for x in settings.get("suspicious_ports", "21,22,23,3389,4444,8080").split(",")
            if x.strip()
        ]
    except ValueError:
        return [21, 22, 23, 3389, 4444, 8080]


def sniff_packets(app):
    iface = app.interface_var.get()
    sniff(prn=lambda pkt: process_packet(app, pkt), iface=iface, store=False)


def process_packet(app, packet):
    state = app.state

    if not state.sniffing or IP not in packet:
        return

    state.total_bytes += len(packet)

    protocol = "OTHER"
    src_port = "-"
    dst_port = "-"

    if TCP in packet:
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        state.tcp_count += 1
    elif UDP in packet:
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        state.udp_count += 1
    else:
        state.other_count += 1

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    state.traffic_counter[src_ip] = state.traffic_counter.get(src_ip, 0) + 1

    threshold = get_alert_threshold(app.settings)
    suspicious_ports = get_suspicious_ports(app.settings)

    if state.traffic_counter[src_ip] == threshold:
        state.blacklisted_ips.add(src_ip)

        log_attack(src_ip, "-", "Possible DoS / Port Scan", "High")
        add_alert(
            state,
            src_ip,
            "-",
            "Possible DoS / Port Scan",
            "High",
            f"{src_ip} crossed threshold {threshold} and was blacklisted.",
        )

        app.root.after(0, app.refresh_blacklist_panel)
        app.root.after(0, app.refresh_alerts_table)
        app.root.after(0, app.refresh_dashboard)
        app.root.after(0, app.refresh_analytics)
        app.root.after(0, lambda: app.show_toast("High Threat Detected", f"{src_ip} added to blacklist.", app.RED))

    if src_port in suspicious_ports or dst_port in suspicious_ports:
        attack_port = src_port if src_port in suspicious_ports else dst_port

        log_attack(src_ip, attack_port, "Suspicious Port Activity", "Medium")
        add_alert(
            state,
            src_ip,
            attack_port,
            "Suspicious Port Activity",
            "Medium",
            f"Traffic detected on suspicious port {attack_port} from {src_ip}.",
        )

        app.root.after(0, app.refresh_alerts_table)
        app.root.after(0, app.refresh_dashboard)
        app.root.after(0, app.refresh_analytics)
        app.root.after(0, lambda: app.show_toast("Suspicious Port Activity", f"{src_ip} used port {attack_port}.", app.ORANGE))

    packet_info = {
        "time": app.now_str(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "src_port": str(src_port),
        "dst_port": str(dst_port),
        "size": len(packet),
        "packet": packet,
    }

    state.captured_packets.append(packet_info)
    state.packet_count += 1

    if app.settings.get("auto_save_packets", "False") == "True" and state.packet_count % 100 == 0:
        app.root.after(0, app.auto_save_snapshot)

    app.root.after(0, app.refresh_packets_table)
    app.root.after(0, app.refresh_dashboard)
    app.root.after(0, app.refresh_analytics)
    app.root.after(0, app.update_footer)
