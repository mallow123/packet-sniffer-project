class AppState:
    def __init__(self):
        self.sniffing = False
        self.packet_count = 0
        self.captured_packets = []
        self.filtered_packets = []

        self.tcp_count = 0
        self.udp_count = 0
        self.other_count = 0
        self.total_bytes = 0

        self.traffic_counter = {}
        self.blacklisted_ips = set()
        self.alerts_data = []

        self.anim = None
