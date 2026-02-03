import os
from scapy.all import wrpcap
from scapy.all import sniff
from src.parser import parse_packet
from src.analyzer import TrafficAnalyzer

analyzer = TrafficAnalyzer()

# Auto-create logs directory
LOG_DIR = "logs"
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)
    print(f"📁 Created directory: {LOG_DIR}")

PCAP_FILE = os.path.join(LOG_DIR, "captured_traffic.pcap")

def packet_callback(packet):
    # Analyze the packet
    data = parse_packet(packet)

    if data:
        credential_alert = analyzer.detect_credentials(packet)

        src = data.get('src_ip', 'Unknown')
        dst = data.get('dst_ip', 'Unknown')
        info = data.get('info', f"Protocol: {data.get('proto')}")

        # Terminal Export
        print(f"📡 [{src}] -> [{dst}] | {info}")

        if credential_alert:
            print(f"🚨 {credential_alert}")

    wrpcap(PCAP_FILE, packet, append=True)


def start_sniffing(interface):
    from scapy.layers import http

    print(f"🚀 NetSpy is listening on {interface}...")
    sniff(iface=interface, prn=packet_callback, store=0)