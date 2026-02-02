from scapy.all import sniff
from src.parser import parse_packet


def packet_callback(packet):
    # Analyze the packet
    data = parse_packet(packet)

    if data:
        src = data.get('src_ip', 'Unknown')
        dst = data.get('dst_ip', 'Unknown')
        info = data.get('info', f"Protocol: {data.get('proto')}")

        # Terminal Export
        print(f"📡 [{src}] -> [{dst}] | {info}")


def start_sniffing(interface):
    from scapy.layers import http

    print(f"🚀 NetSpy is listening on {interface}...")
    sniff(iface=interface, prn=packet_callback, store=0)