from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTPRequest


def parse_packet(packet):
    """
    Analyzes the packet layers and extracts meaningful information.
    """
    analysis_results = {}

    if packet.haslayer(IP):
        analysis_results['src_ip'] = packet[IP].src
        analysis_results['dst_ip'] = packet[IP].dst
        analysis_results['proto'] = packet[IP].proto

        # 1. TCP Analysis (HTTP, FTP, vb.)
        if packet.haslayer(TCP):
            analysis_results['sport'] = packet[TCP].sport
            analysis_results['dport'] = packet[TCP].dport

            # HTTP Request Detection (Cleartext Traffic)
            if packet.haslayer(HTTPRequest):
                url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
                analysis_results['info'] = f"🌐 HTTP Request: {url}"
                analysis_results['method'] = packet[HTTPRequest].Method.decode()

        # 2. UDP Analysis (DNS, DHCP, vb.)
        elif packet.haslayer(UDP):
            analysis_results['sport'] = packet[UDP].sport
            analysis_results['dport'] = packet[UDP].dport

            if packet.dport == 53 or packet.sport == 53:
                analysis_results['info'] = "🔍 DNS Query/Response"

    return analysis_results