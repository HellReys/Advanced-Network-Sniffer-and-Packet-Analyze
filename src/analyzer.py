import re
import json
import os


class TrafficAnalyzer:
    def __init__(self):
        self.sensitive_keywords = ["user", "pass", "pwd", "login", "password"]
        self.noise_keywords = ["ssdp:discover", "m-search"]
        self.blacklist = self.load_blacklist()

    def load_blacklist(self):
        """Loads malicious IP addresses from a JSON file."""
        try:
            if os.path.exists("blacklist.json"):
                with open("blacklist.json", "r") as f:
                    return json.load(f).get("malicious_ips", [])
            return []
        except Exception as e:
            print(f"⚠️  Could not load blacklist: {e}")
            return []

    def detect_malicious_ips(self, src_ip, dst_ip):
        """Checks if any IP in the packet is in the blacklist."""
        if src_ip in self.blacklist:
            return f"⚠️ [THREAT] Outbound traffic to Malicious IP: {src_ip}"
        if dst_ip in self.blacklist:
            return f"🚨 [CRITICAL] Connection to Known Malicious IP: {dst_ip}"
        return None


    def detect_credentials(self, packet):
        """
        Scans the raw payload of a packet for potential credentials.
        """
        if packet.haslayer("Raw"):
            try:
                payload = packet["Raw"].load.decode('utf-8', errors='ignore').lower()

                if any(noise in payload for noise in self.noise_keywords):
                    return None

                for keyword in self.sensitive_keywords:
                    if keyword in payload:
                        return f"🔑 [POSSIBLE CREDENTIALS]: {payload[:80].strip()}..."
            except:
                pass
        return None

    def analyze_behavior(self, data):
        """
        Logic for detecting suspicious network behaviors (e.g., port scanning).
        (Later we can add more complex logic here)
        """
        pass