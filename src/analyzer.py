import re


class TrafficAnalyzer:
    def __init__(self):
        self.sensitive_keywords = ["user", "pass", "pwd", "login", "password"]

        self.noise_keywords = ["ssdp:discover", "m-search"]

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