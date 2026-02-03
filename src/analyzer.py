import re


class TrafficAnalyzer:
    def __init__(self):
        self.keywords = ["user", "pass", "login", "password", "username", "token", "session"]

    def detect_credentials(self, packet):
        """
        Scans the raw payload of a packet for potential credentials.
        """
        if packet.haslayer("Raw"):
            payload = str(packet["Raw"].load).lower()

            for keyword in self.keywords:
                if keyword in payload:
                    return f"🔑 [POSSIBLE CREDENTIALS FOUND]: {payload[:100]}..."
        return None

    def analyze_behavior(self, data):
        """
        Logic for detecting suspicious network behaviors (e.g., port scanning).
        (Later we can add more complex logic here)
        """
        pass