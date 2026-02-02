import os
import sys
from dotenv import load_dotenv
from src.sniffer import start_sniffing

load_dotenv()

def main():
    interface = os.getenv("INTERFACE")
    if not interface:
        print("⚠️  Warning: INTERFACE not found in .env, defaulting to 'eth0'")
        interface = "eth0"

    print("--- Advanced Network Sniffer ---")

    # root check
    if os.getuid() != 0:
        print("❌ Error: You must run this script as root (sudo)!")
        sys.exit(1)

    try:
        start_sniffing(interface)
    except KeyboardInterrupt:
        print("\n👋 Sniffing stopped. Stay safe!")

if __name__ == "__main__":
    main()