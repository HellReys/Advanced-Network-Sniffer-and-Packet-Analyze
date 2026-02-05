import os
import sys
from dotenv import load_dotenv
from src.sniffer import start_sniffing

load_dotenv()

def main():
    # 1. Interface Configuration
    interface = os.getenv("INTERFACE")
    if not interface:
        print("⚠️  Warning: INTERFACE not found in .env, defaulting to 'eth0'")
        interface = "eth0"

    print("\n" + "*" * 45)
    print("      🕵️  ADVANCED NETWORK SNIFFER      ")
    print("*" * 45 + "\n")

    # 2. Privilege Check (Root is required for Raw Sockets)
    if os.getuid() != 0:
        print("❌ ERROR: Root privileges required!")
        print("💡 Please run with: sudo python3 main.py")
        sys.exit(1)

    # 3. Execution Phase
    try:
        start_sniffing(interface)
    except KeyboardInterrupt:
        print("\n" + "-" * 45)
        print("👋 Session Terminated. PCAP logs saved in 'logs/'")
        print("-" * 45)
    except Exception as e:
        print(f"\n❌ CRITICAL ERROR: {e}")

if __name__ == "__main__":
    main()