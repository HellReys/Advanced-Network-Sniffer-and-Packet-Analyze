# Advanced Network Sniffer & Threat Analyzer

**NetSpy** is a powerful, Python-based network analysis tool designed for real-time packet inspection, credential hunting, and threat intelligence matching. It monitors network interfaces at a low level, parses protocols, and alerts on suspicious activities.



## Core Features

* **Deep Packet Inspection (DPI):** Analyzes layers (IP, TCP, UDP, DNS, HTTP) in real-time.
* **Credential Sniffing:** Automatically detects potential usernames and passwords in unencrypted (HTTP/FTP) traffic.
* **DNS Monitoring:** Tracks domain name queries to monitor web activity.
* **Threat Intelligence:** Matches incoming/outgoing traffic against a custom `blacklist.json` of malicious IPs.
* **Automated PCAP Logging:** Saves all captured traffic into professional `.pcap` files for further analysis in Wireshark.
* **Live Statistics:** Provides periodic summaries of processed packets and high-priority alerts.

## Project Structure

* **`src/sniffer.py`**: The core engine that captures and logs packets.
* **`src/parser.py`**: Deconstructs raw packets into readable data (IPs, Ports, Protocols).
* **`src/analyzer.py`**: The intelligence layer that hunts for credentials and blacklisted IPs.
* **`main.py`**: The entry point with root-privilege checks and environment configuration.

## Installation & Usage

### 1. Requirements
* Python 3.x
* Root/Sudo privileges (for raw socket access)
* `scapy` & `scapy-http` libraries

### 2. Setup
```bash
# Clone the project
git clone https://github.com/HellReys/Advanced-Network-Sniffer-and-Packet-Analyze
cd Advanced-Network-Sniffer-and-Packet-Analyze

# Install dependencies
pip install -r requirements.txt
```

### 3. Configuration
* Create a **`.env`** file:
```bash
INTERFACE=eth0  # Change to your network card (wlan0, etc.)

DEBUG_MODE=0    # 0 = Sniff everything, 1 = Only show specific alerts

PCAP_LOG_DIR=logs/ # Log Path
```

### 4. Run
```bash
sudo python3 main.py
```

### Sample Output
```bash
📡 [192.168.1.10] -> [104.18.27.120] | 🌐 HTTP Request: [example.com/login](https://example.com/login)
🚨 🔑 [POSSIBLE CREDENTIALS]: user=admin&pass=secret123...
🚨 [CRITICAL] Connection to Known Malicious IP: 185.112.24.5
```

## ⚠️ Disclaimer
This tool is for **educational and ethical security testing only**. Unauthorized sniffing of networks you do not own is illegal and unethical. Use responsibly.
