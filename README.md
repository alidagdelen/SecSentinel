SecSentinel 🛡️

    ⚠️ WARNING / DISCLAIMER: This project is currently in an early demo / development stage. It is designed strictly for educational, testing, and defensive monitoring purposes in controlled laboratory environments. Do not run this software on networks or systems without explicit, prior authorization. The author assumes no liability for any misuse or damage caused by this program.

SecSentinel is a lightweight, Python-based network security and anomaly monitoring system designed to detect new device arrivals and alert users against potential ARP spoofing / cache poisoning attacks in real time.
Features

    Real-Time Device Discovery: Automatically detects and logs new devices joining the network by capturing ARP traffic.

    Vendor Identification: Resolves MAC addresses to hardware vendors using Scapy's built-in OUI database (MANUFDB).

    ARP Spoofing Detection: Identifies potential Man-in-the-Middle (MitM) or ARP poisoning attempts by tracking IP-to-MAC consistency.

    Root Privilege Enforcement: Ensures the script runs with necessary packet-sniffing permissions.

    Clean CLI Interface: Features color-coded terminal alerts for immediate threat visibility.

Current Status (v0.4 Demo)

This is a proof-of-concept prototype. Upcoming features and improvements planned for future releases include:

    Persistent storage for known devices (SQLite / JSON logging).

    Whitelisting mechanism for trusted network cards/devices.

    Telegram or desktop notification integrations.

Prerequisites

    Python 3.x

    Scapy library

    Linux-based operating system (requires root privileges for raw socket sniffing)

Installation

    Clone the repository:
    Bash

    git clone https://github.com/yourusername/SecSentinel.git
    cd SecSentinel

    Install dependencies:
    Bash

    pip install scapy

Usage

Run the script with sudo privileges to allow packet capture on your network interfaces:
Bash

sudo python3 sentinel.py

Options

    Specify a custom network interface:
    Bash

    sudo python3 sentinel.py -i eth0

Example Output
Plaintext

=================================================================
                    SecSentinel v0.4                             
          Network Security & Anomaly Monitoring System           
=================================================================
[*] Listening on default network interface...
[*] Listening to network traffic... (Press Ctrl+C to exit)
[+] New Device Discovered -> IP: 192.168.1.1 | MAC: 00:11:22:33:44:55 | Vendor: Example Corp
[!] SECURITY ALERT: ARP Conflict / Possible Spoofing Attack Detected!
    IP: 192.168.1.50 changed its MAC address from (AA:BB:CC:DD:EE:FF) to (11:22:33:44:55:66)

Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
License

MIT
