import os
import sys
import argparse
from scapy.all import ARP, sniff
from scapy.data import MANUFDB

# State management for known network devices
known_devices = {}

def parse_arguments():
    parser = argparse.ArgumentParser(description="SecSentinel - Network Security & Anomaly Monitoring System")
    parser.add_argument("-i", "--interface", dest="interface", help="Network interface to listen on (e.g., eth0, wlan0)")
    return parser.parse_args()

def check_root():
    if os.geteuid() != 0:
        print("[-] Error: SecSentinel must be run with root privileges (sudo python3 sentinel.py).")
        sys.exit(1)

def get_device_vendor(mac):
    if not mac or mac == "N/A":
        return "Unknown Vendor"
    try:
        oui = ":".join(mac.split(":")[:3]).upper()
        return MANUFDB._manufdb.get(oui, "Generic / Unknown Vendor")
    except Exception:
        return "Unknown Vendor"

def packet_callback(packet):
    if packet.haslayer(ARP):
        arp_layer = packet[ARP]
        src_ip = arp_layer.psrc
        src_mac = arp_layer.hwsrc
        
        # Handle ARP probes / Address Announcement packets (0.0.0.0) gracefully
        if src_ip == "0.0.0.0":
            vendor = get_device_vendor(src_mac)
            print(f"\033[93m[*] ARP Probe / Announcement -> MAC: {src_mac} | Vendor: {vendor}\033[0m")
            return

        # Track and detect anomalies without blocking the sniffing loop
        if src_ip not in known_devices:
            known_devices[src_ip] = src_mac
            vendor = get_device_vendor(src_mac)
            print(f"\033[92m[+] New Device Discovered -> IP: {src_ip} | MAC: {src_mac} | Vendor: {vendor}\033[0m")
            
        elif known_devices[src_ip] != src_mac:
            old_mac = known_devices[src_ip]
            vendor = get_device_vendor(src_mac)
            print(f"\033[91m[!] SECURITY ALERT: ARP Conflict / Possible Spoofing Attack Detected!\033[0m")
            print(f"    IP: {src_ip} changed its MAC address from ({old_mac}) to ({src_mac}) | Vendor: {vendor}")

def main():
    check_root()
    args = parse_arguments()
    
    print("=================================================================")
    print("                    SecSentinel v0.5                             ")
    print("          Network Security & Anomaly Monitoring System           ")
    print("=================================================================")
    
    if args.interface:
        print(f"[*] Selected Interface: {args.interface}")
        sniff_args = {"filter": "arp", "prn": packet_callback, "store": 0, "iface": args.interface}
    else:
        print("[*] Listening on default network interface...")
        sniff_args = {"filter": "arp", "prn": packet_callback, "store": 0}
        
    print("[*] Listening to network traffic... (Press Ctrl+C to exit)")
    
    try:
        sniff(**sniff_args)
    except KeyboardInterrupt:
        print("\n[+] SecSentinel gracefully shut down.")
        sys.exit(0)

if __name__ == "__main__":
    main()
