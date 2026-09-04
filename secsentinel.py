#!/usr/bin/env python3
"""
SecSentinel v0.9
Simple ARP spoofing / MITM detector for local networks.
"""

import os
import sys
import json
import argparse
import datetime

try:
    from scapy.all import ARP, sniff
    from scapy.data import MANUFDB
except ImportError:
    print("[-] scapy not installed. Run: pip install scapy")
    sys.exit(1)

try:
    from plyer import notification
    HAVE_NOTIFY = True
except ImportError:
    HAVE_NOTIFY = False

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEVICES_FILE = os.path.join(BASE_DIR, "known_devices.json")
WHITELIST_FILE = os.path.join(BASE_DIR, "whitelist.json")
LOG_FILE = os.path.join(BASE_DIR, "sentinel_log.jsonl")

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

known_devices = {}   # ip -> mac
whitelist = {}       # ip -> mac, trusted/pinned devices

stats = {
    "new_devices": 0,
    "alerts": 0,
    "probes": 0,
    "started": None,
}


def load_json(path):
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        print(f"[-] couldn't read {path}, starting empty")
        return {}


def save_devices():
    try:
        with open(DEVICES_FILE, "w") as f:
            json.dump(known_devices, f, indent=2)
    except IOError as e:
        print(f"[-] failed to save device db: {e}")


def log_event(data):
    data["ts"] = datetime.datetime.now().isoformat(timespec="seconds")
    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(data) + "\n")
    except IOError as e:
        print(f"[-] log write failed: {e}")


def notify(title, msg):
    if not HAVE_NOTIFY:
        return
    try:
        notification.notify(title=title, message=msg, timeout=6)
    except Exception:
        # notifications aren't critical, just skip on failure
        pass


def get_args():
    p = argparse.ArgumentParser(description="SecSentinel - ARP spoofing / anomaly monitor")
    p.add_argument("-i", "--interface", help="network interface to listen on (eth0, wlan0, ...)")
    p.add_argument("--no-persist", action="store_true", help="don't load/save known_devices.json")
    p.add_argument("--no-notify", action="store_true", help="disable desktop notifications")
    p.add_argument("--whitelist", default=WHITELIST_FILE, help="path to whitelist json")
    return p.parse_args()


def check_root():
    if os.geteuid() != 0:
        print("[-] needs root privileges, run with sudo")
        sys.exit(1)


def vendor_lookup(mac):
    if not mac or mac == "N/A":
        return "Unknown Vendor"
    try:
        return MANUFDB.lookup(mac) or "Generic / Unknown Vendor"
    except Exception:
        return "Unknown Vendor"


def handle_packet(pkt, notify_enabled=True):
    if not pkt.haslayer(ARP):
        return

    arp = pkt[ARP]
    ip = arp.psrc
    mac = arp.hwsrc

    # gratuitous ARP / probe packets, not an actual host announcing traffic
    if ip == "0.0.0.0":
        stats["probes"] += 1
        vendor = vendor_lookup(mac)
        print(f"{YELLOW}[*] ARP probe -> MAC: {mac} | Vendor: {vendor}{RESET}")
        return

    # pinned device changed MAC -> treat as highest priority
    if ip in whitelist and whitelist[ip] != mac:
        vendor = vendor_lookup(mac)
        stats["alerts"] += 1
        msg = f"Whitelisted IP {ip} expected {whitelist[ip]} but saw {mac} ({vendor})"
        print(f"{RED}{BOLD}[!!!] WHITELIST VIOLATION: {msg}{RESET}")
        log_event({"event": "whitelist_violation", "ip": ip,
                   "expected_mac": whitelist[ip], "seen_mac": mac, "vendor": vendor})
        if notify_enabled:
            notify("SecSentinel - critical alert", msg)
        known_devices[ip] = mac
        return

    if ip not in known_devices:
        known_devices[ip] = mac
        vendor = vendor_lookup(mac)
        stats["new_devices"] += 1
        print(f"{GREEN}[+] New device -> IP: {ip} | MAC: {mac} | Vendor: {vendor}{RESET}")
        log_event({"event": "new_device", "ip": ip, "mac": mac, "vendor": vendor})

    elif known_devices[ip] != mac:
        old_mac = known_devices[ip]
        vendor = vendor_lookup(mac)
        stats["alerts"] += 1
        print(f"{RED}[!] ALERT: possible ARP spoofing detected{RESET}")
        print(f"    {ip} changed MAC from {old_mac} to {mac} | Vendor: {vendor}")
        log_event({"event": "arp_conflict", "ip": ip, "old_mac": old_mac,
                   "new_mac": mac, "vendor": vendor})
        if notify_enabled:
            notify("SecSentinel - alert", f"{ip} MAC changed: {old_mac} -> {mac}")
        known_devices[ip] = mac


def banner():
    print("=" * 65)
    print(f"{CYAN}{BOLD}  SecSentinel v0.9{RESET}")
    print("  ARP spoofing / anomaly monitor")
    print("=" * 65)


def summary():
    dur = datetime.datetime.now() - stats["started"] if stats["started"] else None
    print("\n" + "-" * 65)
    print(f"{CYAN}{BOLD}Session summary{RESET}")
    if dur:
        print(f"  runtime          : {str(dur).split('.')[0]}")
    print(f"  new devices      : {stats['new_devices']}")
    print(f"  arp probes       : {stats['probes']}")
    print(f"  alerts           : {stats['alerts']}")
    print(f"  known devices    : {len(known_devices)}")
    print(f"  log file         : {LOG_FILE}")
    print("-" * 65)


def main():
    global known_devices, whitelist

    check_root()
    args = get_args()
    banner()

    if not args.no_persist:
        known_devices = load_json(DEVICES_FILE)
        if known_devices:
            print(f"[*] loaded {len(known_devices)} known devices from previous run")

    whitelist = load_json(args.whitelist)
    if whitelist:
        print(f"[*] loaded {len(whitelist)} whitelisted devices")
    else:
        print(f"[*] no whitelist found at {args.whitelist} (optional, see whitelist.example.json)")

    notify_enabled = not args.no_notify and HAVE_NOTIFY
    if not HAVE_NOTIFY and not args.no_notify:
        print("[*] plyer not installed, notifications disabled (pip install plyer to enable)")
    elif notify_enabled:
        print("[*] desktop notifications on")

    stats["started"] = datetime.datetime.now()

    if args.interface:
        print(f"[*] interface: {args.interface}")
        sniff_kwargs = {"filter": "arp", "iface": args.interface}
    else:
        print("[*] no interface given, using default")
        sniff_kwargs = {"filter": "arp"}

    sniff_kwargs["prn"] = lambda pkt: handle_packet(pkt, notify_enabled)
    sniff_kwargs["store"] = 0

    print("[*] listening for ARP traffic, Ctrl+C to stop")
    print("-" * 65)

    try:
        sniff(**sniff_kwargs)
    except KeyboardInterrupt:
        pass
    except OSError as e:
        print(f"\n[-] interface error: {e}")
        sys.exit(1)
    finally:
        if not args.no_persist:
            save_devices()
            print(f"\n[+] saved device db -> {DEVICES_FILE}")
        summary()
        sys.exit(0)


if __name__ == "__main__":
    main()
