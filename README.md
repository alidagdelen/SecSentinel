# SecSentinel

Small tool that watches ARP traffic on your local network and flags
possible spoofing / MITM attempts (someone's MAC address suddenly
claiming an IP that already belongs to another device).

Started this as a school project, still adding stuff here and there.

## What it does
- Listens to ARP packets on an interface
- Logs new devices it sees, with vendor lookup from the MAC
- Flags MAC/IP conflicts (classic ARP spoofing pattern)
- Optional whitelist for devices you want to pin down (router, NAS, etc.)
- Keeps a device list between runs (`known_devices.json`)
- Writes everything to a log file (`sentinel_log.jsonl`)
- Desktop notification on alerts, if `plyer` is installed

## Setup
```bash
pip install -r requirements.txt
```

## Run
```bash
sudo python3 sentinel.py -i wlan0
```

Needs root since it's sniffing raw packets.

If you don't pass `-i`, it'll try the default interface.

### Whitelist (optional)
Copy the example and fill in devices you trust:
```bash
cp whitelist.example.json whitelist.json
```
If an IP in the whitelist shows up with a different MAC than expected,
you get a high-priority alert instead of the normal one.

### Flags
- `-i, --interface` — which interface to listen on
- `--no-persist` — don't save/load known_devices.json
- `--no-notify` — turn off desktop notifications
- `--whitelist PATH` — use a different whitelist file

## Notes
- `known_devices.json` and `sentinel_log.jsonl` contain your actual network
  data, probably don't commit those (already in `.gitignore`).

## TODO
- web dashboard maybe
- email/telegram alerts
- auto-fix ARP table on detection
- other attack types (DHCP starvation, DNS spoofing)
- also educal bro
