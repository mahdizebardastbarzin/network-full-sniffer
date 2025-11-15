# analyzer_arp.py
import json, os
from collections import Counter
RAW_PATH = "results/raw_packets.json"
OUT_PATH = "results/arp_analysis.json"

def load_raw():
    if not os.path.exists(RAW_PATH):
        return []
    with open(RAW_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def analyze_arp():
    pkts = load_raw()
    arp_pairs = []
    for p in pkts:
        if p.get("protocol") == "ARP":
            arp_pairs.append({"timestamp": p.get("timestamp"),
                              "src_ip": p.get("src_ip"),
                              "dst_ip": p.get("dst_ip"),
                              "mac_src": p.get("mac_src"),
                              "mac_dst": p.get("mac_dst")})
    # detect MAC changes for same IP (possible spoofing)
    ip_to_macs = {}
    suspicious = []
    for a in arp_pairs:
        ip = a.get("src_ip")
        mac = a.get("mac_src")
        if ip:
            if ip not in ip_to_macs:
                ip_to_macs[ip] = set()
            if mac:
                ip_to_macs[ip].add(mac)
                if len(ip_to_macs[ip])>1:
                    suspicious.append({"ip": ip, "macs": list(ip_to_macs[ip])})
    out = {"arp_count": len(arp_pairs), "suspicious": suspicious}
    os.makedirs("results", exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print(f"📁 ARP analysis saved: {OUT_PATH}")
    return out

if __name__ == "__main__":
    analyze_arp()
