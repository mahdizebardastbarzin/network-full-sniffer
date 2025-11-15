# analyzer_security.py
import json, os
from collections import Counter, defaultdict
RAW_PATH = "results/raw_packets.json"
OUT_PATH = "results/security_analysis.json"

def load_raw():
    if not os.path.exists(RAW_PATH):
        return []
    with open(RAW_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def detect_syn_flood(pkts):
    # count SYNs per src IP to many dst ports
    syn_map = defaultdict(list)
    # NOTE: raw_payload hex may not show TCP flags; we detect by presence of TCP and no payload heuristic
    for p in pkts:
        if p.get("protocol")=="TCP":
            # heuristic: many packets with small length to many dst ports -> possible scan/flood
            src = p.get("src_ip")
            dst_port = p.get("dst_port")
            if src and dst_port:
                syn_map[src].append(dst_port)
    suspects = []
    for src, ports in syn_map.items():
        unique_ports = len(set(ports))
        total = len(ports)
        if unique_ports > 50 and total > 100:
            suspects.append({"src":src,"unique_ports":unique_ports,"total_packets":total})
    return suspects

def detect_port_scan(pkts):
    # detect hosts connecting to many ports on single dst
    dst_map = defaultdict(list)
    for p in pkts:
        if p.get("protocol")=="TCP":
            dst = p.get("dst_ip")
            src_port = p.get("src_port")
            if dst and src_port is not None:
                dst_map[dst].append(src_port)
    scans = []
    for dst, ports in dst_map.items():
        if len(set(ports))>100:
            scans.append({"dst":dst,"ports_seen":len(set(ports))})
    return scans

def run_security_checks():
    pkts = load_raw()
    syn = detect_syn_flood(pkts)
    scans = detect_port_scan(pkts)
    out = {"syn_flood_candidates": syn, "port_scan_candidates": scans}
    os.makedirs("results", exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print(f"📁 Security analysis saved: {OUT_PATH}")
    return out

if __name__ == "__main__":
    run_security_checks()
