# stats_engine.py
import json, os, time
from collections import Counter, defaultdict

RAW_PATH = "results/raw_packets.json"
OUT_PATH = "results/stats.json"

def load_raw():
    if not os.path.exists(RAW_PATH):
        return []
    with open(RAW_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def compute_stats():
    pkts = load_raw()
    proto = Counter()
    src = Counter()
    dst = Counter()
    ports = Counter()
    total_bytes = 0
    for p in pkts:
        proto[p.get("protocol") or "RAW"] += 1
        if p.get("src_ip"):
            src[p.get("src_ip")] += 1
        if p.get("dst_ip"):
            dst[p.get("dst_ip")] += 1
        if p.get("src_port"):
            ports[p.get("src_port")] += 1
        if p.get("dst_port"):
            ports[p.get("dst_port")] += 1
        total_bytes += p.get("length",0)
    out = {
        "total_packets": len(pkts),
        "total_bytes": total_bytes,
        "protocol_usage": dict(proto.most_common()),
        "top_src_ips": src.most_common(10),
        "top_dst_ips": dst.most_common(10),
        "top_ports": ports.most_common(20)
    }
    os.makedirs("results", exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print(f"📁 Stats saved: {OUT_PATH}")
    return out

if __name__ == "__main__":
    compute_stats()
