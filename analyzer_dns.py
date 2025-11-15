# analyzer_dns.py
# DNS analysis: detect queries and responses from UDP payloads
import json
import os
from collections import Counter

RAW_PATH = "results/raw_packets.json"
OUT_PATH = "results/dns_analysis.json"

def load_raw():
    if not os.path.exists(RAW_PATH):
        return []
    with open(RAW_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def parse_dns_from_hex(hexstr):
    # minimal parser: look for ASCII domain-like parts in payload bytes
    try:
        b = bytes.fromhex(hexstr)
    except:
        return None
    # naive: find sequences of printable characters separated by dots
    hints = []
    chunk = []
    for byte in b:
        if 32 <= byte <= 126:  # printable
            chunk.append(chr(byte))
        else:
            if len(chunk) >= 3 and '.' in ''.join(chunk):
                hints.append(''.join(chunk))
            chunk = []
    if len(chunk) >= 3 and '.' in ''.join(chunk):
        hints.append(''.join(chunk))
    return hints or None

def analyze_dns():
    pkts = load_raw()
    dns_queries = []
    dns_responses = []
    for p in pkts:
        if p.get("protocol") == "UDP" and p.get("dst_port") == 53 or p.get("src_port") == 53:
            raw = p.get("raw_payload")
            if raw:
                hints = parse_dns_from_hex(raw)
                if hints:
                    record = {
                        "timestamp": p.get("timestamp"),
                        "src": f"{p.get('src_ip')}:{p.get('src_port')}" if p.get('src_port') else p.get('src_ip'),
                        "dst": f"{p.get('dst_ip')}:{p.get('dst_port')}" if p.get('dst_port') else p.get('dst_ip'),
                        "hints": hints
                    }
                    if p.get("dst_port") == 53:
                        dns_queries.append(record)
                    else:
                        dns_responses.append(record)
    out = {
        "queries": dns_queries,
        "responses": dns_responses,
        "query_count": len(dns_queries),
        "response_count": len(dns_responses)
    }
    os.makedirs("results", exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print(f"📁 DNS analysis saved: {OUT_PATH}")
    return out

if __name__ == "__main__":
    analyze_dns()
