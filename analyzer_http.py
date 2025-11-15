# analyzer_http.py
# HTTP analysis: extract simple HTTP requests/responses from TCP raw payloads
import json
import os
from collections import defaultdict

RAW_PATH = "results/raw_packets.json"
OUT_PATH = "results/http_analysis.json"

def load_raw():
    if not os.path.exists(RAW_PATH):
        return []
    with open(RAW_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def try_parse_http_from_hex(hexstr):
    try:
        b = bytes.fromhex(hexstr)
    except:
        return None
    try:
        txt = b.decode('utf-8', errors='ignore')
    except:
        return None
    # naive detection of HTTP request lines
    lines = txt.splitlines()
    if not lines:
        return None
    first = lines[0].strip()
    if first.startswith(("GET ","POST ","HEAD ","PUT ","DELETE ","OPTIONS ")):
        # parse headers
        headers = {}
        path = first.split(' ',2)[1] if len(first.split())>1 else ""
        for ln in lines[1:]:
            if ':' in ln:
                k,v = ln.split(':',1)
                headers[k.strip()] = v.strip()
        return {"type":"request","line":first,"path":path,"headers":headers,"raw":txt[:2000]}
    # maybe a response
    if first.startswith("HTTP/"):
        # parse status
        status = first
        return {"type":"response","status":status,"raw":txt[:2000]}
    return None

def analyze_http():
    pkts = load_raw()
    http_events = []
    for p in pkts:
        if p.get("protocol") == "TCP":
            raw = p.get("raw_payload")
            if raw:
                parsed = try_parse_http_from_hex(raw)
                if parsed:
                    ev = {
                        "timestamp": p.get("timestamp"),
                        "src": f"{p.get('src_ip')}:{p.get('src_port')}" if p.get('src_port') else p.get('src_ip'),
                        "dst": f"{p.get('dst_ip')}:{p.get('dst_port')}" if p.get('dst_port') else p.get('dst_ip'),
                        "parsed": parsed
                    }
                    http_events.append(ev)
    out = {"http_events": http_events, "count": len(http_events)}
    os.makedirs("results", exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print(f"📁 HTTP analysis saved: {OUT_PATH}")
    return out

if __name__ == "__main__":
    analyze_http()
