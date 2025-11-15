# analyzer_tls.py
# TLS analyzer: attempt to parse ClientHello for SNI (without decrypt)
import json, os
RAW_PATH = "results/raw_packets.json"
OUT_PATH = "results/tls_analysis.json"

def load_raw():
    if not os.path.exists(RAW_PATH):
        return []
    with open(RAW_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def extract_sni_from_bytes(b):
    """
    naive TLS ClientHello SNI parser: search for 0x00 0x00 <len> pattern and sni bytes
    This is heuristic — works for many ClientHello payloads.
    """
    try:
        i = 0
        # search for handshake type 0x16 (TLS handshake) and ClientHello 0x01
        while i < len(b)-5:
            if b[i] == 0x16:
                # TLS record, handshake
                # look for 0x01 later
                # skip record header 5 bytes
                rec_len = (b[i+3] << 8) + b[i+4]
                # search in record
                rec = b[i+5:i+5+rec_len]
                # handshake type ClientHello is 0x01 at start of handshake
                if rec and rec[0] == 0x01:
                    # search for extensions and SNI (type 0x00 0x00)
                    # find 0x00 0x00 in rec
                    j = 0
                    while j < len(rec)-1:
                        if rec[j] == 0x00 and rec[j+1] == 0x00:
                            # next two bytes length
                            if j+4 < len(rec):
                                sl = (rec[j+2]<<8)+rec[j+3]
                                # extract after that — might contain hostname
                                candidate = rec[j+4:j+4+sl]
                                # find printable substring
                                s = ''.join([chr(x) for x in candidate if 32<=x<=126])
                                if '.' in s:
                                    return s.strip()
                        j += 1
            i += 1
    except Exception:
        return None
    return None

def analyze_tls():
    pkts = load_raw()
    snis = []
    for p in pkts:
        if p.get("protocol") == "TCP":
            raw = p.get("raw_payload")
            if raw:
                try:
                    b = bytes.fromhex(raw)
                    sni = extract_sni_from_bytes(b)
                    if sni:
                        snis.append({"timestamp": p.get("timestamp"),
                                     "src": p.get("src_ip"),
                                     "dst": p.get("dst_ip"),
                                     "sni": sni})
                except:
                    pass
    os.makedirs("results", exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump({"snis":snis, "count":len(snis)}, f, indent=2, ensure_ascii=False)
    print(f"📁 TLS analysis saved: {OUT_PATH}")
    return {"snis":snis, "count":len(snis)}

if __name__ == "__main__":
    analyze_tls()
