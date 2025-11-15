# sniffer.py
# Advanced FULL Sniffer — Capture engine
# By Mahdi Zebardast Barzin
#
# 🇬🇧 Captures live packets using Scapy, extracts base metadata,
# saves raw packet metadata to results/raw_packets.json for analyzers.
# 🇮🇷 این فایل پکت‌ها را بصورت زنده شنود می‌کند، متادیتای پایه را استخراج کرده
# و در results/raw_packets.json ذخیره می‌کند تا ماژول‌های تحلیلگر از آن استفاده کنند.

from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw, conf
from datetime import datetime
import json
import os
import signal
import sys

RAW_PATH = "results/raw_packets.json"
CAPTURE_LIMIT = 0  # 0 = unlimited; can be overridden by CLI args

captured = []

def ensure_results():
    os.makedirs("results", exist_ok=True)

def extract_basic(packet):
    """
    🇬🇧 Extract basic metadata from Scapy packet.
    🇮🇷 متادیتای پایه را از پکت اسکاپی استخراج می‌کند.
    """
    info = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "protocol": None,
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "length": len(packet),
        "raw_payload": None,
        "mac_src": None,
        "mac_dst": None
    }

    try:
        if packet.haslayer(ARP):
            info["protocol"] = "ARP"
            info["mac_src"] = packet.src
            info["mac_dst"] = packet.dst
            if packet.psrc:
                info["src_ip"] = packet.psrc
            if packet.pdst:
                info["dst_ip"] = packet.pdst

        elif packet.haslayer(IP):
            ip = packet[IP]
            info["src_ip"] = ip.src
            info["dst_ip"] = ip.dst

            if packet.haslayer(TCP):
                info["protocol"] = "TCP"
                info["src_port"] = int(packet[TCP].sport)
                info["dst_port"] = int(packet[TCP].dport)

            elif packet.haslayer(UDP):
                info["protocol"] = "UDP"
                info["src_port"] = int(packet[UDP].sport)
                info["dst_port"] = int(packet[UDP].dport)

            elif packet.haslayer(ICMP):
                info["protocol"] = "ICMP"

        # raw payload (as hex or text) if present
        if packet.haslayer(Raw):
            try:
                raw = bytes(packet[Raw].load)
                # keep base64-safe or hex small preview to avoid huge json
                info["raw_payload"] = raw[:512].hex()
            except Exception:
                info["raw_payload"] = None

        # MAC addresses if present (requires L2)
        try:
            if hasattr(packet, 'hwsrc'):
                info["mac_src"] = packet.hwsrc
            if hasattr(packet, 'hwdst'):
                info["mac_dst"] = packet.hwdst
        except Exception:
            pass

    except Exception as ex:
        # never crash sniffer on bad packet
        info["error"] = str(ex)

    return info

def handler(pkt):
    info = extract_basic(pkt)
    captured.append(info)

    # live terminal line (concise)
    proto = info.get("protocol") or "RAW"
    sip = info.get("src_ip") or info.get("mac_src") or "?"
    dip = info.get("dst_ip") or info.get("mac_dst") or "?"
    sport = f":{info['src_port']}" if info.get("src_port") else ""
    dport = f":{info['dst_port']}" if info.get("dst_port") else ""
    print(f"[{proto}] {sip}{sport} -> {dip}{dport}  ({info['length']} bytes)")

    # write to disk periodically for safety (append)
    if len(captured) % 50 == 0:
        persist_partial()

def persist_partial():
    ensure_results()
    try:
        # append-new approach: load existing then extend
        existing = []
        if os.path.exists(RAW_PATH):
            with open(RAW_PATH, "r", encoding="utf-8") as f:
                try:
                    existing = json.load(f)
                except:
                    existing = []
        existing.extend(captured)
        with open(RAW_PATH, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2, ensure_ascii=False)
        # clear in-memory buffer (we keep all in memory too)
        # but keep captured list for final write as well
    except Exception as e:
        print("! persist error:", e)

def save_all():
    ensure_results()
    try:
        if os.path.exists(RAW_PATH):
            with open(RAW_PATH, "r", encoding="utf-8") as f:
                try:
                    existing = json.load(f)
                except:
                    existing = []
        else:
            existing = []
        existing.extend(captured)
        with open(RAW_PATH, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2, ensure_ascii=False)
        print(f"📁 Saved raw packets: {RAW_PATH}")
    except Exception as e:
        print("! save_all error:", e)

def stop_and_exit(signum, frame):
    print("\n🛑 Stop signal received. Saving and exiting...")
    save_all()
    sys.exit(0)

def main(interface=None, count=0):
    """
    :param interface: interface name or None
    :param count:  number of packets to capture (0 = infinite)
    """
    # fallback to layer3 on systems without libpcap
    if not conf.use_pcap:
        # try to force layer3 if pcaps not available
        try:
            from scapy.all import L3RawSocket
            conf.L2socket = conf.L3socket
            conf.use_pcap = False
        except:
            pass

    signal.signal(signal.SIGINT, stop_and_exit)
    signal.signal(signal.SIGTERM, stop_and_exit)

    print("🔍 Starting live capture... (CTRL+C to stop)")
    sniff(iface=interface, prn=handler, store=False, count=count)
    # after sniff returns
    save_all()

if __name__ == "__main__":
    # simple CLI: optional: python sniffer.py [interface] [count]
    iface = None
    cnt = 0
    if len(sys.argv) >= 2:
        iface = sys.argv[1]
    if len(sys.argv) >= 3:
        try:
            cnt = int(sys.argv[2])
        except:
            cnt = 0
    main(interface=iface, count=cnt)
