# formatter_terminal.py
# Provides colored printing helpers and simple summary printing
from colorama import Fore, Style, init
init(autoreset=True)

def print_packet_line(info):
    proto = info.get("protocol") or "RAW"
    if proto == "TCP":
        color = Fore.CYAN
    elif proto == "UDP":
        color = Fore.MAGENTA
    elif proto == "ICMP":
        color = Fore.YELLOW
    elif proto == "ARP":
        color = Fore.GREEN
    else:
        color = Fore.WHITE
    sip = info.get("src_ip") or info.get("mac_src") or "?"
    dip = info.get("dst_ip") or info.get("mac_dst") or "?"
    sp = f":{info['src_port']}" if info.get('src_port') else ""
    dp = f":{info['dst_port']}" if info.get('dst_port') else ""
    size = info.get("length",0)
    print(color + f"[{proto}] {sip}{sp} -> {dip}{dp}  ({size} bytes)" + Style.RESET_ALL)

def print_summary(stats):
    print(Style.BRIGHT + Fore.WHITE + "=== Summary ===")
    print(f"Total Packets: {stats.get('total_packets')}")
    print("Top protocols:")
    for k,v in stats.get("protocol_usage",{}).items():
        print(f"  {k}: {v}")
