# analyzer_arp.py
"""
ARP (Address Resolution Protocol) Analyzer Module

This module analyzes ARP traffic to detect potential security threats
like ARP spoofing and MAC address spoofing.

ماژول تحلیل‌گر ترافیک ARP
این ماژول ترافیک ARP را برای تشخیص تهدیدات امنیتی احتمالی
مانند جعل آدرس ARP و جعل آدرس MAC تحلیل می‌کند.
"""

import json
import os
import logging
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Set, Any, Optional, Union

# Constants
RAW_PATH = "results/raw_packets.json"  # Path to raw packet data
OUT_PATH = "results/arp_analysis.json"  # Output path for analysis results

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('arp_analyzer.log')
    ]
)
logger = logging.getLogger(__name__)

def load_raw() -> List[Dict[str, Any]]:
    """
    Load raw packet data from JSON file.
    
    Returns:
        List[Dict[str, Any]]: List of packet data or empty list if error occurs
        
    این تابع داده‌های خام بسته‌ها را از فایل JSON بارگذاری می‌کند.
    
    برمی‌گرداند:
        لیستی از دیکشنری‌های حاوی داده‌های بسته یا لیست خالی در صورت بروز خطا
    """
    try:
        if not os.path.exists(RAW_PATH):
            logger.warning(f"{RAW_PATH} not found. No ARP data to analyze.")
            return []
            
        with open(RAW_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            if not isinstance(data, list):
                logger.error(f"{RAW_PATH} does not contain a JSON array")
                return []
            return data
            
    except json.JSONDecodeError as e:
        logger.error(f"{RAW_PATH} contains invalid JSON: {str(e)}")
        return []
    except Exception as e:
        logger.error(f"Error loading {RAW_PATH}: {str(e)}", exc_info=True)
        return []

def analyze_arp() -> Dict[str, Any]:
    """
    Analyze ARP traffic and detect potential spoofing attempts.
    
    Returns:
        Dict containing analysis results including ARP statistics and detected threats
        
    ترافیک ARP را تحلیل کرده و تلاش‌های احتمالی جعل را تشخیص می‌دهد.
    
    برمی‌گرداند:
        دیکشنری حاوی نتایج تحلیل شامل آمار ARP و تهدیدات شناسایی شده
    """
    logger.info("Starting ARP analysis...")
    pkts = load_raw()
    
    if not pkts:
        logger.warning("No packet data available for analysis")
        return {
            "arp_count": 0, 
            "suspicious": [], 
            "error": "No packet data available",
            "analysis_timestamp": datetime.utcnow().isoformat() + "Z"
        }
    
    # Mapping of ARP operation codes to their human-readable names
    # نگاشت کدهای عملیات ARP به نام‌های قابل فهم
    ARP_OPERATIONS = {
        '1': 'REQUEST',      # ARP Request
        '2': 'REPLY',        # ARP Reply
        '3': 'RARP_REQUEST', # RARP Request
        '4': 'RARP_REPLY'    # RARP Reply
    }
    
    arp_entries: List[Dict[str, Any]] = []
    ip_to_macs: Dict[str, Set[str]] = defaultdict(set)
    mac_to_ips: Dict[str, Set[str]] = defaultdict(set)
    suspicious: List[Dict[str, Any]] = []
    
    # Process each packet and extract ARP information
    # پردازش هر بسته و استخراج اطلاعات ARP
    for pkt in pkts:
        try:
            if pkt.get("protocol") != "ARP":
                continue
                
            # Extract ARP packet information with fallback values
            # استخراج اطلاعات بسته ARP با مقادیر پیش‌فرض
            entry = {
                "timestamp": pkt.get("timestamp") or datetime.utcnow().isoformat() + "Z",
                "src_ip": pkt.get("src_ip") or pkt.get("psrc") or "0.0.0.0",
                "dst_ip": pkt.get("dst_ip") or pkt.get("pdst") or "0.0.0.0",
                "src_mac": (pkt.get("mac_src") or pkt.get("hwsrc") or "00:00:00:00:00:00").lower(),
                "dst_mac": (pkt.get("mac_dst") or pkt.get("hwdst") or "ff:ff:ff:ff:ff:ff").lower(),
                "op": ARP_OPERATIONS.get(str(pkt.get("op", "")).strip(), "UNKNOWN")
            }
            
            arp_entries.append(entry)
            
            # Update mappings for spoofing detection
            # به‌روزرسانی نگاشت‌ها برای تشخیص جعل
            if entry["src_ip"] != "0.0.0.0" and entry["src_mac"] != "00:00:00:00:00:00":
                ip_to_macs[entry["src_ip"]].add(entry["src_mac"])
                mac_to_ips[entry["src_mac"]].add(entry["src_ip"])
                
        except Exception as e:
            logger.error(f"Error processing ARP packet: {str(e)}", exc_info=True)
            continue
    
    # Detect potential ARP spoofing (multiple MACs for one IP)
    # تشخیص جعل ARP (چندین MAC برای یک آدرس IP)
    for ip, macs in ip_to_macs.items():
        if len(macs) > 1:
            threat = {
                "type": "ARP_SPOOFING",
                "severity": "HIGH",
                "ip": ip,
                "macs": sorted(list(macs)),
                "first_seen": datetime.utcnow().isoformat() + "Z",
                "description": f"Multiple MAC addresses ({len(macs)}) detected for IP {ip}",
                "recommendation": "Investigate for potential ARP spoofing attack. "
                                "Legitimate devices should have only one MAC per IP."
            }
            suspicious.append(threat)
            logger.warning(f"Potential ARP spoofing detected for IP {ip} with {len(macs)} MACs")
    
    # Detect potential MAC address spoofing (one MAC, multiple IPs)
    # تشخیص جعل آدرس MAC (یک MAC، چندین آدرس IP)
    for mac, ips in mac_to_ips.items():
        if len(ips) > 1:
            threat = {
                "type": "MAC_SPOOFING",
                "severity": "MEDIUM",
                "mac": mac,
                "ips": sorted(list(ips)),
                "first_seen": datetime.utcnow().isoformat() + "Z",
                "description": f"Multiple IP addresses ({len(ips)}) detected for MAC {mac}",
                "recommendation": "This could indicate MAC spoofing or a misconfigured network device. "
                                "Verify if this is expected behavior."
            }
            suspicious.append(threat)
            logger.warning(f"Potential MAC spoofing detected for MAC {mac} with {len(ips)} IPs")
    
    # Prepare analysis results
    # آماده‌سازی نتایج تحلیل
    out = {
        "analysis_timestamp": datetime.utcnow().isoformat() + "Z",
        "analysis_duration_seconds": (datetime.utcnow() - 
                                     datetime.fromisoformat(arp_entries[0]["timestamp"].replace("Z", "")) 
                                     if arp_entries else 0).total_seconds(),
        "arp_count": len(arp_entries),
        "unique_ips": len(ip_to_macs),
        "unique_macs": len(mac_to_ips),
        "suspicious_activity_count": len(suspicious),
        "suspicious_activity": suspicious,
        "arp_operations": {
            op_name: sum(1 for e in arp_entries if e["op"] == op_name)
            for op_name in ARP_OPERATIONS.values()
        },
        "metadata": {
            "analyzer_version": "1.0.0",
            "analysis_type": "arp_security_analysis"
        }
    }
    
    # Save results to JSON file
    # ذخیره نتایج در فایل JSON
    try:
        os.makedirs(os.path.dirname(OUT_PATH) or ".", exist_ok=True)
        with open(OUT_PATH, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, ensure_ascii=False, ensure_ascii=False)
            
        logger.info(f"ARP analysis completed. {len(arp_entries)} packets processed.")
        if suspicious:
            logger.warning(f"Detected {len(suspicious)} potential security threats")
        
        # Print summary to console
        print("\n" + "="*50)
        print(f"🔍 ARP Analysis Results")
        print("="*50)
        print(f"📊 Total ARP packets: {len(arp_entries)}")
        print(f"🌐 Unique IP addresses: {len(ip_to_macs)}")
        print(f"🔌 Unique MAC addresses: {len(mac_to_ips)}")
        print(f"⚠️  Potential threats detected: {len(suspicious)}")
        print(f"💾 Results saved to: {os.path.abspath(OUT_PATH)}")
        print("="*50 + "\n")
        
    except Exception as e:
        error_msg = f"Error saving ARP analysis: {str(e)}"
        logger.error(error_msg, exc_info=True)
        print(f"❌ {error_msg}")
    
    return out

def main() -> None:
    """
    Main function to run ARP analysis.
    تابع اصلی برای اجرای تحلیل ARP
    """
    try:
        results = analyze_arp()
        if results.get("suspicious_activity_count", 0) > 0:
            exit(1)  # Exit with error code if threats detected
    except KeyboardInterrupt:
        logger.info("ARP analysis interrupted by user")
        print("\nAnalysis interrupted by user.")
        exit(130)  # Standard exit code for Ctrl+C
    except Exception as e:
        logger.critical(f"Critical error in ARP analysis: {str(e)}", exc_info=True)
        print(f"\n❌ Critical error: {str(e)}")
        exit(1)

if __name__ == "__main__":
    main()
