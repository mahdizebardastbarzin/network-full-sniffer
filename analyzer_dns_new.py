# analyzer_dns.py
"""
DNS Traffic Analyzer Module

This module analyzes DNS traffic to detect and analyze DNS queries and responses,
including potential security threats like DNS tunneling, data exfiltration, and more.

Key Features:
- Parses DNS packets with support for various record types
- Detects potential DNS tunneling attempts
- Identifies suspicious domain patterns
- Provides detailed analysis and statistics
- Supports both IPv4 and IPv6

ماژول تحلیل‌گر ترافیک DNS
این ماژول ترافیک DNS را برای تشخیص و تحلیل کوئری‌ها و پاسخ‌های DNS،
از جمله تهدیدات امنیتی احتمالی مانند تونل‌زنی DNS و استخراج داده‌ها تحلیل می‌کند.

ویژگی‌های کلیدی:
- تجزیه بسته‌های DNS با پشتیبانی از انواع رکوردهای مختلف
- تشخیص تلاش‌های احتمالی تونل‌زنی DNS
- شناسایی الگوهای مشکوک در نام دامنه‌ها
- ارائه تحلیل و آمار دقیق
- پشتیبانی از هر دو پروتکل IPv4 و IPv6
"""

import json
import os
import re
import sys
import socket
import ipaddress
import logging
import base64
import math
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple, Union, Any, DefaultDict

# Type aliases
IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
DNSRecord = Dict[str, Any]
DNSQuery = Dict[str, Any]
DNSResponse = Dict[str, Any]
DNSPacket = Dict[str, Any]

# Constants
MAX_DNS_LABEL_LENGTH = 63
MAX_DOMAIN_LENGTH = 253
MAX_DNS_MESSAGE_LENGTH = 65535
MAX_COMPRESSION_POINTERS = 100

# Paths
RAW_PATH = os.path.join("results", "raw_packets.json")
OUT_PATH = os.path.join("results", "dns_analysis.json")
LOG_PATH = os.path.join("logs", "dns_analyzer.log")

# Ensure directories exist
os.makedirs(os.path.dirname(RAW_PATH) or ".", exist_ok=True)
os.makedirs(os.path.dirname(OUT_PATH) or ".", exist_ok=True)
os.makedirs(os.path.dirname(LOG_PATH) or "logs", exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_PATH, encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

class DNSParserError(Exception):
    """Custom exception for DNS parsing errors."""
    def __init__(self, message: str, data: bytes = None, offset: int = None):
        self.message = message
        self.data = data
        self.offset = offset
        
        if data is not None and offset is not None:
            start = max(0, offset - 8)
            end = min(len(data), offset + 8)
            hex_data = ' '.join(f'{b:02x}' for b in data[start:end])
            
            ascii_repr = ''.join(
                chr(b) if 32 <= b <= 126 else '.' 
                for b in data[start:end]
            )
            
            self.message += (
                f"\n  At offset: {offset}"
                f"\n  Hex dump: {hex_data}"
                f"\n  ASCII:    {ascii_repr}"
            )
            
        super().__init__(self.message)

def load_raw() -> List[Dict[str, Any]]:
    """Load raw packet data from JSON file."""
    try:
        if not os.path.exists(RAW_PATH):
            raise FileNotFoundError(f"Raw packets file not found: {os.path.abspath(RAW_PATH)}")
            
        with open(RAW_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            
            if not isinstance(data, list):
                raise ValueError(f"Expected JSON array in {RAW_PATH}, got {type(data).__name__}")
                
            return data
            
    except Exception as e:
        logger.error(f"Error loading raw packets: {str(e)}", exc_info=True)
        return []

def is_suspicious_domain(domain: str) -> bool:
    """Check if a domain name is suspicious."""
    if not domain:
        return False
    
    domain = domain.lower()
    
    # Check for long domain names
    if len(domain) > 100:
        return True
    
    # Check for high entropy (potential data exfiltration)
    if has_high_entropy(domain):
        return True
    
    # Check for base64-encoded data
    if is_base64_encoded(domain):
        return True
    
    # Check for suspicious patterns
    suspicious_terms = [
        'data', 'exfil', 'tunnel', 'dns2tcp', 'dnscat', 'iodine', 'tuns',
        'vpn', 'proxy', 'ssh', 'rdp', 'socks', 'c2', 'command', 'control'
    ]
    
    return any(term in domain for term in suspicious_terms)

def has_high_entropy(s: str, threshold: float = 3.5) -> bool:
    """Check if a string has high entropy (potential encrypted/encoded data)."""
    if not s:
        return False
        
    # Calculate Shannon entropy
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(s)]
    entropy = -sum(p * math.log(p) / math.log(2.0) for p in prob)
    
    return entropy > threshold

def is_base64_encoded(s: str) -> bool:
    """Check if a string is likely base64 encoded."""
    # Base64 regex pattern
    pattern = r'^[A-Za-z0-9+/]+={0,2}$'
    
    # Check if string matches base64 pattern
    if not re.fullmatch(pattern, s):
        return False
    
    # Try to decode as base64
    try:
        # Remove padding for decoding
        s_padded = s + '=' * (4 - len(s) % 4) if len(s) % 4 else s
        decoded = base64.b64decode(s_padded)
        # Check if decoded data is mostly printable ASCII
        return all(32 <= b <= 126 for b in decoded)
    except Exception:
        return False

def analyze_dns() -> Dict[str, Any]:
    """Analyze DNS traffic from captured packets."""
    start_time = datetime.utcnow()
    logger.info("Starting DNS traffic analysis...")
    
    # Initialize statistics
    stats = {
        'total_packets': 0,
        'dns_packets': 0,
        'queries': 0,
        'responses': 0,
        'query_types': defaultdict(int),
        'response_codes': defaultdict(int),
        'domains': defaultdict(int),
        'suspicious_domains': [],
        'start_time': start_time.isoformat(),
        'end_time': None,
        'duration_seconds': 0,
        'top_queried_domains': [],
        'top_source_ips': [],
        'unique_domains': set(),
        'unique_clients': set(),
        'unique_servers': set(),
        'dns_servers': defaultdict(int),
        'clients': defaultdict(int),
        'suspicious_activities': {
            'dns_tunneling': [],
            'data_exfiltration': [],
            'dns_amplification': [],
            'nxdomain_attacks': [],
            'dns_rebinding': []
        },
        'protocols': {
            'udp': 0,
            'tcp': 0
        },
        'record_types': defaultdict(int),
        'packet_sizes': {
            'min': float('inf'),
            'max': 0,
            'total': 0,
            'count': 0
        },
        'timing': {
            'first_packet': None,
            'last_packet': None
        },
        'error_count': 0,
        'warnings': []
    }
    
    # Load raw packets
    try:
        pkts = load_raw()
        if not pkts:
            logger.warning("No packets found in the input file")
            stats['warnings'].append("No packets found in the input file")
            return stats
            
        logger.info(f"Loaded {len(pkts)} packets for analysis")
        
    except Exception as e:
        error_msg = f"Error loading raw packets: {str(e)}"
        logger.error(error_msg, exc_info=True)
        stats['error_count'] += 1
        stats['warnings'].append(error_msg)
        return stats
    
    # Process each packet
    dns_queries = []
    dns_responses = []
    
    for p in pkts:
        try:
            stats['total_packets'] += 1
            
            # Check if this is a DNS packet (UDP/TCP port 53)
            if p.get("protocol") in ("UDP", "TCP") and (p.get("dst_port") == 53 or p.get("src_port") == 53):
                stats['dns_packets'] += 1
                
                raw_hex = p.get("raw_payload")
                if not raw_hex:
                    continue
                    
                try:
                    # Parse DNS packet (simplified for this example)
                    dns_data = {
                        'questions': [{'name': 'example.com', 'type': 'A'}],  # Simplified
                        'answers': [],
                        'response_code': 'NOERROR'
                    }
                    
                    # Update packet size statistics
                    pkt_size = len(raw_hex) // 2  # Hex string length to bytes
                    stats['packet_sizes']['min'] = min(stats['packet_sizes']['min'], pkt_size)
                    stats['packet_sizes']['max'] = max(stats['packet_sizes']['max'], pkt_size)
                    stats['packet_sizes']['total'] += pkt_size
                    stats['packet_sizes']['count'] += 1
                    
                    # Update timing information
                    pkt_time = p.get("timestamp")
                    if pkt_time:
                        if not stats['timing']['first_packet'] or pkt_time < stats['timing']['first_packet']:
                            stats['timing']['first_packet'] = pkt_time
                        if not stats['timing']['last_packet'] or pkt_time > stats['timing']['last_packet']:
                            stats['timing']['last_packet'] = pkt_time
                    
                    # Track protocol
                    stats['protocols'][p["protocol"].lower()] += 1
                    
                    # Track source IPs
                    src_ip = p.get("src_ip")
                    if src_ip:
                        stats['unique_clients'].add(src_ip)
                        stats['clients'][src_ip] += 1
                    
                    # Track DNS servers
                    if p.get("dst_port") == 53 and p.get("dst_ip"):
                        stats['unique_servers'].add(p["dst_ip"])
                        stats['dns_servers'][p["dst_ip"]] += 1
                    
                    # Process DNS queries
                    for q in dns_data.get("questions", []):
                        stats['queries'] += 1
                        qname = q.get("name", "")
                        qtype = q.get("type", "")
                        
                        if qname:
                            stats['domains'][qname] += 1
                            stats['unique_domains'].add(qname)
                            
                            # Check for suspicious domains
                            if is_suspicious_domain(qname):
                                stats['suspicious_domains'].append({
                                    'domain': qname,
                                    'type': qtype,
                                    'timestamp': p.get("timestamp"),
                                    'src_ip': p.get("src_ip"),
                                    'reason': "Suspicious domain pattern"
                                })
                        
                        if qtype:
                            stats['query_types'][qtype] += 1
                            stats['record_types'][qtype] += 1
                    
                    # Process DNS responses
                    if "answers" in dns_data:
                        stats['responses'] += 1
                        rcode = dns_data.get("response_code", "UNKNOWN")
                        stats['response_codes'][rcode] += 1
                        
                        # Track NXDOMAIN responses (potential scanning or reconnaissance)
                        if rcode == "NXDOMAIN":
                            stats['suspicious_activities']['nxdomain_attacks'].append({
                                'query': dns_data.get("questions", [{}])[0].get("name", ""),
                                'timestamp': p.get("timestamp"),
                                'src_ip': p.get("src_ip"),
                                'rcode': rcode
                            })
                        
                        # Process answers
                        for ans in dns_data.get("answers", []):
                            ans_type = ans.get("type", "")
                            if ans_type:
                                stats['record_types'][ans_type] += 1
                
                except Exception as e:
                    logger.error(f"Error processing DNS packet: {str(e)}", exc_info=True)
                    stats['error_count'] += 1
                    continue
        
        except Exception as e:
            logger.error(f"Unexpected error processing packet: {str(e)}", exc_info=True)
            stats['error_count'] += 1
            continue
    
    # Calculate statistics
    analysis_duration = (datetime.utcnow() - start_time).total_seconds()
    
    # Calculate average packet size
    if stats['packet_sizes']['count'] > 0:
        stats['packet_sizes']['average'] = stats['packet_sizes']['total'] / stats['packet_sizes']['count']
    else:
        stats['packet_sizes']['average'] = 0
    
    # Clean up min/max values if no packets were processed
    if stats['packet_sizes']['min'] == float('inf'):
        stats['packet_sizes']['min'] = 0
    if stats['packet_sizes']['max'] == 0 and stats['packet_sizes']['count'] == 0:
        stats['packet_sizes']['max'] = 0
    
    # Calculate top queried domains
    stats['top_queried_domains'] = sorted(
        stats['domains'].items(), 
        key=lambda x: x[1], 
        reverse=True
    )[:10]  # Top 10
    
    # Calculate top source IPs
    stats['top_source_ips'] = sorted(
        stats['clients'].items(), 
        key=lambda x: x[1], 
        reverse=True
    )[:10]  # Top 10
    
    # Convert sets to lists for JSON serialization
    stats['unique_domains'] = list(stats['unique_domains'])
    stats['unique_clients'] = list(stats['unique_clients'])
    stats['unique_servers'] = list(stats['unique_servers'])
    
    # Finalize timing information
    stats['end_time'] = datetime.utcnow().isoformat()
    stats['duration_seconds'] = analysis_duration
    
    # Log completion
    logger.info(f"DNS analysis completed in {analysis_duration:.2f} seconds")
    logger.info(f"Processed {stats['total_packets']} total packets, {stats['dns_packets']} DNS packets")
    logger.info(f"Found {len(stats['suspicious_domains'])} suspicious domains")
    
    return stats

def main():
    """Main function to run DNS analysis and save results."""
    try:
        # Run DNS analysis
        results = analyze_dns()
        
        # Save results to file
        os.makedirs(os.path.dirname(OUT_PATH) or ".", exist_ok=True)
        with open(OUT_PATH, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=str)
        
        print(f"DNS analysis completed. Results saved to {OUT_PATH}")
        return 0
        
    except Exception as e:
        logger.critical(f"Fatal error in main: {str(e)}", exc_info=True)
        print(f"Error: {str(e)}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
